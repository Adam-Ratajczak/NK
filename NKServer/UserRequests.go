package main

/*
#cgo CFLAGS: -I../NKProtocol/include
#cgo LDFLAGS: -L../NKProtocol/build -lnk_protocol -lsodium -lz
#include <stdlib.h>
#include "nk_protocol.h"
*/
import "C"

import (
	"fmt"
	"unsafe"

	"github.com/gorilla/websocket"

	_ "github.com/mattn/go-sqlite3"
)

func canAccessUserData(userId, subjectId int) bool {

	if userId == subjectId {
		return true
	}

	var tmp int
	err := db.QueryRow(
		`SELECT 1 FROM friend_requests
		  WHERE user_id = ? AND recipient_id = ? LIMIT 1`,
		subjectId,
		userId,
	).Scan(&tmp)

	if err == nil {
		return true
	}

	var user1ID int
	var user2ID int
	var relationType int
	var direction int

	err = db.QueryRow(
		`SELECT user1_id, user2_id, relation_type, direction
		   FROM user_relations
		  WHERE (user1_id = ? OR user2_id = ?)
		    AND (user1_id = ? OR user2_id = ?)
		  LIMIT 1`,
		userId, subjectId,
		userId, subjectId,
	).Scan(&user1ID, &user2ID, &relationType, &direction)

	if err != nil {
		return false
	}

	if relationType == C.NK_USER_RELATION_FRIEND && direction == C.NK_RELATION_DIR_MUTUAL {
		return true
	}

	if relationType == C.NK_USER_RELATION_BLOCKED {

		if user1ID == userId && direction == C.NK_RELATION_DIR_OUTGOING {
			return true
		}

		if user2ID == userId && direction == C.NK_RELATION_DIR_INCOMING {
			return true
		}
	}

	return false
}

func sendSyncUserData(client *ClientConn, ids []int) {
	var userData [C.NK_MAX_PAYLOAD_ARRAY_SIZE]C.NKUserData
	var outLen C.ushort = 0

	stmt, err := db.Prepare(`
		SELECT id, username, tag, pfp_resource_id, strftime('%s', created_at)
		FROM users
		WHERE id = ?
	`)
	if err != nil {
		// sendError(client, int(C.NK_OPCODE_SYNC_USER_DATA), int(C.NK_ERROR_INTERNAL))
		return
	}
	defer stmt.Close()

	for _, reqID := range ids {

		var id int
		var uname string
		var joined int64
		var tag int
		var pfp int

		err := stmt.QueryRow(reqID).Scan(
			&id,
			&uname,
			&tag,
			&pfp,
			&joined,
		)
		if err != nil {
			continue
		}

		ud := &userData[outLen]

		ud.userId = C.uint(id)
		ud.joinedTime = C.ulonglong(joined)
		ud.pfpResourceId = C.uint(pfp)
		ud.userTag = C.uint(tag)

		cName := []byte(uname)
		if len(cName) >= int(C.NK_MAX_USERNAME_SIZE) {
			cName = cName[:int(C.NK_MAX_USERNAME_SIZE)-1]
		}

		for j := range cName {
			ud.username[j] = C.char(cName[j])
		}
		ud.username[len(cName)] = 0

		outLen++
	}

	if outLen == 0 {
		sendError(client, int(C.NK_OPCODE_SYNC_USER_DATA), int(C.NK_ERROR_NOTHING_TO_SEND))
		return
	}

	var replySize C.uint
	reply := C.nk_encode_sync_user_data(
		&userData[0],
		outLen,
		&client.txKey[0],
		&replySize,
	)
	if reply == nil {
		sendError(client, int(C.NK_OPCODE_SYNC_USER_DATA), int(C.NK_ERROR_INTERNAL))
		return
	}

	goReply := C.GoBytes(unsafe.Pointer(reply), C.int(replySize))

	err = client.conn.WriteMessage(websocket.BinaryMessage, goReply)
	if err != nil {
		fmt.Println("ws write error:", err)
	}

	C.free(unsafe.Pointer(reply))
}

func getLoggedClient(userID uint64) (*ClientConn, bool) {
	clientReg.RLock()
	defer clientReg.RUnlock()

	c, ok := clientReg.clients[userID]
	return c, ok
}

func broadcastUserDataUpdate(userID int) {
	rows, err := db.Query(`
		SELECT user1_id, user2_id
		FROM user_relations
		WHERE relation_type=? AND direction=? 
		AND (user1_id=? OR user2_id=?)
	`,
		int(C.NK_USER_RELATION_FRIEND),
		int(C.NK_RELATION_DIR_MUTUAL),
		userID, userID,
	)
	if err != nil {
		return
	}
	defer rows.Close()

	var friendIDs []int

	for rows.Next() {
		var u1, u2 int
		if err := rows.Scan(&u1, &u2); err != nil {
			continue
		}

		if u1 == userID {
			friendIDs = append(friendIDs, u2)
		} else {
			friendIDs = append(friendIDs, u1)
		}
	}

	if len(friendIDs) == 0 {
		return
	}

	clientReg.RLock()
	defer clientReg.RUnlock()

	for _, fid := range friendIDs {
		c, ok := clientReg.clients[uint64(fid)]
		if !ok || !c.authenticated {
			continue
		}

		sendSyncUserData(c, []int{userID})
	}
}
