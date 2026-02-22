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
	"time"
	"unsafe"

	"github.com/gorilla/websocket"
	_ "github.com/mattn/go-sqlite3"
)

func receiveOpcodeFriendRequest(client *ClientConn, data []byte) {
	var username [C.NK_MAX_USERNAME_SIZE]C.char
	var usernameLen C.ushort
	var tag C.uint

	if C.nk_decode_friend_request(
		(*C.uchar)(unsafe.Pointer(&data[0])),
		C.uint(len(data)),
		&client.rxKey[0],
		&username[0],
		&usernameLen,
		&tag,
	) != 0 {
		sendError(client, (int)(C.NK_OPCODE_FRIEND_REQUEST), (int)(C.NK_ERROR_INVALID_FRAME))
		return
	}

	goUsername := C.GoBytes(
		unsafe.Pointer(&username[0]),
		C.int(usernameLen),
	)

	senderID := client.userID
	var recipientID int

	err := db.QueryRow(
		`SELECT id FROM users
				WHERE username = ? AND tag = ?`,
		string(goUsername),
		int(tag),
	).Scan(&recipientID)

	if err != nil {
		sendError(client, (int)(C.NK_OPCODE_FRIEND_REQUEST), (int)(C.NK_ERROR_USER_NOT_FOUND))
		return
	}
	if int(client.userID) == recipientID {
		sendError(client, (int)(C.NK_OPCODE_FRIEND_REQUEST), (int)(C.NK_ERROR_RECIPENT_CANNOT_BE_SENDER))
		return
	}
	var relationType int
	var direction int

	err = db.QueryRow(
		`SELECT relation_type, direction
				FROM user_relations
				WHERE (user1_id=? AND user2_id=?)
					OR (user1_id=? AND user2_id=?)
				LIMIT 1`,
		recipientID, senderID,
		senderID, recipientID,
	).Scan(&relationType, &direction)

	if err == nil &&
		relationType == C.NK_USER_RELATION_BLOCKED {

		if (direction == C.NK_RELATION_DIR_OUTGOING && recipientID < senderID) ||
			(direction == C.NK_RELATION_DIR_INCOMING && recipientID > senderID) {
			sendError(client, (int)(C.NK_OPCODE_FRIEND_REQUEST), (int)(C.NK_ERROR_PERMISSION_DENIED))
			return
		}
	}
	var tmp int
	err = db.QueryRow(
		`SELECT 1 FROM friend_requests
				WHERE user_id=? AND recipent_id=?
					AND (status=? OR status=?)
				LIMIT 1`,
		senderID,
		recipientID,
		C.NK_FRIEND_REQUEST_PENDING,
		C.NK_FRIEND_REQUEST_ACCEPTED,
	).Scan(&tmp)

	if err == nil {
		sendError(client, (int)(C.NK_OPCODE_FRIEND_REQUEST), (int)(C.NK_ERROR_ALREADY_REQUESTED))
		return
	}
	row, err := db.Exec(
		`INSERT INTO friend_requests
					(user_id, recipent_id, status)
				VALUES (?, ?, ?)`,
		senderID,
		recipientID,
		C.NK_FRIEND_REQUEST_PENDING,
	)

	if err != nil {
		sendError(client, (int)(C.NK_OPCODE_FRIEND_REQUEST), (int)(C.NK_ERROR_INTERNAL))
		return
	}
	sendOk(client, (int)(C.NK_OPCODE_FRIEND_REQUEST))

	recipentClient, ok := getLoggedClient((uint64)(recipientID))
	if ok {
		lastId, _ := row.LastInsertId()
		sendFriendRequestData(recipentClient, int(lastId), senderID, int(C.NK_FRIEND_REQUEST_PENDING), time.Now().Unix())
		goIDs := make([]int, 1)
		goIDs[0] = senderID
		sendSyncUserData(recipentClient, goIDs)
	}
}

func receiveOpcodeFriendRequestUpdateStatus(client *ClientConn, data []byte) {
	var requestID C.uint
	var statusCode C.uint

	if C.nk_decode_friend_request_update_status(
		(*C.uchar)(unsafe.Pointer(&data[0])),
		C.uint(len(data)),
		&client.rxKey[0],
		&requestID,
		&statusCode,
	) != 0 {
		sendError(client, int(C.NK_OPCODE_FRIEND_REQUEST_UPDATE_STATUS), int(C.NK_ERROR_INVALID_FRAME))
		return
	}

	res, err := db.Exec(`
		UPDATE friend_requests
		SET status=?, last_update=CURRENT_TIMESTAMP
		WHERE id=? AND recipent_id=?
	`,
		int(statusCode),
		int(requestID),
		client.userID,
	)

	if err != nil {
		sendError(client, int(C.NK_OPCODE_FRIEND_REQUEST_UPDATE_STATUS), int(C.NK_ERROR_INTERNAL))
		return
	}

	rows, _ := res.RowsAffected()
	if rows == 0 {
		sendError(client, int(C.NK_OPCODE_FRIEND_REQUEST_UPDATE_STATUS), int(C.NK_ERROR_PERMISSION_DENIED))
		return
	}

	now := time.Now().Unix()
	var senderID int
	err = db.QueryRow(
		`SELECT user_id FROM friend_requests WHERE id=?`,
		int(requestID),
	).Scan(&senderID)

	if statusCode == C.NK_FRIEND_REQUEST_ACCEPTED {
		row, _ := db.Exec(`
        INSERT INTO user_relations
        (user1_id, user2_id, relation_type, direction)
        VALUES (?, ?, ?, ?)
    `,
			senderID,
			client.userID,
			int(C.NK_USER_RELATION_FRIEND),
			int(C.NK_RELATION_DIR_MUTUAL),
		)

		lastId, _ := row.LastInsertId()

		sendRelationData(client, int(lastId), senderID, int(C.NK_USER_RELATION_FRIEND), int(C.NK_RELATION_DIR_MUTUAL), now)
		senderClient, ok := getLoggedClient(uint64(senderID))
		if ok {
			sendRelationData(senderClient, int(lastId), client.userID, int(C.NK_USER_RELATION_FRIEND), int(C.NK_RELATION_DIR_MUTUAL), now)

			ids := []int{client.userID, senderID}
			sendSyncUserData(senderClient, ids)
		}

		ids := []int{client.userID, senderID}
		sendSyncUserData(client, ids)
	}

	sendFriendRequestData(client, int(requestID), senderID, int(statusCode), now)
	sendOk(client, int(C.NK_OPCODE_FRIEND_REQUEST_UPDATE_STATUS))
}

func receiveOpcodeUserRelationBlock(client *ClientConn, data []byte) {
	var recipentID C.uint

	if C.nk_decode_user_relation_block(
		(*C.uchar)(unsafe.Pointer(&data[0])),
		C.uint(len(data)),
		&client.rxKey[0],
		&recipentID,
	) != 0 {
		sendError(client, int(C.NK_OPCODE_USER_RELATION_BLOCK), int(C.NK_ERROR_INVALID_FRAME))
		return
	}

	targetID := int(recipentID)
	now := time.Now().Unix()

	rows, _ := db.Query(`
		SELECT id, user_id
		FROM friend_requests
		WHERE (user_id=? AND recipent_id=?)
		   OR (user_id=? AND recipent_id=?)
	`, client.userID, targetID, targetID, client.userID)

	for rows.Next() {
		var id int
		var sender int
		if rows.Scan(&id, &sender) == nil {
			sendFriendRequestData(client, id, targetID, int(C.NK_FRIEND_REQUEST_DENIED), now)

			if other, ok := getLoggedClient(uint64(targetID)); ok {
				sendFriendRequestData(other, id, sender, int(C.NK_FRIEND_REQUEST_DENIED), now)
			}
		}
	}
	rows.Close()

	_, _ = db.Exec(`
		UPDATE friend_requests
		SET status=?, last_update=CURRENT_TIMESTAMP
		WHERE (user_id=? AND recipent_id=?)
		   OR (user_id=? AND recipent_id=?)
	`,
		C.NK_FRIEND_REQUEST_DENIED,
		client.userID, targetID,
		targetID, client.userID,
	)

	row, err := db.Exec(`
		INSERT INTO user_relations
			(user1_id, user2_id, relation_type, direction)
		VALUES (?, ?, ?, ?)
		ON CONFLICT(user1_id, user2_id)
		DO UPDATE SET
			relation_type=excluded.relation_type,
			direction=excluded.direction,
			last_update=CURRENT_TIMESTAMP
	`,
		client.userID,
		targetID,
		int(C.NK_USER_RELATION_BLOCKED),
		int(C.NK_RELATION_DIR_OUTGOING),
	)

	if err != nil {
		fmt.Println(err.Error())
		sendError(client, int(C.NK_OPCODE_USER_RELATION_BLOCK), int(C.NK_ERROR_INTERNAL))
		return
	}

	lastId, _ := row.LastInsertId()

	sendOk(client, int(C.NK_OPCODE_USER_RELATION_BLOCK))

	sendRelationData(
		client,
		int(lastId),
		targetID,
		int(C.NK_USER_RELATION_BLOCKED),
		int(C.NK_RELATION_DIR_OUTGOING),
		now,
	)

	if other, ok := getLoggedClient(uint64(targetID)); ok {
		sendRelationData(
			other,
			int(lastId),
			client.userID,
			int(C.NK_USER_RELATION_BLOCKED),
			int(C.NK_RELATION_DIR_INCOMING),
			now,
		)
	}
}

func receiveOpcodeUserRelationReset(client *ClientConn, data []byte) {
	var recipentID C.uint

	if C.nk_decode_user_relation_reset(
		(*C.uchar)(unsafe.Pointer(&data[0])),
		C.uint(len(data)),
		&client.rxKey[0],
		&recipentID,
	) != 0 {
		sendError(client, int(C.NK_OPCODE_USER_RELATION_RESET), int(C.NK_ERROR_INVALID_FRAME))
		return
	}

	var relationType int
	var direction int
	var user1 int

	otherID := int(recipentID)
	err := db.QueryRow(`
	SELECT user1_id, relation_type, direction
	FROM user_relations
	WHERE (user1_id=? AND user2_id=?)
	   OR (user1_id=? AND user2_id=?)
	LIMIT 1
`, client.userID, otherID, otherID, client.userID).
		Scan(&user1, &relationType, &direction)

	if err != nil {
		sendError(client, int(C.NK_OPCODE_USER_RELATION_RESET), int(C.NK_ERROR_PERMISSION_DENIED))
		return
	}

	if relationType == C.NK_USER_RELATION_BLOCKED {
		if user1 != client.userID {
			sendError(client, int(C.NK_OPCODE_USER_RELATION_RESET), int(C.NK_ERROR_PERMISSION_DENIED))
			return
		}
	}

	_, _ = db.Exec(`
		UPDATE friend_requests
		SET status=?, last_update=CURRENT_TIMESTAMP
		WHERE (user_id=? AND recipent_id=?)
		   OR (user_id=? AND recipent_id=?)
	`,
		C.NK_FRIEND_REQUEST_DENIED,
		client.userID, otherID,
		otherID, client.userID,
	)

	rows, err := db.Query(`
		SELECT id, user1_id, user2_id, direction,
		       strftime('%s', last_update)
		FROM user_relations
		WHERE (user1_id=? AND user2_id=?)
		   OR (user1_id=? AND user2_id=?)
	`, client.userID, otherID, otherID, client.userID)

	if err != nil {
		sendError(client, int(C.NK_OPCODE_USER_RELATION_RESET), int(C.NK_ERROR_INTERNAL))
		return
	}
	defer rows.Close()

	type rel struct {
		id        int
		u1        int
		u2        int
		direction int
		time      int64
	}

	var relations []rel

	for rows.Next() {
		var r rel
		if rows.Scan(&r.id, &r.u1, &r.u2, &r.direction, &r.time) == nil {
			relations = append(relations, r)
		}
	}

	_, err = db.Exec(`
		DELETE FROM user_relations
		WHERE (user1_id=? AND user2_id=?)
		   OR (user1_id=? AND user2_id=?)
	`, client.userID, otherID, otherID, client.userID)

	if err != nil {
		sendError(client, int(C.NK_OPCODE_USER_RELATION_RESET), int(C.NK_ERROR_INTERNAL))
		return
	}

	sendOk(client, int(C.NK_OPCODE_USER_RELATION_RESET))

	otherClient, ok := getLoggedClient(uint64(otherID))

	for _, r := range relations {

		recip := r.u1
		if r.u1 == client.userID {
			recip = r.u2
		}

		sendRelationData(
			client,
			r.id,
			recip,
			int(C.NK_USER_RELATION_REMOVED),
			r.direction,
			r.time,
		)

		if ok {
			recipOther := r.u1
			if r.u1 == otherID {
				recipOther = r.u2
			}

			sendRelationData(
				otherClient,
				r.id,
				recipOther,
				int(C.NK_USER_RELATION_REMOVED),
				r.direction,
				r.time,
			)
		}
	}

	rows2, _ := db.Query(`
		SELECT id, user_id, status, strftime('%s', last_update)
		FROM friend_requests
		WHERE (user_id=? AND recipent_id=?)
		   OR (user_id=? AND recipent_id=?)
	`, client.userID, otherID, otherID, client.userID)

	if rows2 != nil {
		defer rows2.Close()

		for rows2.Next() {
			var id, sender, status int
			var t int64

			if rows2.Scan(&id, &sender, &status, &t) == nil {
				sendFriendRequestData(client, id, otherID, status, t)

				if ok {
					sendFriendRequestData(otherClient, id, sender, status, t)
				}
			}
		}
	}
}

func sendFriendRequestData(
	client *ClientConn,
	requestID int,
	senderID int,
	status int,
	updateTime int64,
) {

	var out [1]C.NKFriendRequestData

	fd := &out[0]
	fd.requestId = C.uint(requestID)
	fd.senderId = C.uint(senderID)
	fd.statusCode = C.uint(status)
	fd.updateTime = C.ulonglong(updateTime)
	fd.reserved0 = 0

	var replySize C.uint
	reply := C.nk_encode_sync_friend_requests(
		&out[0],
		1,
		&client.txKey[0],
		&replySize,
	)
	if reply == nil {
		return
	}

	goReply := C.GoBytes(unsafe.Pointer(reply), C.int(replySize))
	client.conn.WriteMessage(websocket.BinaryMessage, goReply)
	C.free(unsafe.Pointer(reply))
}

func sendRelationData(
	client *ClientConn,
	relationID int,
	recipentID int,
	relationType int,
	direction int,
	updateTime int64,
) {

	var out [1]C.NKUserRelationData

	rd := &out[0]
	rd.relationId = C.uint(relationID)
	rd.recipentId = C.uint(recipentID)
	rd.statusCode = C.uint(relationType)
	rd.direction = C.uint(direction)
	rd.updateTime = C.ulonglong(updateTime)

	var replySize C.uint
	reply := C.nk_encode_sync_relations(
		&out[0],
		1,
		&client.txKey[0],
		&replySize,
	)

	if reply == nil {
		return
	}

	goReply := C.GoBytes(unsafe.Pointer(reply), C.int(replySize))
	client.conn.WriteMessage(websocket.BinaryMessage, goReply)
	C.free(unsafe.Pointer(reply))
}
