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

func receiveOpcodeRegisterNewDeviceKeys(client *ClientConn, data []byte) {
	var deviceID C.uint

	var x25519 [C.NK_X25519_KEY_SIZE]C.uchar
	var ed25519 [C.NK_X25519_KEY_SIZE]C.uchar

	if C.nk_decode_register_new_device_keys(
		(*C.uchar)(unsafe.Pointer(&data[0])),
		C.uint(len(data)),
		&client.rxKey[0],
		&deviceID,
		&x25519[0],
		&ed25519[0],
	) != 0 {
		fmt.Println("NK_ERROR_INVALID_FRAME")
		sendError(client, int(C.NK_OPCODE_REGISTER_NEW_DEVICE_KEYS), int(C.NK_ERROR_INVALID_FRAME))
		return
	}

	var storedUserID int
	var existingX []byte

	err := db.QueryRow(`
		SELECT user_id, x25519_pub 
		FROM devices 
		WHERE id=?`,
		int(deviceID),
	).Scan(&storedUserID, &existingX)

	if err != nil || storedUserID != client.userID {
		fmt.Println("NK_ERROR_INVALID_DEVICE")
		sendError(client, int(C.NK_OPCODE_REGISTER_NEW_DEVICE_KEYS), int(C.NK_ERROR_INVALID_DEVICE))
		return
	}

	if len(existingX) != 0 {
		fmt.Println("NK_ERROR_PERMISSION_DENIED")
		sendError(client, int(C.NK_OPCODE_REGISTER_NEW_DEVICE_KEYS), int(C.NK_ERROR_PERMISSION_DENIED))
		return
	}

	goX := C.GoBytes(unsafe.Pointer(&x25519[0]), C.NK_X25519_KEY_SIZE)
	goE := C.GoBytes(unsafe.Pointer(&ed25519[0]), C.NK_X25519_KEY_SIZE)

	_, err = db.Exec(`
		UPDATE devices
		SET x25519_pub=?, ed25519_pub=?
		WHERE id=?`,
		goX,
		goE,
		int(deviceID),
	)

	if err != nil {
		fmt.Println("NK_ERROR_INTERNAL")
		fmt.Println(err.Error())
		sendError(client, int(C.NK_OPCODE_REGISTER_NEW_DEVICE_KEYS), int(C.NK_ERROR_INTERNAL))
		return
	}

	sendOk(client, int(C.NK_OPCODE_REGISTER_NEW_DEVICE_KEYS))
}

func receiveOpcodeRequestDevices(client *ClientConn, data []byte) {
	var deviceIDs [C.NK_MAX_PAYLOAD_ARRAY_SIZE]C.uint
	var deviceIDsLen C.ushort

	if C.nk_decode_request_devices(
		(*C.uchar)(unsafe.Pointer(&data[0])),
		C.uint(len(data)),
		&client.rxKey[0],
		&deviceIDs[0],
		&deviceIDsLen,
	) != 0 {
		sendError(client, int(C.NK_OPCODE_REQUEST_DEVICES), int(C.NK_ERROR_INVALID_FRAME))
		return
	}

	allowedUsers := map[int]bool{}
	allowedUsers[client.userID] = true

	rows, err := db.Query(`
        SELECT user1_id, user2_id
        FROM user_relations
        WHERE relation_type=? AND direction=? 
        AND (user1_id=? OR user2_id=?)
    `,
		int(C.NK_USER_RELATION_FRIEND),
		int(C.NK_RELATION_DIR_MUTUAL),
		client.userID,
		client.userID,
	)
	if err == nil {
		defer rows.Close()

		for rows.Next() {
			var u1, u2 int
			if rows.Scan(&u1, &u2) != nil {
				continue
			}

			if u1 == client.userID {
				allowedUsers[u2] = true
			} else {
				allowedUsers[u1] = true
			}
		}
	}

	goDeviceIDs := make([]int, 0, deviceIDsLen)
	for i := 0; i < int(deviceIDsLen); i++ {
		goDeviceIDs = append(goDeviceIDs, int(deviceIDs[i]))
	}

	if len(goDeviceIDs) == 0 {
		return
	}

	rows, err = db.Query(`
        SELECT id, user_id, x25519_pub, ed25519_pub
        FROM devices
        WHERE id IN (`+placeholders(len(goDeviceIDs))+`)
    `, toInterfaceSlice(goDeviceIDs)...)

	if err != nil {
		sendError(client, int(C.NK_OPCODE_REQUEST_DEVICES), int(C.NK_ERROR_INTERNAL))
		return
	}
	defer rows.Close()

	var devices [C.NK_MAX_PAYLOAD_ARRAY_SIZE]C.NKDeviceData
	var outLen C.ushort = 0

	for rows.Next() {
		var id int
		var uid int
		var x25519 []byte
		var ed25519 []byte

		if err := rows.Scan(&id, &uid, &x25519, &ed25519); err != nil {
			continue
		}

		if !allowedUsers[uid] {
			continue
		}

		d := &devices[outLen]

		d.deviceId = C.uint(id)
		d.userId = C.uint(uid)

		copy((*[32]byte)(unsafe.Pointer(&d.x25519_pub[0]))[:], x25519)
		copy((*[32]byte)(unsafe.Pointer(&d.ed25519_pub[0]))[:], ed25519)

		outLen++
		if outLen >= C.NK_MAX_PAYLOAD_ARRAY_SIZE {
			break
		}
	}

	if outLen == 0 {
		return
	}

	var replySize C.uint
	reply := C.nk_encode_request_devices_result(
		&devices[0],
		outLen,
		&client.txKey[0],
		&replySize,
	)

	if reply == nil {
		sendError(client, int(C.NK_OPCODE_REQUEST_DEVICES), int(C.NK_ERROR_INTERNAL))
		return
	}

	goReply := C.GoBytes(unsafe.Pointer(reply), C.int(replySize))
	client.conn.WriteMessage(websocket.BinaryMessage, goReply)
	C.free(unsafe.Pointer(reply))
}

func receiveOpcodeRequestUserDevices(client *ClientConn, data []byte) {
	var userIDs [C.NK_MAX_PAYLOAD_ARRAY_SIZE]C.uint
	var userIDsLen C.ushort

	if C.nk_decode_request_user_devices(
		(*C.uchar)(unsafe.Pointer(&data[0])),
		C.uint(len(data)),
		&client.rxKey[0],
		&userIDs[0],
		&userIDsLen,
	) != 0 {
		sendError(client, int(C.NK_OPCODE_REQUEST_USER_DEVICES), int(C.NK_ERROR_INVALID_FRAME))
		return
	}

	if userIDsLen == 0 {
		sendError(client, int(C.NK_OPCODE_REQUEST_USER_DEVICES), int(C.NK_ERROR_INVALID_FRAME))
		return
	}

	fmt.Println("userIDsLen:", userIDsLen)
	for i := 0; i < int(userIDsLen); i++ {
		fmt.Println("requested user:", int(userIDs[i]))
	}
	var count int
	fmt.Println("devices count:")
	db.QueryRow("SELECT COUNT(*) FROM devices").Scan(&count)
	fmt.Println(count)

	allowed := map[int]bool{}
	allowed[client.userID] = true

	rows, err := db.Query(`
		SELECT user1_id, user2_id
		FROM user_relations
		WHERE relation_type=? AND direction=?
		AND (user1_id=? OR user2_id=?)`,
		int(C.NK_USER_RELATION_FRIEND),
		int(C.NK_RELATION_DIR_MUTUAL),
		client.userID,
		client.userID,
	)
	if err == nil {
		defer rows.Close()

		for rows.Next() {
			var u1, u2 int
			if rows.Scan(&u1, &u2) != nil {
				continue
			}

			if u1 == client.userID {
				allowed[u2] = true
			} else {
				allowed[u1] = true
			}
		}
	}
	filtered := make([]int, 0, userIDsLen)

	for i := 0; i < int(userIDsLen); i++ {
		id := int(userIDs[i])
		if allowed[id] {
			filtered = append(filtered, id)
		}
	}

	if len(filtered) == 0 {
		sendError(client, int(C.NK_OPCODE_REQUEST_USER_DEVICES), int(C.NK_ERROR_NOTHING_TO_SEND))
		return
	}

	query := `
		SELECT id, user_id, x25519_pub, ed25519_pub
		FROM devices
		WHERE user_id IN (` + placeholders(len(filtered)) + `)
	`

	rows, err = db.Query(query, toInterfaceSlice(filtered)...)
	if err != nil {
		sendError(client, int(C.NK_OPCODE_REQUEST_USER_DEVICES), int(C.NK_ERROR_INTERNAL))
		return
	}
	defer rows.Close()

	var devices [C.NK_MAX_PAYLOAD_ARRAY_SIZE]C.NKDeviceData
	var outLen C.ushort = 0

	for rows.Next() {
		var id int
		var uid int
		var x25519 []byte
		var ed25519 []byte

		if rows.Scan(&id, &uid, &x25519, &ed25519) != nil {
			continue
		}

		if len(x25519) != 32 || len(ed25519) != 32 {
			continue
		}

		d := &devices[outLen]

		d.deviceId = C.uint(id)
		d.userId = C.uint(uid)

		copy((*[32]byte)(unsafe.Pointer(&d.x25519_pub[0]))[:], x25519)
		copy((*[32]byte)(unsafe.Pointer(&d.ed25519_pub[0]))[:], ed25519)

		outLen++
		if outLen >= C.NK_MAX_PAYLOAD_ARRAY_SIZE {
			break
		}
	}

	if outLen == 0 {
		sendError(client, int(C.NK_OPCODE_REQUEST_USER_DEVICES), int(C.NK_ERROR_NOTHING_TO_SEND))
		return
	}

	var replySize C.uint
	reply := C.nk_encode_request_devices_result(
		&devices[0],
		outLen,
		&client.txKey[0],
		&replySize,
	)

	if reply == nil {
		sendError(client, int(C.NK_OPCODE_REQUEST_USER_DEVICES), int(C.NK_ERROR_INTERNAL))
		return
	}

	goReply := C.GoBytes(unsafe.Pointer(reply), C.int(replySize))
	client.conn.WriteMessage(websocket.BinaryMessage, goReply)

	C.free(unsafe.Pointer(reply))
}

func ensureDeviceReady(client *ClientConn, opcode int) bool {
	var x, e []byte

	err := db.QueryRow(`
		SELECT x25519_pub, ed25519_pub
		FROM devices
		WHERE id=? AND user_id=?`,
		client.deviceID,
		client.userID,
	).Scan(&x, &e)

	if err != nil {
		sendError(client, opcode, int(C.NK_ERROR_INVALID_DEVICE))
		return false
	}

	if len(x) != int(C.NK_X25519_KEY_SIZE) || len(e) != int(C.NK_X25519_KEY_SIZE) {
		sendError(client, opcode, int(C.NK_ERROR_PERMISSION_DENIED))
		return false
	}

	return true
}
