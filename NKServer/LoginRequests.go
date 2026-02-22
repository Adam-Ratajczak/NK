package main

/*
#cgo CFLAGS: -I../NKProtocol/include
#cgo LDFLAGS: -L../NKProtocol/build -lnk_protocol -lsodium -lz
#include <stdlib.h>
#include "nk_protocol.h"
*/
import "C"

import (
	"crypto/subtle"
	"fmt"
	"math/rand"
	"time"
	"unsafe"

	"github.com/gorilla/websocket"

	_ "github.com/mattn/go-sqlite3"
)

func receiveOpcodeRegister(client *ClientConn, data []byte) {
	var username [64]C.char
	var usernameLen C.ushort
	var salt [16]C.uchar
	var hash [32]C.uchar

	var umkNonce [24]C.uchar
	var umkCipher [48]C.uchar

	if C.nk_decode_register(
		(*C.uchar)(unsafe.Pointer(&data[0])),
		C.uint(len(data)),
		&client.rxKey[0],
		&username[0],
		&usernameLen,
		&salt[0],
		&hash[0],
		&umkNonce[0],
		&umkCipher[0],
	) != 0 {
		sendError(client, int(C.NK_OPCODE_REGISTER), int(C.NK_ERROR_INVALID_FRAME))
		return
	}

	goUsername := C.GoBytes(unsafe.Pointer(&username[0]), C.int(usernameLen))
	goSalt := C.GoBytes(unsafe.Pointer(&salt[0]), 16)
	goHash := C.GoBytes(unsafe.Pointer(&hash[0]), 32)
	goUMKNonce := C.GoBytes(unsafe.Pointer(&umkNonce[0]), 24)
	goUMKCipher := C.GoBytes(unsafe.Pointer(&umkCipher[0]), 48)

	rand.Seed(time.Now().UnixNano())
	goTag := rand.Intn(90000) + 10000

	_, err := db.Exec(
		`INSERT INTO users 
		(username, tag, salt, password_hash, umk_nonce, umk_cipher) 
		VALUES (?, ?, ?, ?, ?, ?)`,
		string(goUsername),
		goTag,
		goSalt,
		goHash,
		goUMKNonce,
		goUMKCipher,
	)

	if err != nil {
		sendError(client, int(C.NK_OPCODE_REGISTER), int(C.NK_ERROR_USER_EXISTS))
		return
	}

	sendOk(client, int(C.NK_OPCODE_REGISTER))
}

func receiveOpcodeRequestSalt(client *ClientConn, data []byte) {
	var username [C.NK_MAX_USERNAME_SIZE]C.char
	var usernameLen C.ushort

	if C.nk_decode_request_salt(
		(*C.uchar)(unsafe.Pointer(&data[0])),
		C.uint(len(data)),
		&client.rxKey[0],
		&username[0],
		&usernameLen,
	) != 0 {
		sendError(client, (int)(C.NK_OPCODE_REQUEST_SALT), (int)(C.NK_ERROR_INVALID_FRAME))
		return
	}

	goUsername := C.GoBytes(
		unsafe.Pointer(&username[0]),
		C.int(usernameLen),
	)

	var salt []byte

	err := db.QueryRow(
		"SELECT salt FROM users WHERE username = ?",
		string(goUsername),
	).Scan(&salt)

	if err != nil {
		fake := make([]byte, 16)
		rand.Read(fake)
		salt = fake
	}

	var replySize C.uint
	reply := C.nk_encode_request_salt_result(
		(*C.uchar)(unsafe.Pointer(&salt[0])),
		&client.txKey[0],
		&replySize,
	)

	goReply := C.GoBytes(unsafe.Pointer(reply), C.int(replySize))
	client.conn.WriteMessage(websocket.BinaryMessage, goReply)
	C.free(unsafe.Pointer(reply))
}

func receiveOpcodeLogin(client *ClientConn, data []byte) {
	var username [C.NK_MAX_USERNAME_SIZE]C.char
	var usernameLen C.ushort
	var receivedHash [32]C.uchar
	var deviceID C.uint

	if C.nk_decode_login(
		(*C.uchar)(unsafe.Pointer(&data[0])),
		C.uint(len(data)),
		&client.rxKey[0],
		&username[0],
		&usernameLen,
		&receivedHash[0],
		&deviceID,
	) != 0 {
		sendError(client, int(C.NK_OPCODE_LOGIN), int(C.NK_ERROR_INVALID_FRAME))
		return
	}

	goUsername := C.GoBytes(
		unsafe.Pointer(&username[0]),
		C.int(usernameLen),
	)

	var userID int
	var storedHash []byte
	var umkNonce []byte
	var umkCipher []byte

	err := db.QueryRow(
		`SELECT id, password_hash, umk_nonce, umk_cipher 
		 FROM users WHERE username = ?`,
		string(goUsername),
	).Scan(&userID, &storedHash, &umkNonce, &umkCipher)

	if err != nil {
		storedHash = make([]byte, 32)
	}

	received := C.GoBytes(
		unsafe.Pointer(&receivedHash[0]),
		32,
	)

	if len(storedHash) != 32 || subtle.ConstantTimeCompare(storedHash, received) != 1 {
		sendError(client, int(C.NK_OPCODE_LOGIN), int(C.NK_ERROR_INVALID_USER_OR_PASSWORD))
		return
	}

	var finalDeviceID int

	if deviceID == C.NK_INVALID_DEVICE {
		res, err := db.Exec(`
			INSERT INTO devices (user_id, created_at)
			VALUES (?, strftime('%s','now'))`,
			userID,
		)
		if err != nil {
			fmt.Println(err.Error())
			sendError(client, int(C.NK_OPCODE_LOGIN), int(C.NK_ERROR_INTERNAL))
			return
		}

		id, _ := res.LastInsertId()
		finalDeviceID = int(id)

	} else {
		var exists int
		err := db.QueryRow(`
			SELECT 1 FROM devices WHERE id=? AND user_id=?`,
			int(deviceID), userID,
		).Scan(&exists)

		if err != nil {
			sendError(client, int(C.NK_OPCODE_LOGIN), int(C.NK_ERROR_INVALID_DEVICE))
			return
		}

		finalDeviceID = int(deviceID)
	}

	nonceSize := int(C.NK_NONCE_SIZE)
	cipherSize := int(C.NK_X25519_KEY_SIZE + C.NK_MAC_SIZE)

	if len(umkNonce) != nonceSize || len(umkCipher) != cipherSize {
		fmt.Printf("%d, %d, %d, %d\n", len(umkNonce), nonceSize, len(umkCipher), cipherSize)
		sendError(client, int(C.NK_OPCODE_LOGIN), int(C.NK_ERROR_INTERNAL))
		return
	}

	client.userID = userID
	client.deviceID = finalDeviceID
	client.authenticated = true

	clientReg.Lock()
	clientReg.clients[uint64(userID)] = client
	clientReg.Unlock()

	fmt.Printf("User online: %d (device %d)\n", userID, finalDeviceID)

	var replySize C.uint
	reply := C.nk_encode_login_result(
		C.uint(userID),
		C.uint(finalDeviceID),
		(*C.uchar)(unsafe.Pointer(&umkNonce[0])),
		(*C.uchar)(unsafe.Pointer(&umkCipher[0])),
		&client.txKey[0],
		&replySize,
	)

	goReply := C.GoBytes(unsafe.Pointer(reply), C.int(replySize))
	client.conn.WriteMessage(websocket.BinaryMessage, goReply)
	C.free(unsafe.Pointer(reply))

	SynchroOnLogin(userID)
}

func receiveOpcodeLogout(client *ClientConn, data []byte) {
	if C.nk_decode_logout(
		(*C.uchar)(unsafe.Pointer(&data[0])),
		C.uint(len(data)),
		&client.rxKey[0],
	) != 0 {
		sendError(client, (int)(C.NK_OPCODE_LOGOUT), (int)(C.NK_ERROR_INVALID_FRAME))
		return
	}

	clientReg.RLock()
	defer clientReg.RUnlock()
	delete(clientReg.clients, uint64(client.userID))
	fmt.Printf("User offline: %d\n", client.userID)

	client.authenticated = false
	client.userID = 0
	client.deviceID = 0

	sendOk(client, (int)(C.NK_OPCODE_LOGOUT))
}

func receiveOpcodeUnregister(client *ClientConn, data []byte) {
	if C.nk_decode_unregister(
		(*C.uchar)(unsafe.Pointer(&data[0])),
		C.uint(len(data)),
		&client.rxKey[0],
	) != 0 {
		sendError(client, int(C.NK_OPCODE_UNREGISTER), int(C.NK_ERROR_INVALID_FRAME))
		return
	}

	tx, err := db.Begin()
	if err != nil {
		fmt.Println(err.Error())
		sendError(client, int(C.NK_OPCODE_UNREGISTER), int(C.NK_ERROR_INTERNAL))
		return
	}

	uid := client.userID

	if _, err = tx.Exec(`
		DELETE FROM friend_requests
		WHERE user_id=? OR recipent_id=?`,
		uid, uid); err != nil {
		fmt.Println(err.Error())
		tx.Rollback()
		goto fail
	}

	if _, err = tx.Exec(`
		DELETE FROM user_relations
		WHERE user1_id=? OR user2_id=?`,
		uid, uid); err != nil {
		fmt.Println(err.Error())
		tx.Rollback()
		goto fail
	}

	if _, err = tx.Exec(`
		DELETE FROM dm_channels
		WHERE user1_id=? OR user2_id=?`,
		uid, uid); err != nil {
		fmt.Println(err.Error())
		tx.Rollback()
		goto fail
	}

	if _, err = tx.Exec(`
		DELETE FROM devices
		WHERE user_id=?`,
		uid); err != nil {
		fmt.Println(err.Error())
		tx.Rollback()
		goto fail
	}

	if _, err = tx.Exec(`
		DELETE FROM channel_members
		WHERE user_id=?`,
		uid); err != nil {
		fmt.Println(err.Error())
		tx.Rollback()
		goto fail
	}

	if _, err = tx.Exec(`
		DELETE FROM channel_keys_device
		WHERE user_id=?`,
		uid); err != nil {
		fmt.Println(err.Error())
		tx.Rollback()
		goto fail
	}

	if _, err = tx.Exec(`
		DELETE FROM channel_keys_backup
		WHERE user_id=?`,
		uid); err != nil {
		fmt.Println(err.Error())
		tx.Rollback()
		goto fail
	}

	if _, err = tx.Exec(`
		DELETE FROM messages
		WHERE sender_id=?`,
		uid); err != nil {
		fmt.Println(err.Error())
		tx.Rollback()
		goto fail
	}

	if _, err = tx.Exec(`
		DELETE FROM users WHERE id=?`,
		uid); err != nil {
		fmt.Println(err.Error())
		tx.Rollback()
		goto fail
	}

	if err := tx.Commit(); err != nil {
		goto fail
	}

	clientReg.Lock()
	delete(clientReg.clients, uint64(uid))
	clientReg.Unlock()

	fmt.Printf("User deleted: %d\n", uid)

	client.authenticated = false
	client.userID = 0
	client.deviceID = 0

	sendOk(client, int(C.NK_OPCODE_UNREGISTER))
	return

fail:
	sendError(client, int(C.NK_OPCODE_UNREGISTER), int(C.NK_ERROR_INTERNAL))
}

func receiveOpcodeUpdateUserData(client *ClientConn, data []byte) {
	var updateType C.uint

	var payload [C.NK_MAX_PAYLOAD_USERINFO_SIZE]C.uchar
	var payloadLen C.ushort

	if C.nk_decode_update_user_data(
		(*C.uchar)(unsafe.Pointer(&data[0])),
		C.uint(len(data)),
		&client.rxKey[0],
		&updateType,
		&payload[0],
		&payloadLen,
	) != 0 {
		sendError(client, int(C.NK_OPCODE_UPDATE_USER_DATA), int(C.NK_ERROR_INVALID_FRAME))
		return
	}

	if updateType == C.NK_USERDATA_USERNAME {
		processUsernameChange(client, &payload[0], payloadLen)
		return
	}
	if updateType == C.NK_USERDATA_PASSWORD {
		processPasswordChange(client, &payload[0], payloadLen)
		return
	}
	if updateType == C.NK_USERDATA_TAG {
		processUserTagChange(client, &payload[0], payloadLen)
		return
	}

	sendError(client, int(C.NK_OPCODE_UPDATE_USER_DATA), int(C.NK_ERROR_INVALID_FRAME))
}

func processUsernameChange(client *ClientConn, payloadPtr *C.uchar, payloadLen C.ushort) {
	var uname [C.NK_MAX_USERNAME_SIZE]C.char
	var unameLen C.ushort

	if C.nk_decode_update_user_data_change_username_payload(
		payloadPtr,
		payloadLen,
		&uname[0],
		&unameLen,
	) != 0 {
		sendError(client, int(C.NK_OPCODE_UPDATE_USER_DATA), int(C.NK_ERROR_INVALID_FRAME))
		return
	}

	goUsername := C.GoBytes(
		unsafe.Pointer(&uname[0]),
		C.int(unameLen),
	)

	_, err := db.Exec(
		"UPDATE users SET username=? WHERE id=?",
		string(goUsername),
		client.userID,
	)

	if err != nil {
		fmt.Println(err.Error())
		sendError(client, int(C.NK_OPCODE_UPDATE_USER_DATA), int(C.NK_ERROR_INTERNAL))
		return
	}

	sendOk(client, int(C.NK_OPCODE_UPDATE_USER_DATA))

	goIDs := make([]int, 1)
	goIDs[0] = client.userID
	sendSyncUserData(client, goIDs)
	broadcastUserDataUpdate(client.userID)
}

func processPasswordChange(client *ClientConn, payloadPtr *C.uchar, payloadLen C.ushort) {
	var salt [C.NK_SALT_SIZE]C.uchar
	var hash [C.NK_HASH_SIZE]C.uchar

	if C.nk_decode_update_user_data_change_password_payload(
		payloadPtr,
		payloadLen,
		&salt[0],
		&hash[0],
	) != 0 {
		sendError(client, int(C.NK_OPCODE_UPDATE_USER_DATA), int(C.NK_ERROR_INVALID_FRAME))
		return
	}

	goSalt := C.GoBytes(unsafe.Pointer(&salt[0]), C.NK_SALT_SIZE)
	goHash := C.GoBytes(unsafe.Pointer(&hash[0]), C.NK_HASH_SIZE)

	_, err := db.Exec(
		"UPDATE users SET salt=?, password_hash=? WHERE id=?",
		goSalt,
		goHash,
		client.userID,
	)

	if err != nil {
		fmt.Println(err.Error())
		sendError(client, int(C.NK_OPCODE_UPDATE_USER_DATA), int(C.NK_ERROR_INTERNAL))
		return
	}

	sendOk(client, int(C.NK_OPCODE_UPDATE_USER_DATA))

	goIDs := make([]int, 1)
	goIDs[0] = client.userID
	sendSyncUserData(client, goIDs)
	broadcastUserDataUpdate(client.userID)
}

func processUserTagChange(client *ClientConn, payloadPtr *C.uchar, payloadLen C.ushort) {
	if C.nk_decode_update_user_data_change_tag_payload(
		payloadPtr,
		payloadLen,
	) != 0 {
		sendError(client, int(C.NK_OPCODE_UPDATE_USER_DATA), int(C.NK_ERROR_INVALID_FRAME))
		return
	}

	rand.Seed(time.Now().UnixNano())
	newTag := rand.Intn(90000) + 10000

	_, err := db.Exec(
		"UPDATE users SET tag=? WHERE id=?",
		newTag,
		client.userID,
	)

	if err != nil {
		fmt.Println(err.Error())
		sendError(client, int(C.NK_OPCODE_UPDATE_USER_DATA), int(C.NK_ERROR_INTERNAL))
		return
	}

	sendOk(client, int(C.NK_OPCODE_UPDATE_USER_DATA))

	goIDs := make([]int, 1)
	goIDs[0] = client.userID
	sendSyncUserData(client, goIDs)
	broadcastUserDataUpdate(client.userID)
}
