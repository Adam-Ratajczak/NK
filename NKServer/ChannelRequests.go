package main

/*
#cgo CFLAGS: -I../NKProtocol/include
#cgo LDFLAGS: -L../NKProtocol/build -lnk_protocol -lsodium -lz
#include <stdlib.h>
#include "nk_protocol.h"
*/
import "C"

import (
	"database/sql"
	"fmt"
	"unsafe"

	"github.com/gorilla/websocket"
	_ "github.com/mattn/go-sqlite3"
)

func receiveOpcodeChannelRequestRecipents(client *ClientConn, data []byte) {
	var channelID C.uint

	if C.nk_decode_channel_request_recipents(
		(*C.uchar)(unsafe.Pointer(&data[0])),
		C.uint(len(data)),
		&client.rxKey[0],
		&channelID,
	) != 0 {
		sendError(client, int(C.NK_OPCODE_CHANNEL_REQUEST_RECIPENTS), int(C.NK_ERROR_INVALID_FRAME))
		return
	}

	var exists int
	err := db.QueryRow(`
		SELECT 1 FROM channel_members
		WHERE channel_id=? AND user_id=?`,
		int(channelID), client.userID,
	).Scan(&exists)

	if err != nil {
		fmt.Println(err.Error())
		sendError(client, int(C.NK_OPCODE_CHANNEL_REQUEST_RECIPENTS), int(C.NK_ERROR_PERMISSION_DENIED))
		return
	}

	rows, err := db.Query(`
		SELECT user_id FROM channel_members
		WHERE channel_id=?`,
		int(channelID),
	)
	if err != nil {
		fmt.Println(err.Error())
		sendError(client, int(C.NK_OPCODE_CHANNEL_REQUEST_RECIPENTS), int(C.NK_ERROR_INTERNAL))
		return
	}
	defer rows.Close()

	var userIDs [C.NK_MAX_PAYLOAD_ARRAY_SIZE]C.uint
	var outLen C.ushort = 0

	for rows.Next() {
		var uid int
		if err := rows.Scan(&uid); err != nil {
			fmt.Println(err.Error())
			continue
		}

		userIDs[outLen] = C.uint(uid)
		outLen++

		if outLen >= C.NK_MAX_PAYLOAD_ARRAY_SIZE {
			break
		}
	}

	var replySize C.uint
	reply := C.nk_encode_channel_request_recipents_result(
		channelID,
		&userIDs[0],
		outLen,
		&client.txKey[0],
		&replySize,
	)

	if reply == nil {
		sendError(client, int(C.NK_OPCODE_CHANNEL_REQUEST_RECIPENTS), int(C.NK_ERROR_INTERNAL))
		return
	}

	goReply := C.GoBytes(unsafe.Pointer(reply), C.int(replySize))
	err = client.conn.WriteMessage(websocket.BinaryMessage, goReply)
	if err != nil {
		fmt.Println("ws write error:", err)
	}

	C.free(unsafe.Pointer(reply))
}

func receiveOpcodeChannelRequestDM(client *ClientConn, data []byte) {
	var targetUserID C.uint

	if C.nk_decode_channel_request_dm(
		(*C.uchar)(unsafe.Pointer(&data[0])),
		C.uint(len(data)),
		&client.rxKey[0],
		&targetUserID,
	) != 0 {
		fmt.Println("receiveOpcodeChannelRequestDM NK_ERROR_INVALID_FRAME")
		sendError(client, int(C.NK_OPCODE_CHANNEL_REQUEST_DM), int(C.NK_ERROR_INVALID_FRAME))
		return
	}

	if int(targetUserID) == client.userID {
		fmt.Println("receiveOpcodeChannelRequestDM NK_ERROR_RECIPENT_CANNOT_BE_SENDER")
		sendError(client, int(C.NK_OPCODE_CHANNEL_REQUEST_DM), int(C.NK_ERROR_RECIPENT_CANNOT_BE_SENDER))
		return
	}

	userA := client.userID
	userB := int(targetUserID)

	if userA > userB {
		userA, userB = userB, userA
	}

	tx, err := db.Begin()
	if err != nil {
		fmt.Println(err.Error())
		sendError(client, int(C.NK_OPCODE_CHANNEL_REQUEST_DM), int(C.NK_ERROR_INTERNAL))
		return
	}

	var (
		channelID int
		chaId     int64

		replySize C.uint
		reply     *C.uchar
		goReply   []byte
	)

	err = tx.QueryRow(`
        SELECT channel_id FROM dm_channels
        WHERE user1_id=? AND user2_id=?`,
		userA, userB,
	).Scan(&channelID)

	if err == sql.ErrNoRows {
		res, err := tx.Exec(`
            INSERT INTO channels (type, created_at)
            VALUES (?, strftime('%s','now'))`,
			int(C.NK_CHANNEL_TYPE_DM),
		)
		if err != nil {
			fmt.Println(err.Error())
			tx.Rollback()
			goto fail
		}

		chaId, _ = res.LastInsertId()
		channelID = int(chaId)

		_, err = tx.Exec(`
            INSERT INTO dm_channels (user1_id, user2_id, channel_id)
            VALUES (?, ?, ?)`,
			userA, userB, channelID,
		)
		if err != nil {
			fmt.Println(err.Error())
			tx.Rollback()
			goto fail
		}

		_, err = tx.Exec(`
            INSERT INTO channel_members (channel_id, user_id, role, joined_at)
            VALUES (?, ?, 0, strftime('%s','now')),
                   (?, ?, 0, strftime('%s','now'))`,
			channelID, userA,
			channelID, userB,
		)
		if err != nil {
			fmt.Println(err.Error())
			tx.Rollback()
			goto fail
		}

	} else if err != nil {
		fmt.Println(err.Error())
		tx.Rollback()
		goto fail
	}

	if err := tx.Commit(); err != nil {
		fmt.Println(err.Error())
		goto fail
	}

	reply = C.nk_encode_channel_request_dm_result(
		targetUserID,
		C.uint(channelID),
		&client.txKey[0],
		&replySize,
	)

	if reply == nil {
		fmt.Println("NULL reply")
		goto fail
	}

	goReply = C.GoBytes(unsafe.Pointer(reply), C.int(replySize))
	client.conn.WriteMessage(websocket.BinaryMessage, goReply)
	C.free(unsafe.Pointer(reply))

	return

fail:
	sendError(client, int(C.NK_OPCODE_CHANNEL_REQUEST_DM), int(C.NK_ERROR_INTERNAL))
}

func receiveOpcodeChannelSubmitKey(client *ClientConn, data []byte) {
	fmt.Println("receiveOpcodeChannelSubmitKey")
	if !ensureDeviceReady(client, int(C.NK_OPCODE_CHANNEL_SUBMIT_KEY)) {
		return
	}
	fmt.Println("Device ready")

	var channelID C.uint

	var deviceKeys [C.NK_MAX_PAYLOAD_ARRAY_SIZE]C.NKChannelSubmitDeviceKey
	var deviceKeysLen C.ushort

	var umkEnc [C.NK_MAX_ENCRYPTED_KEY_SIZE]C.uchar
	var umkEncSize C.ushort

	if C.nk_decode_channel_submit_key(
		(*C.uchar)(unsafe.Pointer(&data[0])),
		C.uint(len(data)),
		&client.rxKey[0],
		&channelID,
		&deviceKeys[0],
		&deviceKeysLen,
		&umkEnc[0],
		&umkEncSize,
	) != 0 {
		sendError(client, int(C.NK_OPCODE_CHANNEL_SUBMIT_KEY), int(C.NK_ERROR_INVALID_FRAME))
		return
	}

	var exists int
	err := db.QueryRow(`
		SELECT 1 FROM channel_members
		WHERE channel_id=? AND user_id=?`,
		int(channelID), client.userID,
	).Scan(&exists)

	if err != nil {
		fmt.Println(err.Error())
		sendError(client, int(C.NK_OPCODE_CHANNEL_SUBMIT_KEY), int(C.NK_ERROR_PERMISSION_DENIED))
		return
	}

	tx, err := db.Begin()
	if err != nil {
		fmt.Println(err.Error())
		sendError(client, int(C.NK_OPCODE_CHANNEL_SUBMIT_KEY), int(C.NK_ERROR_INTERNAL))
		return
	}

	var keyVersion int
	var replySize C.uint
	var reply *C.uchar
	var goReply []byte
	err = tx.QueryRow(`
		SELECT COALESCE(MAX(key_version), 0) + 1
		FROM channel_keys_device
		WHERE channel_id=?`,
		int(channelID),
	).Scan(&keyVersion)

	var umkBytes []byte
	if err != nil {
		fmt.Println(err.Error())
		tx.Rollback()
		goto fail
	}

	for i := 0; i < int(deviceKeysLen); i++ {
		dk := &deviceKeys[i]

		keyBytes := C.GoBytes(
			unsafe.Pointer(&dk.encryptedKey[0]),
			C.int(dk.encryptedKeySize),
		)

		_, err = tx.Exec(`
			INSERT INTO channel_keys_device
			(channel_id, key_version, sender_device_id, target_device_id, encrypted_key)
			VALUES (?, ?, ?, ?, ?)`,
			int(channelID),
			keyVersion,
			client.deviceID,
			int(dk.targetDeviceId),
			keyBytes,
		)

		if err != nil {
			fmt.Println(err.Error())
			tx.Rollback()
			goto fail
		}
	}

	umkBytes = C.GoBytes(unsafe.Pointer(&umkEnc[0]), C.int(umkEncSize))

	_, err = tx.Exec(`
		INSERT INTO channel_keys_backup
		(channel_id, key_version, user_id, encrypted_key)
		VALUES (?, ?, ?, ?)`,
		int(channelID),
		keyVersion,
		client.userID,
		umkBytes,
	)

	if err != nil {
		fmt.Println(err.Error())
		tx.Rollback()
		goto fail
	}

	if err := tx.Commit(); err != nil {
		goto fail
	}

	reply = C.nk_encode_channel_submit_key_result(
		channelID,
		C.uint(keyVersion),
		&umkEnc[0], umkEncSize,
		&client.txKey[0],
		&replySize,
	)

	if reply == nil {
		fmt.Printf("submit key NK_ERROR_INTERNAL\n")
		sendError(client, int(C.NK_OPCODE_SYNC_CHANNEL_KEYS), int(C.NK_ERROR_INTERNAL))
		return
	}
	fmt.Printf("Sending channel key\n")

	goReply = C.GoBytes(unsafe.Pointer(reply), C.int(replySize))
	client.conn.WriteMessage(websocket.BinaryMessage, goReply)
	C.free(unsafe.Pointer(reply))
	return

fail:
	sendError(client, int(C.NK_OPCODE_CHANNEL_SUBMIT_KEY), int(C.NK_ERROR_INTERNAL))
}

func receiveOpcodeChannelBackupKeys(client *ClientConn, data []byte) {
	var keys [C.NK_MAX_PAYLOAD_ARRAY_SIZE]C.NKEncryptedChannelBackupKeyData
	var keysLen C.ushort

	if C.nk_decode_channel_backup_keys(
		(*C.uchar)(unsafe.Pointer(&data[0])),
		C.uint(len(data)),
		&client.rxKey[0],
		&keys[0],
		&keysLen,
	) != 0 {
		sendError(client, int(C.NK_OPCODE_CHANNEL_BACKUP_KEY), int(C.NK_ERROR_INVALID_FRAME))
		return
	}

	tx, err := db.Begin()
	if err != nil {
		sendError(client, int(C.NK_OPCODE_CHANNEL_BACKUP_KEY), int(C.NK_ERROR_INTERNAL))
		return
	}

	for i := 0; i < int(keysLen); i++ {
		k := &keys[i]

		keyBytes := C.GoBytes(unsafe.Pointer(&k.encryptedKey[0]), C.int(k.encryptedKeySize))

		_, err = tx.Exec(`
			INSERT INTO channel_keys_backup
			(channel_id, key_version, user_id, encrypted_key)
			VALUES (?, ?, ?, ?)`,
			int(k.channelId),
			int(k.keyVersion),
			client.userID,
			keyBytes,
		)

		if err != nil {
			tx.Rollback()
			goto fail
		}
	}

	if err := tx.Commit(); err != nil {
		goto fail
	}

	sendOk(client, int(C.NK_OPCODE_CHANNEL_BACKUP_KEY))
	return

fail:
	sendError(client, int(C.NK_OPCODE_CHANNEL_BACKUP_KEY), int(C.NK_ERROR_INTERNAL))
}

func receiveOpcodeSyncChannelKeysRequest(client *ClientConn, data []byte) {
	fmt.Println("receiveOpcodeSyncChannelKeysRequest")
	if !ensureDeviceReady(client, int(C.NK_OPCODE_SYNC_CHANNEL_KEYS_REQUEST)) {
		return
	}

	var channelID C.uint

	if C.nk_decode_sync_channel_keys_request(
		(*C.uchar)(unsafe.Pointer(&data[0])),
		C.uint(len(data)),
		&client.rxKey[0],
		&channelID,
	) != 0 {
		fmt.Println("receiveOpcodeSyncChannelKeysRequest NK_ERROR_INVALID_FRAME")
		sendError(client, int(C.NK_OPCODE_SYNC_CHANNEL_KEYS_REQUEST), int(C.NK_ERROR_INVALID_FRAME))
		return
	}

	rows, err := db.Query(`
		SELECT key_version, sender_device_id, target_device_id, encrypted_key
		FROM channel_keys_device
		WHERE channel_id=? AND target_device_id=?`,
		int(channelID), client.deviceID,
	)
	if err != nil {
		fmt.Println(err.Error())
		sendError(client, int(C.NK_OPCODE_SYNC_CHANNEL_KEYS_REQUEST), int(C.NK_ERROR_INTERNAL))
		return
	}
	defer rows.Close()

	var deviceKeys [C.NK_MAX_PAYLOAD_ARRAY_SIZE]C.NKChannelDeviceKeyData
	var dLen C.ushort = 0

	for rows.Next() {
		var kv, sender, target int
		var enc []byte

		if rows.Scan(&kv, &sender, &target, &enc) != nil {
			continue
		}

		d := &deviceKeys[dLen]

		d.keyVersion = C.uint(kv)
		d.senderDeviceId = C.uint(sender)
		d.targetDeviceId = C.uint(target)
		d.encryptedKeySize = C.ushort(len(enc))

		copy((*[C.NK_MAX_ENCRYPTED_KEY_SIZE]byte)(unsafe.Pointer(&d.encryptedKey[0]))[:], enc)

		dLen++
		if dLen >= C.NK_MAX_PAYLOAD_ARRAY_SIZE {
			break
		}
	}

	rows2, err := db.Query(`
		SELECT key_version, encrypted_key
		FROM channel_keys_backup
		WHERE channel_id=? AND user_id=?`,
		int(channelID), client.userID,
	)
	if err != nil {
		fmt.Println(err.Error())
		sendError(client, int(C.NK_OPCODE_SYNC_CHANNEL_KEYS_REQUEST), int(C.NK_ERROR_INTERNAL))
		return
	}
	defer rows2.Close()

	var backupKeys [C.NK_MAX_PAYLOAD_ARRAY_SIZE]C.NKChannelBackupKeyData
	var bLen C.ushort = 0

	for rows2.Next() {
		var kv int
		var enc []byte

		if rows2.Scan(&kv, &enc) != nil {
			continue
		}

		b := &backupKeys[bLen]

		b.keyVersion = C.uint(kv)
		b.encryptedKeySize = C.ushort(len(enc))

		copy((*[C.NK_MAX_ENCRYPTED_KEY_SIZE]byte)(unsafe.Pointer(&b.encryptedKey[0]))[:], enc)

		bLen++
		if bLen >= C.NK_MAX_PAYLOAD_ARRAY_SIZE {
			break
		}
	}

	if bLen == 0 {
		fmt.Println("Nothing to send")
		sendError(client, int(C.NK_OPCODE_SYNC_CHANNEL_KEYS_REQUEST), int(C.NK_ERROR_NOTHING_TO_SEND))
	}

	var replySize C.uint
	reply := C.nk_encode_sync_channel_keys(
		channelID,
		&deviceKeys[0], dLen,
		&backupKeys[0], bLen,
		&client.txKey[0],
		&replySize,
	)

	if reply == nil {
		fmt.Println("NULL reply")
		sendError(client, int(C.NK_OPCODE_SYNC_CHANNEL_KEYS), int(C.NK_ERROR_INTERNAL))
		return
	}
	fmt.Printf("Sending %d channel keys\n", bLen)

	goReply := C.GoBytes(unsafe.Pointer(reply), C.int(replySize))
	client.conn.WriteMessage(websocket.BinaryMessage, goReply)
	C.free(unsafe.Pointer(reply))
}
