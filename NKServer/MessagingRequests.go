package main

/*
#cgo CFLAGS: -I../NKProtocol/include
#cgo LDFLAGS: -L../NKProtocol/build -lnk_protocol -lsodium -lz
#include <stdlib.h>
#include <string.h>
#include "nk_protocol.h"
*/
import "C"

import (
	"database/sql"
	"fmt"
	"time"
	"unsafe"

	"github.com/gorilla/websocket"
	_ "github.com/mattn/go-sqlite3"
)

func receiveOpcodeChannelMessageSend(client *ClientConn, data []byte) {
	if !ensureDeviceReady(client, int(C.NK_OPCODE_CHANNEL_MESSAGE_SEND)) {
		return
	}

	var channelID C.uint
	var keyVersion C.uint

	var payload [C.NK_MAX_MESSAGE_SIZE]C.uchar
	var payloadSize C.ushort

	var sig [C.NK_ED25519_SIG_SIZE]C.uchar
	if C.nk_decode_channel_message_send(
		(*C.uchar)(unsafe.Pointer(&data[0])),
		C.uint(len(data)),
		&client.rxKey[0],
		&channelID,
		&keyVersion,
		&payload[0],
		&payloadSize,
		&sig[0],
	) != 0 {
		sendError(client, int(C.NK_OPCODE_CHANNEL_MESSAGE_SEND), int(C.NK_ERROR_INVALID_FRAME))
		return
	}

	if payloadSize == 0 || payloadSize > C.NK_MAX_MESSAGE_SIZE {
		sendError(client, int(C.NK_OPCODE_CHANNEL_MESSAGE_SEND), int(C.NK_ERROR_INVALID_FRAME))
		return
	}

	var exists int
	err := db.QueryRow(`
		SELECT 1 FROM channel_members
		WHERE channel_id=? AND user_id=?`,
		int(channelID), client.userID,
	).Scan(&exists)

	if err != nil {
		fmt.Println("Not a member")
		sendError(client, int(C.NK_OPCODE_CHANNEL_MESSAGE_SEND), int(C.NK_ERROR_PERMISSION_DENIED))
		return
	}

	var edPub []byte
	err = db.QueryRow(`
		SELECT ed25519_pub FROM devices
		WHERE id=? AND user_id=?`,
		client.deviceID, client.userID,
	).Scan(&edPub)

	if err != nil || len(edPub) != int(C.NK_ED25519_PUBLIC_KEY_SIZE) {
		sendError(client, int(C.NK_OPCODE_CHANNEL_MESSAGE_SEND), int(C.NK_ERROR_INVALID_DEVICE))
		return
	}

	if C.nk_verify_signature(
		(*C.uchar)(unsafe.Pointer(&edPub[0])),
		&payload[0],
		C.uint(payloadSize),
		&sig[0],
	) != 0 {
		fmt.Println("Wrong signature")
		sendError(client, int(C.NK_OPCODE_CHANNEL_MESSAGE_SEND), int(C.NK_ERROR_INVALID_SIGNATURE))
		return
	}

	goPayload := C.GoBytes(unsafe.Pointer(&payload[0]), C.int(payloadSize))
	goSig := C.GoBytes(unsafe.Pointer(&sig[0]), C.int((int)(C.NK_ED25519_SIG_SIZE)))

	res, err := db.Exec(`
		INSERT INTO messages (channel_id, sender_id, sender_device_id, payload, sig, key_version, created_at)
		VALUES (?, ?, ?, ?, ?, ?, strftime('%s','now'))`,
		int(channelID),
		client.userID,
		client.deviceID,
		goPayload,
		goSig,
		int(keyVersion),
	)
	if err != nil {
		fmt.Println(err.Error())
		sendError(client, int(C.NK_OPCODE_CHANNEL_MESSAGE_SEND), int(C.NK_ERROR_INTERNAL))
		return
	}

	msgID, _ := res.LastInsertId()

	var msg C.NKChannelMessageData
	msg.messageId = C.uint(msgID)
	msg.senderId = C.uint(client.userID)
	msg.senderDeviceId = C.uint(client.deviceID)
	msg.keyVersion = keyVersion
	msg.payloadSize = payloadSize
	msg.updateTime = C.ulonglong(time.Now().Unix())

	C.memcpy(unsafe.Pointer(&msg.payload[0]), unsafe.Pointer(&payload[0]), C.size_t(payloadSize))
	C.memcpy(unsafe.Pointer(&msg.sig[0]), unsafe.Pointer(&sig[0]), C.size_t(C.NK_ED25519_SIG_SIZE))

	broadcastChannelMessage(int(channelID), &msg)
}

func broadcastChannelMessage(channelID int, msg *C.NKChannelMessageData) {
	rows, err := db.Query(`
		SELECT user_id FROM channel_members WHERE channel_id=?`,
		channelID,
	)
	if err != nil {
		return
	}
	defer rows.Close()

	clientReg.RLock()
	defer clientReg.RUnlock()

	for rows.Next() {
		var uid int
		if rows.Scan(&uid) != nil {
			continue
		}

		c, ok := clientReg.clients[uint64(uid)]
		if !ok || !c.authenticated {
			continue
		}

		var replySize C.uint
		reply := C.nk_encode_channel_message_deliver(
			C.uint(channelID),
			msg,
			&c.txKey[0],
			&replySize,
		)

		if reply == nil {
			continue
		}

		goReply := C.GoBytes(unsafe.Pointer(reply), C.int(replySize))
		c.conn.WriteMessage(websocket.BinaryMessage, goReply)
		C.free(unsafe.Pointer(reply))
	}
}

func receiveOpcodeSyncChannelHistoryRequest(client *ClientConn, data []byte) {
	var channelID, fromID, limit C.uint

	if C.nk_decode_sync_channel_history_request(
		(*C.uchar)(unsafe.Pointer(&data[0])),
		C.uint(len(data)),
		&client.rxKey[0],
		&channelID,
		&fromID,
		&limit,
	) != 0 {
		sendError(client, int(C.NK_OPCODE_SYNC_CHANNEL_HISTORY_REQUEST), int(C.NK_ERROR_INVALID_FRAME))
		return
	}

	var rows *sql.Rows
	var err error
	if fromID == C.NK_INVALID_MESSAGE {
		rows, err = db.Query(`
			SELECT id, sender_id, sender_device_id, payload, sig, key_version, created_at
			FROM messages
			WHERE channel_id=?
			ORDER BY id DESC
			LIMIT ?`,
			int(channelID), int(limit),
		)
		if err != nil {
			sendError(client, int(C.NK_OPCODE_SYNC_CHANNEL_HISTORY_REQUEST), int(C.NK_ERROR_INTERNAL))
			return
		}
		defer rows.Close()
	} else {
		rows, err = db.Query(`
			SELECT id, sender_id, sender_device_id, payload, sig, key_version, created_at
			FROM messages
			WHERE channel_id=? AND id>? 
			ORDER BY id DESC
			LIMIT ?`,
			int(channelID), int(fromID), int(limit),
		)
		if err != nil {
			sendError(client, int(C.NK_OPCODE_SYNC_CHANNEL_HISTORY_REQUEST), int(C.NK_ERROR_INTERNAL))
			return
		}
		defer rows.Close()
	}

	var msgs [C.NK_MAX_PAYLOAD_ARRAY_SIZE]C.NKChannelMessageData
	var outLen C.ushort = 0

	for rows.Next() {
		var id, senderID, senderDeviceID, kv int
		var payload []byte
		var sig []byte
		var ts int64

		if rows.Scan(&id, &senderID, &senderDeviceID, &payload, &sig, &kv, &ts) != nil {
			continue
		}

		if len(payload) == 0 || len(payload) > int(C.NK_MAX_MESSAGE_SIZE) {
			fmt.Println("invalid payload size:", len(payload))
			continue
		}

		m := &msgs[outLen]

		m.messageId = C.uint(id)
		m.senderId = C.uint(senderID)
		m.senderDeviceId = C.uint(senderDeviceID)
		m.keyVersion = C.uint(kv)
		m.updateTime = C.ulonglong(ts)
		m.payloadSize = C.ushort(len(payload))

		dst := (*[C.NK_MAX_MESSAGE_SIZE]byte)(unsafe.Pointer(&m.payload[0]))[:len(payload)]
		copy(dst, payload)
		dst = (*[C.NK_ED25519_SIG_SIZE]byte)(unsafe.Pointer(&m.sig[0]))[:len(sig)]
		copy(dst, sig)

		outLen++
		if outLen >= C.NK_MAX_PAYLOAD_ARRAY_SIZE {
			break
		}
	}

	if outLen == 0 {
		sendError(client, int(C.NK_OPCODE_SYNC_CHANNEL_HISTORY), int(C.NK_ERROR_NOTHING_TO_SEND))
		return
	}

	var replySize C.uint
	reply := C.nk_encode_sync_channel_history(
		channelID,
		&msgs[0],
		outLen,
		&client.txKey[0],
		&replySize,
	)

	if reply == nil {
		sendError(client, int(C.NK_OPCODE_SYNC_CHANNEL_HISTORY), int(C.NK_ERROR_INTERNAL))
		return
	}

	goReply := C.GoBytes(unsafe.Pointer(reply), C.int(replySize))
	client.conn.WriteMessage(websocket.BinaryMessage, goReply)
	C.free(unsafe.Pointer(reply))
}

func receiveOpcodeChannelTypingUpdate(client *ClientConn, data []byte) {
	var channelID C.uint
	var typingStatus C.uint

	if C.nk_decode_channel_typing_update(
		(*C.uchar)(unsafe.Pointer(&data[0])),
		C.uint(len(data)),
		&client.rxKey[0],
		&channelID,
		&typingStatus,
	) != 0 {
		sendError(client, int(C.NK_OPCODE_CHANNEL_TYPING_UPDATE), int(C.NK_ERROR_INVALID_FRAME))
		return
	}

	broadcastTyping(client.userID, int(channelID), int(typingStatus))
}

func broadcastTyping(userID, channelID, typingStatus int) {
	rows, err := db.Query(`
		SELECT user_id FROM channel_members WHERE channel_id=?`,
		channelID,
	)
	if err != nil {
		return
	}
	defer rows.Close()

	clientReg.RLock()
	defer clientReg.RUnlock()

	for rows.Next() {
		var uid int
		if rows.Scan(&uid) != nil {
			continue
		}

		if uid == userID {
			continue
		}

		c, ok := clientReg.clients[uint64(uid)]
		if !ok || !c.authenticated {
			continue
		}

		var reply *C.uchar
		var replySize C.uint

		reply = C.nk_encode_channel_typing_broadcast(
			C.uint(userID),
			C.uint(channelID),
			C.uint(typingStatus),
			&c.txKey[0],
			&replySize,
		)

		if reply == nil {
			continue
		}

		goReply := C.GoBytes(unsafe.Pointer(reply), C.int(replySize))
		c.conn.WriteMessage(websocket.BinaryMessage, goReply)
		C.free(unsafe.Pointer(reply))
	}
}
