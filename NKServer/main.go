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
	"log"
	"net/http"
	"strconv"
	"sync"

	"github.com/gorilla/websocket"
	"github.com/labstack/echo/v4"

	"database/sql"

	_ "github.com/mattn/go-sqlite3"
)

type ClientConn struct {
	conn *websocket.Conn

	userID        int
	deviceID      int
	authenticated bool

	serverPk [32]C.uchar
	serverSk [32]C.uchar

	rxKey [32]C.uchar
	txKey [32]C.uchar

	handshakeDone bool

	writeMu sync.Mutex
}

type ClentRegistry struct {
	sync.RWMutex
	clients map[uint64]*ClientConn
}

var clientReg = &ClentRegistry{
	clients: make(map[uint64]*ClientConn),
}

var upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool {
		return true
	},
}

var db *sql.DB

func wsHandler(c echo.Context) error {

	conn, err := upgrader.Upgrade(c.Response(), c.Request(), nil)
	if err != nil {
		return err
	}

	client := &ClientConn{
		conn: conn,
	}
	C.nk_crypto_x25519_keypair(&client.serverPk[0], &client.serverSk[0])

	defer func() {
		if client.authenticated {
			clientReg.RLock()
			defer clientReg.RUnlock()
			delete(clientReg.clients, uint64(client.userID))
			fmt.Printf("User offline: %d\n", client.userID)
		}
		// if client.authenticated {
		// 	hub.Lock()
		// 	delete(hub.clients, client.userID)
		// 	hub.Unlock()
		// }

		// C.sodium_memzero(unsafe.Pointer(&client.serverSk[0]), 32)
		// C.sodium_memzero(unsafe.Pointer(&client.rxKey[0]), 32)
		// C.sodium_memzero(unsafe.Pointer(&client.txKey[0]), 32)
	}()

	for {
		msgType, data, err := conn.ReadMessage()
		if err != nil {
			log.Println("ws read error:", err)
			break
		}

		if msgType != websocket.BinaryMessage {
			continue
		}

		var opcode C.uchar
		var payloadLen C.uint

		if C.nk_decode_header(
			(*C.uchar)(&data[0]),
			(C.uint)(len(data)),
			&opcode,
			&payloadLen,
		) != 0 {
			sendError(client, (int)(C.NK_OPCODE_INVALID), (int)(C.NK_ERROR_INVALID_FRAME))
			continue
		}

		if opcode == C.NK_OPCODE_HELLO {
			receiveOpcodeHello(client, data)
			continue
		}

		if !client.handshakeDone {
			sendError(client, (int)(opcode), (int)(C.NK_ERROR_AUTH_FAILED))
			continue
		}

		if opcode == C.NK_OPCODE_REGISTER {
			receiveOpcodeRegister(client, data)
			continue
		}
		if opcode == C.NK_OPCODE_REQUEST_SALT {
			receiveOpcodeRequestSalt(client, data)
			continue
		}

		if opcode == C.NK_OPCODE_LOGIN {
			receiveOpcodeLogin(client, data)
			continue
		}

		if !client.authenticated {
			sendError(client, (int)(opcode), (int)(C.NK_ERROR_AUTH_FAILED))
			continue
		}

		if opcode == C.NK_OPCODE_LOGOUT {
			receiveOpcodeLogout(client, data)
			continue
		}

		if opcode == C.NK_OPCODE_UNREGISTER {
			receiveOpcodeUnregister(client, data)
			continue
		}

		if opcode == C.NK_OPCODE_REGISTER_NEW_DEVICE_KEYS {
			receiveOpcodeRegisterNewDeviceKeys(client, data)
			continue
		}

		if opcode == C.NK_OPCODE_REQUEST_DEVICES {
			receiveOpcodeRequestDevices(client, data)
			continue
		}

		if opcode == C.NK_OPCODE_REQUEST_USER_DEVICES {
			receiveOpcodeRequestUserDevices(client, data)
			continue
		}

		if opcode == C.NK_OPCODE_UPDATE_USER_DATA {
			receiveOpcodeUpdateUserData(client, data)
			continue
		}

		if opcode == C.NK_OPCODE_FRIEND_REQUEST {
			receiveOpcodeFriendRequest(client, data)
			continue
		}

		if opcode == C.NK_OPCODE_FRIEND_REQUEST_UPDATE_STATUS {
			receiveOpcodeFriendRequestUpdateStatus(client, data)
			continue
		}

		if opcode == C.NK_OPCODE_USER_RELATION_BLOCK {
			receiveOpcodeUserRelationBlock(client, data)
			continue
		}

		if opcode == C.NK_OPCODE_USER_RELATION_RESET {
			receiveOpcodeUserRelationReset(client, data)
			continue
		}

		if opcode == C.NK_OPCODE_CHANNEL_REQUEST_DM {
			receiveOpcodeChannelRequestDM(client, data)
			continue
		}

		if opcode == C.NK_OPCODE_CHANNEL_REQUEST_RECIPENTS {
			receiveOpcodeChannelRequestRecipents(client, data)
			continue
		}

		if opcode == C.NK_OPCODE_CHANNEL_SUBMIT_KEY {
			receiveOpcodeChannelSubmitKey(client, data)
			continue
		}

		if opcode == C.NK_OPCODE_CHANNEL_BACKUP_KEY {
			receiveOpcodeChannelBackupKeys(client, data)
			continue
		}

		if opcode == C.NK_OPCODE_SYNC_CHANNEL_KEYS_REQUEST {
			receiveOpcodeSyncChannelKeysRequest(client, data)
			continue
		}

		if opcode == C.NK_OPCODE_CHANNEL_MESSAGE_SEND {
			receiveOpcodeChannelMessageSend(client, data)
			continue
		}

		if opcode == C.NK_OPCODE_SYNC_CHANNEL_HISTORY_REQUEST {
			receiveOpcodeSyncChannelHistoryRequest(client, data)
			continue
		}

		if opcode == C.NK_OPCODE_CHANNEL_TYPING_UPDATE {
			receiveOpcodeChannelTypingUpdate(client, data)
			continue
		}

		sendError(client, int(C.NK_OPCODE_INVALID), int(C.NK_ERROR_OPCODE_NOT_SUPPORTED))
	}

	return nil
}

func main() {
	C.nk_init()

	var version [4]C.int
	C.nk_get_version(&version[0])

	log.Println(
		"NK v" +
			strconv.Itoa(int(version[0])) + "." +
			strconv.Itoa(int(version[1])) + "." +
			strconv.Itoa(int(version[2])) + "." +
			strconv.Itoa(int(version[3])),
	)

	var err error
	db, err = sql.Open("sqlite3", "/app/data/nk.db")
	if err != nil {
		log.Fatal(err)
	}

	if err = db.Ping(); err != nil {
		log.Fatal(err)
	}

	createTable := `
		CREATE TABLE IF NOT EXISTS users (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			username TEXT NOT NULL UNIQUE,
			tag INTEGER NOT NULL,
			pfp_resource_id INTEGER DEFAULT -1,

			salt BLOB NOT NULL,
			password_hash BLOB NOT NULL,

			umk_nonce BLOB NOT NULL,
			umk_cipher BLOB NOT NULL,

			created_at DATETIME DEFAULT CURRENT_TIMESTAMP
		);
		`

	_, err = db.Exec(createTable)
	if err != nil {
		log.Fatal(err)
	}

	createTable = `
		CREATE TABLE IF NOT EXISTS devices (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			user_id INTEGER NOT NULL,

			x25519_pub BLOB,
			ed25519_pub BLOB,

			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,

			UNIQUE(user_id, x25519_pub)
		);
		`
	_, err = db.Exec(createTable)
	if err != nil {
		log.Fatal(err)
	}

	createTable = `
		CREATE TABLE IF NOT EXISTS friend_requests (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			user_id INTEGER NOT NULL,
			recipent_id INTEGER NOT NULL,
			status INTEGER NOT NULL,
			last_update DATETIME DEFAULT CURRENT_TIMESTAMP
		);
		`

	_, err = db.Exec(createTable)
	if err != nil {
		log.Fatal(err)
	}

	createTable = `
		CREATE TABLE IF NOT EXISTS user_relations (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			user1_id INTEGER NOT NULL,
			user2_id INTEGER NOT NULL,
			relation_type INTEGER NOT NULL,
			direction INTEGER NOT NULL,
			last_update DATETIME DEFAULT CURRENT_TIMESTAMP,

    		UNIQUE(user1_id, user2_id)
		);
		`
	_, err = db.Exec(createTable)
	if err != nil {
		log.Fatal(err)
	}

	createTable = `
		CREATE TABLE IF NOT EXISTS channels (
			id INTEGER PRIMARY KEY,
			type INTEGER,
			created_at INTEGER
		);
		`
	_, err = db.Exec(createTable)
	if err != nil {
		log.Fatal(err)
	}

	createTable = `
		CREATE TABLE IF NOT EXISTS dm_channels (
			user1_id INTEGER NOT NULL,
			user2_id INTEGER NOT NULL,
			channel_id INTEGER NOT NULL,
			UNIQUE(user1_id, user2_id)
		);
		`
	_, err = db.Exec(createTable)
	if err != nil {
		log.Fatal(err)
	}

	createTable = `
		CREATE TABLE IF NOT EXISTS channel_members (
			channel_id INTEGER,
			user_id INTEGER,
			role INTEGER,
			joined_at INTEGER,

			PRIMARY KEY (channel_id, user_id)
		);
		`
	_, err = db.Exec(createTable)
	if err != nil {
		log.Fatal(err)
	}

	createTable = `
		CREATE TABLE IF NOT EXISTS channel_keys_device (
			channel_id INTEGER NOT NULL,
			key_version INTEGER NOT NULL,

			sender_device_id INTEGER NOT NULL,
			target_device_id INTEGER NOT NULL,

			encrypted_key BLOB NOT NULL,

			PRIMARY KEY (channel_id, target_device_id, key_version)
		);
		`
	_, err = db.Exec(createTable)
	if err != nil {
		log.Fatal(err)
	}

	createTable = `
		CREATE TABLE IF NOT EXISTS channel_keys_backup (
			channel_id INTEGER,
			key_version INTEGER,
			user_id INTEGER,

			encrypted_key BLOB NOT NULL,

			PRIMARY KEY (channel_id, key_version, user_id)
		);
		`
	_, err = db.Exec(createTable)
	if err != nil {
		log.Fatal(err)
	}

	createTable = `
		CREATE TABLE IF NOT EXISTS messages (
			id INTEGER PRIMARY KEY AUTOINCREMENT,

			channel_id INTEGER,
			sender_id INTEGER,
			sender_device_id INTEGER,

			payload BLOB NOT NULL,
			sig BLOB NOT NULL,
			key_version INTEGER,

			created_at INTEGER
		);
		`
	_, err = db.Exec(createTable)
	if err != nil {
		log.Fatal(err)
	}

	e := echo.New()

	e.Static("/", "client")

	e.GET("/ws", wsHandler)

	e.Logger.Fatal(e.Start(":8080"))
}
