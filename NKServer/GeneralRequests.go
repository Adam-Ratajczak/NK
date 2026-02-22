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

func receiveOpcodeHello(client *ClientConn, data []byte) {
	var pk [32]C.uchar

	if C.nk_decode_hello(
		(*C.uchar)(&data[0]),
		C.uint(len(data)),
		&pk[0],
	) != 0 {
		var replySize C.uint
		reply := C.nk_encode_hello(&client.serverPk[0], &replySize)

		goReply := C.GoBytes(unsafe.Pointer(reply), C.int(replySize))

		client.conn.WriteMessage(websocket.BinaryMessage, goReply)

		C.free(unsafe.Pointer(reply))
		return
	}

	C.nk_server_derive_keys(&client.rxKey[0], &client.txKey[0], &client.serverPk[0], &client.serverSk[0], &pk[0])

	var replySize C.uint
	reply := C.nk_encode_hello(&client.serverPk[0], &replySize)

	goReply := C.GoBytes(unsafe.Pointer(reply), C.int(replySize))

	client.conn.WriteMessage(websocket.BinaryMessage, goReply)

	C.free(unsafe.Pointer(reply))
	client.handshakeDone = true
}

func sendOk(client *ClientConn, opcode int) {
	var replySize C.uint
	reply := C.nk_encode_ok((C.uchar)(opcode), &client.txKey[0], &replySize)

	goReply := C.GoBytes(unsafe.Pointer(reply), C.int(replySize))
	client.conn.WriteMessage(websocket.BinaryMessage, goReply)
	C.free(unsafe.Pointer(reply))

	fmt.Printf("Sending OK to user %d with opcode %x\n", client.userID, opcode)
}

func sendError(client *ClientConn, opcode, errNo int) {
	var replySize C.uint
	reply := C.nk_encode_error((C.uchar)(opcode), (C.int)(errNo), &client.txKey[0], &replySize)

	goReply := C.GoBytes(unsafe.Pointer(reply), C.int(replySize))
	client.conn.WriteMessage(websocket.BinaryMessage, goReply)
	C.free(unsafe.Pointer(reply))

	fmt.Printf("Sending error to user %d with opcode %x and errNo %x\n", client.userID, opcode, errNo)
}
