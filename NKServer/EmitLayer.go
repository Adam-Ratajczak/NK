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

	_ "github.com/mattn/go-sqlite3"
)

func SynchroOnLogin(userID int) {

	client, ok := getLoggedClient(uint64(userID))
	if !ok {
		return
	}

	userSet := map[int]struct{}{}
	userSet[userID] = struct{}{}

	rows, err := db.Query(`
		SELECT id, user_id, status,
		       strftime('%s', last_update)
		FROM friend_requests
		WHERE recipent_id = ?
		   OR (user_id = ? AND status = ?)
	`, userID, userID, C.NK_FRIEND_REQUEST_ACCEPTED)

	if err == nil {
		defer rows.Close()

		for rows.Next() {
			var id int
			var sender int
			var status int
			var updateTime int64

			if rows.Scan(&id, &sender, &status, &updateTime) == nil {

				sendFriendRequestData(
					client,
					id,
					sender,
					status,
					updateTime,
				)

				userSet[sender] = struct{}{}
			}
		}
	}

	rows2, err := db.Query(`
		SELECT id, user1_id, user2_id,
		       relation_type, direction,
		       strftime('%s', last_update)
		FROM user_relations
		WHERE user1_id = ? OR user2_id = ?
	`, userID, userID)

	if err == nil {
		defer rows2.Close()

		for rows2.Next() {
			var id int
			var u1 int
			var u2 int
			var relation int
			var direction int
			var updateTime int64

			if rows2.Scan(&id, &u1, &u2, &relation, &direction, &updateTime) == nil {

				recip := u1
				if u1 == userID {
					recip = u2
				}

				sendRelationData(
					client,
					id,
					recip,
					relation,
					direction,
					updateTime,
				)

				userSet[recip] = struct{}{}
			}
		}
	}

	goIDs := make([]int, 0, len(userSet))
	for id := range userSet {
		goIDs = append(goIDs, id)
	}

	fmt.Printf("Sending users: %d\n", len(goIDs))
	sendSyncUserData(client, goIDs)
}
