#include "networking/RequestManager.hpp"
#include "networking/NetworkManager.hpp"
#include "networking/SessionManager.hpp"
#include "networking/DevicesManager.hpp"
#include "networking/UserManager.hpp"
#include "networking/FriendRequestsManager.hpp"
#include "networking/UserRelationsManager.hpp"
#include "networking/ChannelMessagesManager.hpp"
#include "networking/ChannelKeysManager.hpp"
#include "networking/ChannelsManager.hpp"
#include "forms/LoginForm.hpp"
#include "nk_protocol.h"

std::map<unsigned char, RequestDelegate> RequestManager::_requestSubscribers;
std::map<unsigned char, OkRequestDelegate> RequestManager::_okRequestSubscribers;
std::map<unsigned char, ErrorRequestDelegate> RequestManager::_errorRequestSubscribers;
void RequestManager::Register(){
    SubscribeRequest(NK_OPCODE_HELLO, &RequestManager::ProcessHelloRequest);
    SubscribeRequest(NK_OPCODE_OK, &RequestManager::ProcessOkRequest);
    SubscribeRequest(NK_OPCODE_ERROR, &RequestManager::ProcessErrorRequest);
    SubscribeRequest(NK_OPCODE_REQUEST_SALT_RESULT, &RequestManager::ProcessRequestSaltResultRequest);
    SubscribeRequest(NK_OPCODE_LOGIN_RESULT, &RequestManager::ProcessLoginResultRequest);
    SubscribeRequest(NK_OPCODE_SYNC_USER_DATA, &RequestManager::ProcessSyncUserDataRequest);
    SubscribeRequest(NK_OPCODE_SYNC_FRIEND_REQUESTS, &RequestManager::ProcessSyncFriendRequestsRequest);
    SubscribeRequest(NK_OPCODE_SYNC_RELATIONS, &RequestManager::ProcessSyncRelationsRequest);
    SubscribeRequest(NK_OPCODE_REQUEST_DEVICES_RESULT, &RequestManager::ProcessRequestDevicesResult);
    SubscribeRequest(NK_OPCODE_CHANNEL_REQUEST_DM_RESULT, &RequestManager::ProcessChannelRequestDMResultRequest);
    SubscribeRequest(NK_OPCODE_CHANNEL_REQUEST_RECIPENTS_RESULT, &RequestManager::ProcessChannelRequestRecipentsResultRequest);
    SubscribeRequest(NK_OPCODE_CHANNEL_SUBMIT_KEY_RESULT, &RequestManager::ProcessChannelSubmitKeyResultRequest);
    SubscribeRequest(NK_OPCODE_SYNC_CHANNEL_KEYS, &RequestManager::ProcessSyncChannelKeysRequest);
    SubscribeRequest(NK_OPCODE_CHANNEL_MESSAGE_DELIVER, &RequestManager::ProcessChannelMessageDeliverRequest);
    SubscribeRequest(NK_OPCODE_SYNC_CHANNEL_HISTORY, &RequestManager::ProcessSyncChannelHistoryRequest);
    SubscribeRequest(NK_OPCODE_CHANNEL_TYPING_BROADCAST, &RequestManager::ProcessChannelTypingBroadcastRequest);
}

void RequestManager::Unregister(){
    UnsubscribeRequest(NK_OPCODE_HELLO);
    UnsubscribeRequest(NK_OPCODE_OK);
    UnsubscribeRequest(NK_OPCODE_ERROR);
    UnsubscribeRequest(NK_OPCODE_REQUEST_SALT_RESULT);
    UnsubscribeRequest(NK_OPCODE_LOGIN_RESULT);
    UnsubscribeRequest(NK_OPCODE_SYNC_USER_DATA);
    UnsubscribeRequest(NK_OPCODE_SYNC_FRIEND_REQUESTS);
    UnsubscribeRequest(NK_OPCODE_SYNC_RELATIONS);
    UnsubscribeRequest(NK_OPCODE_CHANNEL_SUBMIT_KEY_RESULT);
    UnsubscribeRequest(NK_OPCODE_SYNC_CHANNEL_KEYS);
}

void RequestManager::SubscribeRequest(unsigned char opcode, RequestDelegate delegate){
    _requestSubscribers[opcode] = delegate;
}

void RequestManager::UnsubscribeRequest(unsigned char opcode){
    auto it = _requestSubscribers.find(opcode);
    if(it != _requestSubscribers.end()){
        _requestSubscribers.erase(it);
    }
}

void RequestManager::SubscribeOkRequest(unsigned char opcode, OkRequestDelegate delegate){
    _okRequestSubscribers[opcode] = delegate;
}

void RequestManager::UnsubscribeOkRequest(unsigned char opcode){
    auto it = _okRequestSubscribers.find(opcode);
    if(it != _okRequestSubscribers.end()){
        _okRequestSubscribers.erase(it);
    }
}

void RequestManager::SubscribeErrorRequest(unsigned char opcode, ErrorRequestDelegate delegate){
    _errorRequestSubscribers[opcode] = delegate;
}

void RequestManager::UnsubscribeErrorRequest(unsigned char opcode){
    auto it = _errorRequestSubscribers.find(opcode);
    if(it != _errorRequestSubscribers.end()){
        _errorRequestSubscribers.erase(it);
    }
}

void RequestManager::ProcessRequest(const unsigned char* data, int len){
    unsigned char opcode = 0;
    unsigned int payloadLen = 0;
    if(nk_decode_header(data, len, &opcode, &payloadLen) != 0){
        ApplyError(NK_OPCODE_INVALID, NK_ERROR_INVALID_FRAME);
        return;
    }
    
    auto it = _requestSubscribers.find(opcode);
    if (it != _requestSubscribers.end() && it->second) {
        it->second(data, len);
    }
}

void RequestManager::ProcessHelloRequest(const unsigned char* data, int len){
    unsigned char serverPk[32] = {};
    if(nk_decode_hello(data, len, serverPk) == 0){
        SessionManager::SetServerPublicKey(serverPk);
    }else{
        ApplyError(NK_OPCODE_HELLO, NK_ERROR_INVALID_FRAME);
    }
}

void RequestManager::ProcessOkRequest(const unsigned char* data, int len){
    unsigned char opcode = 0;
    if(nk_decode_ok(data, len, SessionManager::RxKey.data(), &opcode) == 0){
        ApplyOk(opcode);
    }else{
        ApplyError(NK_OPCODE_HELLO, NK_ERROR_INVALID_FRAME);
    }
}

void RequestManager::ProcessErrorRequest(const unsigned char* data, int len){
    unsigned char opcode = 0;
    int errNo = 0;
    if(nk_decode_error(data, len, SessionManager::RxKey.data(), &opcode, &errNo) == 0){
        ApplyError(opcode, errNo);
    }else{
        ApplyError(NK_OPCODE_ERROR, NK_ERROR_INVALID_FRAME);
    }
}

void RequestManager::ProcessRequestSaltResultRequest(const unsigned char* data, int len){
    unsigned char saltBytes[NK_SALT_SIZE] = {};
    if(nk_decode_request_salt_result(data, len, SessionManager::RxKey.data(), saltBytes) == 0){
        UserManager::ReceiveSaltBytes(saltBytes);
    }else{
        ApplyError(NK_OPCODE_REQUEST_SALT_RESULT, NK_ERROR_INVALID_FRAME);
    }
}

void RequestManager::ProcessLoginResultRequest(const unsigned char* data, int len){
    unsigned int deviceId = 0;
    printf("Processing login result\n");
    fflush(stdout);
    if(nk_decode_login_result(data, len, SessionManager::RxKey.data(), UserManager::Password.c_str(), UserManager::Password.size(), 
                                         UserManager::SaltBytes.data(), &UserManager::UserId, &deviceId, UserManager::UMK.data()) == 0){
        printf("Device ID: %d\n", deviceId);
        fflush(stdout);
        DevicesManager::GetDeviceKeys(deviceId);
        LoginForm::HandleSuccess();
    }else{
        ApplyError(NK_OPCODE_LOGIN_RESULT, NK_ERROR_INVALID_FRAME);
        printf("Error\n");
        fflush(stdout);
    }
}

void RequestManager::ProcessRequestDevicesResult(const unsigned char* data, int len){
    NKDeviceData deviceData[NK_MAX_PAYLOAD_ARRAY_SIZE] = {};
    unsigned short deviceDataLen = 0;
    if(nk_decode_request_devices_result(data, len, SessionManager::RxKey.data(), deviceData, &deviceDataLen) == 0){
        std::vector<DeviceInfo> devices;
        for(size_t i = 0; i < deviceDataLen; i++){
            devices.emplace_back(DeviceInfo{
                .DeviceId = deviceData[i].deviceId,
                .OwnerId = deviceData[i].userId
            });
            memcpy(devices.back().X25519_pub.data(), deviceData[i].x25519_pub, devices.back().X25519_pub.size());
            memcpy(devices.back().Ed25519_pub.data(), deviceData[i].ed25519_pub, devices.back().Ed25519_pub.size());
        }
        DevicesManager::LoadDeviceInfo(devices);
    }else{
        ApplyError(NK_OPCODE_SYNC_USER_DATA, NK_ERROR_INVALID_FRAME);
    }
}

void RequestManager::ProcessSyncUserDataRequest(const unsigned char* data, int len){
    NKUserData userData[NK_MAX_PAYLOAD_ARRAY_SIZE] = {};
    unsigned short userDataLen = 0;
    if(nk_decode_sync_user_data(data, len, SessionManager::RxKey.data(), userData, &userDataLen) == 0){
        std::vector<UserInfo> users;
        for(size_t i = 0; i < userDataLen; i++){
            users.emplace_back(UserInfo{
                .UserId = userData[i].userId,
                .UserTag = userData[i].userTag,
                .UserPfpResourceId = userData[i].pfpResourceId,
                .UserName = userData[i].username,
                .JoinedDate = std::chrono::system_clock::time_point(std::chrono::seconds(userData[i].joinedTime)),
            });
        }
        UserManager::LoadUserInfo(users);
    }else{
        ApplyError(NK_OPCODE_SYNC_USER_DATA, NK_ERROR_INVALID_FRAME);
    }
}

void RequestManager::ProcessSyncFriendRequestsRequest(const unsigned char* data, int len){
    printf("Processing sync requests\n");
    fflush(stdout);
    NKFriendRequestData friendRequestData[NK_MAX_PAYLOAD_ARRAY_SIZE] = {};
    unsigned short friendRequestDataLen = 0;
    if(nk_decode_sync_friend_requests(data, len, SessionManager::RxKey.data(), friendRequestData, &friendRequestDataLen) == 0){
        std::vector<FriendRequestInfo> friendRequests;
        for(size_t i = 0; i < friendRequestDataLen; i++){
            FriendRequestStatus status;
            switch(friendRequestData[i].statusCode){
                case NK_FRIEND_REQUEST_PENDING:
                    status = FriendRequestStatus::PENDING;
                    break;
                case NK_FRIEND_REQUEST_ACCEPTED:
                    status = FriendRequestStatus::ACCEPTED;
                    break;
                case NK_FRIEND_REQUEST_DENIED:
                    status = FriendRequestStatus::DENIED;
                    break;
            }
                friendRequests.emplace_back(FriendRequestInfo{
                .RequestId = friendRequestData[i].requestId,
                .SenderId = friendRequestData[i].senderId,
                .StatusCode = status,
                .UpdateTime = std::chrono::system_clock::time_point(std::chrono::seconds(friendRequestData[i].updateTime)),
            });
        }
        FriendRequestsManager::LoadFriendRequestInfo(friendRequests);
    }else{
        ApplyError(NK_OPCODE_SYNC_FRIEND_REQUESTS, NK_ERROR_INVALID_FRAME);
    }
}

void RequestManager::ProcessSyncRelationsRequest(const unsigned char* data, int len){
    NKUserRelationData userRelationsData[NK_MAX_PAYLOAD_ARRAY_SIZE] = {};
    unsigned short userRelationsDataLen = 0;
    if(nk_decode_sync_relations(data, len, SessionManager::RxKey.data(), userRelationsData, &userRelationsDataLen) == 0){
        std::vector<UserRelationInfo> userRelations;
        for(size_t i = 0; i < userRelationsDataLen; i++){
            UserRelationStatus status;
            switch(userRelationsData[i].statusCode){
                case NK_USER_RELATION_FRIEND:
                    status = UserRelationStatus::FRIEND;
                    break;
                case NK_USER_RELATION_BLOCKED:
                    status = UserRelationStatus::BLOCKED;
                    break;
                case NK_USER_RELATION_REMOVED:
                    status = UserRelationStatus::REMOVED;
                    break;
            }
            userRelations.emplace_back(UserRelationInfo{
                .RelationId = userRelationsData[i].relationId,
                .RecipentId = userRelationsData[i].recipentId,
                .StatusCode = status,
                .UpdateTime = std::chrono::system_clock::time_point(std::chrono::seconds(userRelationsData[i].updateTime)),
            });
        }
        UserRelationsManager::LoadUserRelationInfo(userRelations);
    }else{
        ApplyError(NK_OPCODE_SYNC_RELATIONS, NK_ERROR_INVALID_FRAME);
    }
}

void RequestManager::ProcessChannelRequestDMResultRequest(const unsigned char* data, int len){
    unsigned int userId, channelId;
    printf("ProcessChannelRequestDMResultRequest\n");
    fflush(stdout);
    if(nk_decode_channel_request_dm_result(data, len, SessionManager::RxKey.data(), &userId, &channelId) == 0){
        DMChannelInfo info;
        info.ChannelId = channelId;
        info.UserId = userId;
        ChannelsManager::LoadDMInfo(info);
    }else{
        ApplyError(NK_OPCODE_CHANNEL_REQUEST_DM_RESULT, NK_ERROR_INVALID_FRAME);
    }
}

void RequestManager::ProcessChannelRequestRecipentsResultRequest(const unsigned char* data, int len){
    unsigned int channelId;
    unsigned int userIds[NK_MAX_PAYLOAD_ARRAY_SIZE];
    unsigned short userIdsLen;
    if(nk_decode_channel_request_recipents_result(data, len, SessionManager::RxKey.data(), &channelId, userIds, &userIdsLen) == 0){
        std::vector<unsigned int> recipents;
        recipents.resize(userIdsLen);
        memcpy(recipents.data(), userIds, recipents.size() * sizeof(unsigned int));
        ChannelsManager::LoadRecipents(channelId, recipents);
    }else{
        ApplyError(NK_OPCODE_CHANNEL_REQUEST_RECIPENTS_RESULT, NK_ERROR_INVALID_FRAME);
    }
}

void RequestManager::ProcessChannelSubmitKeyResultRequest(const unsigned char* data, int len){
    unsigned int channelId, keyVersion; 
    unsigned char umkEncryptedKey[NK_MAX_ENCRYPTED_KEY_SIZE];
    unsigned short umkKeySize;
    if(nk_decode_channel_submit_key_result(data, len, SessionManager::RxKey.data(), &channelId, &keyVersion, umkEncryptedKey, &umkKeySize) == 0){
        BackupKeyEncryptedChannelKeyInfo keyInfo;
        keyInfo.ChannelId = channelId;
        keyInfo.KeyVersion = keyVersion;
        keyInfo.EncryptedKey.resize(umkKeySize);
        memcpy(keyInfo.EncryptedKey.data(), umkEncryptedKey, umkKeySize);
        ChannelKeysManager::LoadBackupEncryptedKeys(std::vector<BackupKeyEncryptedChannelKeyInfo>{ keyInfo });
    }else{
        ApplyError(NK_OPCODE_CHANNEL_SUBMIT_KEY_RESULT, NK_ERROR_INVALID_FRAME);
    }
}

void RequestManager::ProcessSyncChannelKeysRequest(const unsigned char* data, int len){
    unsigned int channelId;
    unsigned short deviceKeysLen, backupKeysLen;
    NKChannelDeviceKeyData deviceKeys[NK_MAX_PAYLOAD_ARRAY_SIZE];
    NKChannelBackupKeyData backupKeys[NK_MAX_PAYLOAD_ARRAY_SIZE];

    std::vector<DeviceKeyEncryptedChannelKeyInfo> encryptedDevKeys;
    std::vector<BackupKeyEncryptedChannelKeyInfo> encryptedBackupKeys;
    if(nk_decode_sync_channel_keys(data, len, SessionManager::RxKey.data(), &channelId, deviceKeys, &deviceKeysLen, backupKeys, &backupKeysLen) == 0){
        for(int i = 0; i < deviceKeysLen; i++){
            if(deviceKeys[i].targetDeviceId != DevicesManager::DeviceId){
                continue;
            }

            DeviceKeyEncryptedChannelKeyInfo devKeyInfo;
            devKeyInfo.ChannelId = channelId;
            devKeyInfo.KeyVersion = deviceKeys[i].keyVersion;
            devKeyInfo.SenderDeviceId = deviceKeys[i].senderDeviceId;
            devKeyInfo.EncryptedKey.resize(deviceKeys[i].encryptedKeySize);
            memcpy(devKeyInfo.EncryptedKey.data(), deviceKeys[i].encryptedKey, devKeyInfo.EncryptedKey.size());
            encryptedDevKeys.emplace_back(devKeyInfo);
        }
        for(int i = 0; i < backupKeysLen; i++){
            BackupKeyEncryptedChannelKeyInfo backupKeyInfo;
            backupKeyInfo.ChannelId = channelId;
            backupKeyInfo.KeyVersion = backupKeys[i].keyVersion;
            backupKeyInfo.EncryptedKey.resize(backupKeys[i].encryptedKeySize);
            memcpy(backupKeyInfo.EncryptedKey.data(), backupKeys[i].encryptedKey, backupKeyInfo.EncryptedKey.size());
            encryptedBackupKeys.emplace_back(backupKeyInfo);
        }
        
        ChannelKeysManager::LoadDeviceEncryptedKeys(encryptedDevKeys);
        ChannelKeysManager::LoadBackupEncryptedKeys(encryptedBackupKeys);
    }else{
        ApplyError(NK_OPCODE_SYNC_CHANNEL_KEYS, NK_ERROR_INVALID_FRAME);
    }
}

void RequestManager::ProcessChannelMessageDeliverRequest(const unsigned char* data, int len){
    unsigned int channelId;
    NKChannelMessageData message;
    if(nk_decode_channel_message_deliver(data, len, SessionManager::RxKey.data(), &channelId, &message)){
        ChannelMessageInfo messageInfo;
        messageInfo.ChannelId = channelId;
        messageInfo.KeyVersion = message.keyVersion;
        messageInfo.MessageId = message.messageId;
        messageInfo.SenderDeviceId = message.senderDeviceId;
        messageInfo.SenderId = message.senderId;
        messageInfo.IsDecrypted = false;
        messageInfo.Time = std::chrono::system_clock::time_point(std::chrono::seconds(message.updateTime));
        messageInfo.Ciphertext.resize(message.payloadSize);
        memcpy(messageInfo.Ciphertext.data(), message.payload, messageInfo.Ciphertext.size());
        ChannelMessagesManager::LoadMessages(std::vector<ChannelMessageInfo>{ messageInfo });
    }
}

void RequestManager::ProcessSyncChannelHistoryRequest(const unsigned char* data, int len){
    unsigned int channelId;
    NKChannelMessageData messages[NK_MAX_PAYLOAD_ARRAY_SIZE];
    unsigned short messagesLen;
    if(nk_decode_sync_channel_history(data, len, SessionManager::RxKey.data(), &channelId, messages, &messagesLen) != 0){
        std::vector<ChannelMessageInfo> messageInfo;
        for(int i = 0; i < messagesLen; i++){
            ChannelMessageInfo message;
            message.ChannelId = channelId;
            message.KeyVersion = messages[i].keyVersion;
            message.MessageId = messages[i].messageId;
            message.SenderDeviceId = messages[i].senderDeviceId;
            message.SenderId = messages[i].senderId;
            message.IsDecrypted = false;
            message.Time = std::chrono::system_clock::time_point(std::chrono::seconds(messages[i].updateTime));
            message.Ciphertext.resize(messages[i].payloadSize);
            messageInfo.emplace_back(message);
        }
        ChannelMessagesManager::LoadMessages(messageInfo);
    }else{
        ApplyError(NK_OPCODE_SYNC_CHANNEL_HISTORY, NK_ERROR_INVALID_FRAME);
    }
}

void RequestManager::ProcessChannelTypingBroadcastRequest(const unsigned char* data, int len){
    unsigned int userId, channelId, typingStatus;
    if(nk_decode_channel_typing_broadcast(data, len, SessionManager::RxKey.data(), &userId, &channelId, &typingStatus) == 0){
        if(typingStatus == NK_CHANNEL_TYPING_START){
            ChannelsManager::StartTyping(channelId, userId);
        }else if(typingStatus == NK_CHANNEL_TYPING_STOP){
            ChannelsManager::StopTyping(channelId, userId);
        }
    }else{
        ApplyError(NK_OPCODE_CHANNEL_TYPING_BROADCAST, NK_ERROR_INVALID_FRAME);
    }
}

void RequestManager::ApplyOk(unsigned char opcode){
    auto it = _okRequestSubscribers.find(opcode);
    if (it != _okRequestSubscribers.end() && it->second) {
        it->second();
    }
}

void RequestManager::ApplyError(unsigned char opcode, int errNo){
    printf("Error opcode %x, errNo %x", opcode, errNo);
    fflush(stdout);
    auto it = _errorRequestSubscribers.find(opcode);
    if (it != _errorRequestSubscribers.end() && it->second) {
        it->second(errNo);
    }
}
