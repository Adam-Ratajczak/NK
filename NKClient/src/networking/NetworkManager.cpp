#include "networking/NetworkManager.hpp"
#include "networking/SessionManager.hpp"
#include "networking/UserManager.hpp"
#include "networking/DevicesManager.hpp"
#include "forms/RegistrationForm.hpp"
#include "forms/LoginForm.hpp"
#include "nk_protocol.h"
#include <emscripten.h>

EM_JS(void, nk_ws_send, (const unsigned char* data, size_t len), {
    if (!Module.ws) {
        console.error("WebSocket not initialized");
        return;
    }

    const bytes = new Uint8Array(Module.HEAPU8.buffer, data, len);
    Module.ws.send(bytes);
});

unsigned char NetworkManager::_lastOpCode = 0;
void NetworkManager::HandshakeServer(unsigned char* publicKey)
{
    if (!publicKey)
        return;

    unsigned int frameSize = 0;
    unsigned char* frame = nk_encode_hello(publicKey, &frameSize);
    if (!frame)
        return;

    Send(frame, (size_t)frameSize);

    free(frame);
}

void NetworkManager::Register(const std::string& login, const std::string& passwd){
    unsigned int frameSize = 0;
    unsigned char* frame = nk_encode_register(login.c_str(), (unsigned short)login.size(), 
                                              passwd.c_str(), (unsigned short)passwd.size(), 
                                              SessionManager::TxKey.data(), &frameSize);
    if (!frame)
        return;

    Send(frame, (size_t)frameSize);

    free(frame);
}

void NetworkManager::RequestSalt(const std::string& login){
    unsigned int frameSize = 0;
    unsigned char* frame = nk_encode_request_salt(login.c_str(), (unsigned short)login.size(),  
                                                  SessionManager::TxKey.data(), &frameSize);
    if (!frame)
        return;

    Send(frame, (size_t)frameSize);

    free(frame);
}

void NetworkManager::Login(const unsigned int deviceId, const std::string& login, const std::string& passwd, const unsigned char* salt){
    unsigned int frameSize = 0;
    unsigned char* frame = nk_encode_login(login.c_str(), (unsigned short)login.size(),
                                           passwd.c_str(), (unsigned short)passwd.size(), 
                                           salt, deviceId, SessionManager::TxKey.data(), &frameSize);
    if (!frame)
        return;

    Send(frame, (size_t)frameSize);

    free(frame);
}

void NetworkManager::ChangeUsername(const std::string& username){
    unsigned short bufferSize = 0;
    unsigned int frameSize = 0;
    unsigned char* buffer = nk_encode_update_user_data_change_username_payload(username.c_str(), username.size(), &bufferSize);
    unsigned char* frame = nk_encode_update_user_data(buffer, bufferSize, SessionManager::TxKey.data(), &frameSize);
    if (!frame)
        return;

    Send(frame, (size_t)frameSize);

    free(buffer);
    free(frame);
}

void NetworkManager::ChangePassword(const std::string& password){
    unsigned short bufferSize = 0;
    unsigned int frameSize = 0;
    unsigned char* buffer = nk_encode_update_user_data_change_password_payload(password.c_str(), password.size(), &bufferSize);
    unsigned char* frame = nk_encode_update_user_data(buffer, bufferSize, SessionManager::TxKey.data(), &frameSize);
    if (!frame)
        return;

    Send(frame, (size_t)frameSize);

    free(buffer);
    free(frame);
}

void NetworkManager::RandomizeUserTag(){
    unsigned short bufferSize = 0;
    unsigned int frameSize = 0;
    unsigned char* buffer = nk_encode_update_user_data_change_tag_payload(&bufferSize);
    unsigned char* frame = nk_encode_update_user_data(buffer, bufferSize, SessionManager::TxKey.data(), &frameSize);
    if (!frame)
        return;

    Send(frame, (size_t)frameSize);

    free(buffer);
    free(frame);
}

void NetworkManager::Logout(){
    unsigned int frameSize = 0;
    unsigned char* frame = nk_encode_logout(SessionManager::TxKey.data(), &frameSize);
    if (!frame)
        return;

    Send(frame, (size_t)frameSize);

    free(frame);
}

void NetworkManager::Unregister(){
    unsigned int frameSize = 0;
    unsigned char* frame = nk_encode_unregister(SessionManager::TxKey.data(), &frameSize);
    if (!frame)
        return;

    Send(frame, (size_t)frameSize);

    free(frame);
}

void NetworkManager::RegisterNewDeviceKeys(const unsigned int deviceId, const unsigned char* x25519_pub, const unsigned char* ed25519_pub){
    unsigned int frameSize = 0;
    unsigned char* frame = nk_encode_register_new_device_keys(deviceId, x25519_pub, ed25519_pub, SessionManager::TxKey.data(), &frameSize);
    if (!frame)
        return;

    Send(frame, (size_t)frameSize);

    free(frame);
}

void NetworkManager::RequestDevices(const std::vector<unsigned int>& deviceIds){
    unsigned int frameSize = 0;
    unsigned char* frame = nk_encode_request_devices(deviceIds.data(), deviceIds.size(), SessionManager::TxKey.data(), &frameSize);
    if (!frame)
        return;

    Send(frame, (size_t)frameSize);

    free(frame);
}

void NetworkManager::RequestUserDevices(const std::vector<unsigned int>& userIds){
    printf("User IDs:\n");
    fflush(stdout);
    for(auto id : userIds){
        printf("Sending %d\n", id);
        fflush(stdout);
    }
    unsigned int frameSize = 0;
    unsigned char* frame = nk_encode_request_user_devices(userIds.data(), userIds.size(), SessionManager::TxKey.data(), &frameSize);
    if (!frame)
        return;

    Send(frame, (size_t)frameSize);

    free(frame);
}

void NetworkManager::SendFriendRequest(const std::string& uname, const unsigned int tag){
    unsigned int frameSize = 0;
    unsigned char* frame = nk_encode_friend_request(uname.c_str(), (unsigned short)uname.size(),
                                                    tag, SessionManager::TxKey.data(), &frameSize);
    if (!frame)
        return;

    Send(frame, (size_t)frameSize);

    free(frame);
}

void NetworkManager::AcceptFriendRequest(const unsigned int requestId){
    unsigned int frameSize = 0;
    unsigned char* frame = nk_encode_friend_request_update_status(requestId, NK_FRIEND_REQUEST_ACCEPTED, SessionManager::TxKey.data(), &frameSize);
    if (!frame)
        return;

    Send(frame, (size_t)frameSize);

    free(frame);
}

void NetworkManager::DenyFriendRequest(const unsigned int requestId){
    unsigned int frameSize = 0;
    unsigned char* frame = nk_encode_friend_request_update_status(requestId, NK_FRIEND_REQUEST_DENIED, SessionManager::TxKey.data(), &frameSize);
    if (!frame)
        return;

    Send(frame, (size_t)frameSize);

    free(frame);
}

void NetworkManager::BlockUser(const unsigned int userId){
    unsigned int frameSize = 0;
    unsigned char* frame = nk_encode_user_relation_block(userId, SessionManager::TxKey.data(), &frameSize);
    if (!frame)
        return;

    Send(frame, (size_t)frameSize);

    free(frame);
}

void NetworkManager::ResetRelation(const unsigned int userId){
    unsigned int frameSize = 0;
    unsigned char* frame = nk_encode_user_relation_reset(userId, SessionManager::TxKey.data(), &frameSize);
    if (!frame)
        return;

    Send(frame, (size_t)frameSize);

    free(frame);
}

void NetworkManager::RequestChannelRecipents(const unsigned int channelId){
    unsigned int frameSize = 0;
    unsigned char* frame = nk_encode_channel_request_recipents(channelId, SessionManager::TxKey.data(), &frameSize);
    if (!frame)
        return;

    Send(frame, (size_t)frameSize);

    free(frame);
}

void NetworkManager::RequestDM(const unsigned int userId){
    unsigned int frameSize = 0;
    unsigned char* frame = nk_encode_channel_request_dm(userId, SessionManager::TxKey.data(), &frameSize);
    if (!frame)
        return;

    Send(frame, (size_t)frameSize);

    free(frame);
}

void NetworkManager::RequestChannelKeys(const unsigned int channelId){
    unsigned int frameSize = 0;
    unsigned char* frame = nk_encode_sync_channel_keys_request(channelId, SessionManager::TxKey.data(), &frameSize);
    if (!frame)
        return;

    Send(frame, (size_t)frameSize);

    free(frame);
}

void NetworkManager::GenerateAndSendChannelKey(const unsigned int channelId, const std::vector<DeviceConn>& connections){
    NKChannelSubmitDeviceInput devices[NK_MAX_PAYLOAD_ARRAY_SIZE];
    unsigned short index = 0;
    for(auto conn : connections){
        devices[index].targetDeviceId = conn.DeviceId;
        memcpy(devices[index].sharedSecret, conn.SharedSecret.data(), conn.SharedSecret.size());
        index++;
    }

    unsigned int frameSize = 0;
    unsigned char* frame = nk_encode_channel_submit_key(channelId, devices, index, UserManager::UMK.data(), DevicesManager::DeviceEd25519_secret.data(), 
                                                        SessionManager::TxKey.data(), &frameSize);
    if (!frame)
        return;

    Send(frame, (size_t)frameSize);

    free(frame);
}

void NetworkManager::SendMessage(const unsigned int channelId, const std::string& payload, const ChannelKeyInfo& keyInfo){
    unsigned int frameSize = 0;
    unsigned char* frame = nk_encode_channel_message_send(channelId, keyInfo.KeyVersion, (unsigned char*)payload.data(), payload.size(), keyInfo.Key.data(), 
                                                          DevicesManager::DeviceEd25519_secret.data(), SessionManager::TxKey.data(), &frameSize);
    if (!frame)
        return;

    Send(frame, (size_t)frameSize);

    free(frame);
}

void NetworkManager::RequestChannelHistory(const unsigned int channelId, const unsigned int fromMessage, const unsigned int limit){
    unsigned int frameSize = 0;
    unsigned char* frame = nk_encode_sync_channel_history_request(channelId, fromMessage, limit, SessionManager::TxKey.data(), &frameSize);
    if (!frame)
        return;

    Send(frame, (size_t)frameSize);

    free(frame);
}

void NetworkManager::StartTyping(const unsigned int channelId){
    unsigned int frameSize = 0;
    unsigned char* frame = nk_encode_channel_typing_update(channelId, NK_CHANNEL_TYPING_START, SessionManager::TxKey.data(), &frameSize);
    if (!frame)
        return;

    Send(frame, (size_t)frameSize);

    free(frame);
}

void NetworkManager::StopTyping(const unsigned int channelId){
    unsigned int frameSize = 0;
    unsigned char* frame = nk_encode_channel_typing_update(channelId, NK_CHANNEL_TYPING_STOP, SessionManager::TxKey.data(), &frameSize);
    if (!frame)
        return;

    Send(frame, (size_t)frameSize);

    free(frame);
}

void NetworkManager::Send(unsigned char* payload, size_t n)
{
    if (!payload || n == 0)
        return;

    nk_ws_send(payload, n);
    _lastOpCode = payload[0];
}
