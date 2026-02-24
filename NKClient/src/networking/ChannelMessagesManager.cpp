#include "networking/ChannelMessagesManager.hpp"
#include "networking/ChannelKeysManager.hpp"
#include "networking/NetworkManager.hpp"
#include "networking/DevicesManager.hpp"
#include "nk_protocol.h"

std::vector<ChannelEncryptedMessageInfo> ChannelMessagesManager::_encryptedMessages;
std::unordered_map<unsigned int, ChannelMessageInfo> ChannelMessagesManager::_messages;
std::vector<ChannelMessageInfoDelegate> ChannelMessagesManager::_subscribers;

void ChannelMessagesManager::Register(){
    ChannelKeysManager::Subscribe(&ChannelMessagesManager::OnKeysUpdated);
    DevicesManager::Subscribe(&ChannelMessagesManager::OnDevicesUpdated);
}
void ChannelMessagesManager::Subscribe(ChannelMessageInfoDelegate func){
    _subscribers.push_back(func);
}

void ChannelMessagesManager::LoadEncryptedMessages(const std::vector<ChannelEncryptedMessageInfo>& messages){
    printf("Messages: %d\n", messages.size());
    fflush(stdout);
    _encryptedMessages.insert(_encryptedMessages.end(), messages.begin(), messages.end());
    DecryptAllPossibleMessages();
}

void ChannelMessagesManager::DecryptAllPossibleMessages(){
    printf("Decrypting messages\n");
    fflush(stdout);
    std::unordered_map<unsigned int, DeviceConn> deviceConnections;
    std::vector<unsigned int> missingDeviceIds;
    for (const auto& msg : _encryptedMessages){
        if(deviceConnections.find(msg.SenderDeviceId) != deviceConnections.end()){
            continue;
        }
        DeviceConn conn;
        if(DevicesManager::GetConnection(msg.SenderDeviceId, conn)){
            deviceConnections[msg.SenderDeviceId] = conn;
        }else{
            auto it = std::find(missingDeviceIds.begin(), missingDeviceIds.end(), msg.SenderDeviceId);
            if(it == missingDeviceIds.end()){
                missingDeviceIds.emplace_back(msg.SenderDeviceId);
            }
        }
    }

    for (auto itEm = _encryptedMessages.begin(); itEm != _encryptedMessages.end();){
        printf("Decrypting messages loop\n");
        fflush(stdout);
        auto itDev = deviceConnections.find(itEm->SenderDeviceId);
        if(itDev == deviceConnections.end()){
            itEm++;
            continue;
        }

        ChannelKeyInfo key;
        if (!ChannelKeysManager::GetChannelKey(itEm->ChannelId, itEm->KeyVersion, key)){
            itEm++;
            continue;
        }
        
        if (!VerifyMessage(*itEm, itDev->second)) {
            itEm++;
            printf("message verification failed\n");
            fflush(stdout);
            continue;
        }

        ChannelMessageInfo msg;
        if(TryDecryptWithKey(*itEm, key, msg)){
            _messages[msg.MessageId] = msg;
            itEm = _encryptedMessages.erase(itEm);
            Notify(msg);
        }else{
            itEm++;
        }
    }

    if(!missingDeviceIds.empty()){
        NetworkManager::RequestDevices(missingDeviceIds);
    }
}

bool ChannelMessagesManager::TryDecryptWithKey(const ChannelEncryptedMessageInfo& enMsg, const ChannelKeyInfo& key, ChannelMessageInfo& msg){
    std::vector<unsigned char> plain(enMsg.Ciphertext.size());
    unsigned int outSize = 0;

    if (nk_decrypt_payload(key.Key.data(), enMsg.Ciphertext.data(), (unsigned int)enMsg.Ciphertext.size(), plain.data(), &outSize) != 0)
    {
        return false;
    }

    plain.resize(outSize);

    msg.ChannelId = enMsg.ChannelId;
    msg.MessageId = enMsg.MessageId;
    msg.SenderId = enMsg.SenderId;
    msg.Time = enMsg.Time;
    msg.Plaintext = std::move(plain);

    return true;
}

void ChannelMessagesManager::OnKeysUpdated(const ChannelKeyInfo& key){
    for (auto itEm = _encryptedMessages.begin(); itEm != _encryptedMessages.end();){
        printf("Decrypting messages by key loop\n");
        fflush(stdout);
        if (itEm->ChannelId == key.ChannelId && itEm->KeyVersion == key.KeyVersion){
            DeviceConn conn;
            if(!DevicesManager::GetConnection(itEm->SenderDeviceId, conn)){
                itEm++;
                continue;
            }
            if (!VerifyMessage(*itEm, conn)) {
                itEm++;
                printf("message verification failed\n");
                fflush(stdout);
                continue;
            }

            ChannelMessageInfo msg;
            if(TryDecryptWithKey(*itEm, key, msg)){
                _messages[msg.MessageId] = msg;
                itEm = _encryptedMessages.erase(itEm);
                Notify(msg);
            }else{
                itEm++;
            }
        }else{
            itEm++;
        }
    }
}

void ChannelMessagesManager::OnDevicesUpdated(const DeviceConn& conn){
    for (auto itEm = _encryptedMessages.begin(); itEm != _encryptedMessages.end();){
        printf("Decrypting messages by device loop\n");
        fflush(stdout);
        if (itEm->SenderDeviceId == conn.DeviceId){
            if (!VerifyMessage(*itEm, conn)) {
                itEm++;
                printf("message verification failed\n");
                fflush(stdout);
                continue;
            }
            
            ChannelKeyInfo key;
            if (!ChannelKeysManager::GetChannelKey(itEm->ChannelId, itEm->KeyVersion, key)){
                itEm++;
                continue;
            }

            ChannelMessageInfo msg;
            if(TryDecryptWithKey(*itEm, key, msg)){
                _messages[msg.MessageId] = msg;
                itEm = _encryptedMessages.erase(itEm);
                Notify(msg);
            }else{
                itEm++;
            }
        }else{
            itEm++;
        }
    }
}

bool ChannelMessagesManager::GetMessage(unsigned int messageId, ChannelMessageInfo& out){
    auto it = _messages.find(messageId);
    if (it == _messages.end())
        return false;

    out = it->second;
    return true;
}

void ChannelMessagesManager::Notify(const ChannelMessageInfo& msg){
    for (auto& s : _subscribers)
        s(msg);
}

void ChannelMessagesManager::Reset(){
    _messages.clear();
    _subscribers.clear();
}

bool ChannelMessagesManager::VerifyMessage(const ChannelEncryptedMessageInfo& msg, const DeviceConn& conn) {
    if(msg.SenderId != conn.OwnerId){
        printf("Invalid ownership\n");
        fflush(stdout);
        return false;
    }

    if (msg.Signature.size() != NK_ED25519_SIG_SIZE){
        printf("Invalid sig size: %d\n", msg.Ciphertext.size());
        fflush(stdout);
        return false;
    }

    if (nk_verify_signature(conn.Ed25519_pub.data(), msg.Ciphertext.data(), msg.Ciphertext.size(), msg.Signature.data()) != 0)
    {
        printf("Sig verify failed: %x %x %x %x\n", msg.Signature[0], msg.Signature[1], msg.Signature[2], msg.Signature[3]);
        fflush(stdout);
        return false;
    }

    return true;
}
