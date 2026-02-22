#include "networking/ChannelMessagesManager.hpp"
#include "networking/ChannelKeysManager.hpp"
#include "networking/DevicesManager.hpp"
#include "nk_protocol.h"

std::map<unsigned int, ChannelMessageInfo> ChannelMessagesManager::_messages;
std::vector<ChannelMessageInfoDelegate> ChannelMessagesManager::_subscribers;

void ChannelMessagesManager::Register(){
    ChannelKeysManager::Subscribe(&ChannelMessagesManager::OnKeysUpdated);
}
void ChannelMessagesManager::Subscribe(ChannelMessageInfoDelegate func){
    _subscribers.push_back(func);
}

void ChannelMessagesManager::LoadMessages(const std::vector<ChannelMessageInfo>& messages){
    for (auto msg : messages){
        if (!VerifyMessage(msg)) {
            continue;
        }
        TryDecrypt(msg);

        _messages[msg.MessageId] = msg;
        Notify(msg);
    }
}

void ChannelMessagesManager::TryDecrypt(ChannelMessageInfo& msg){
    if (msg.IsDecrypted)
        return;

    ChannelKeyInfo key;

    if (!ChannelKeysManager::GetChannelKey(msg.ChannelId, msg.KeyVersion, key))
        return;

    TryDecryptWithKey(msg, key);
}

void ChannelMessagesManager::TryDecryptWithKey(ChannelMessageInfo& msg, const ChannelKeyInfo& key){
    std::vector<unsigned char> plain(msg.Ciphertext.size());
    unsigned int outSize = 0;

    if (nk_decrypt_payload(key.Key.data(), msg.Ciphertext.data(), (unsigned int)msg.Ciphertext.size(), plain.data(), &outSize) != 0)
    {
        return;
    }

    plain.resize(outSize);

    msg.Plaintext = std::move(plain);
    msg.IsDecrypted = true;
}

void ChannelMessagesManager::OnKeysUpdated(const ChannelKeyInfo& key){
    for (auto& [_, msg] : _messages){
        if (!msg.IsDecrypted && msg.ChannelId == key.ChannelId && msg.KeyVersion == key.KeyVersion){
            TryDecryptWithKey(msg, key);

            if (msg.IsDecrypted)
                Notify(msg);
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

bool ChannelMessagesManager::VerifyMessage(ChannelMessageInfo& msg) {
    DeviceConn conn;

    if (!DevicesManager::GetConnection(msg.SenderDeviceId, conn)) {
        return false;
    }
    if(msg.SenderId != conn.OwnerId){
        return false;
    }

    if (msg.Ciphertext.size() < NK_ED25519_SIG_SIZE)
        return false;

    const unsigned char* sig = msg.Ciphertext.data();
    const unsigned char* payload = msg.Ciphertext.data() + NK_ED25519_SIG_SIZE;
    unsigned int payloadLen = (unsigned int)msg.Ciphertext.size() - NK_ED25519_SIG_SIZE;

    if (nk_verify_signature(conn.Ed25519_pub.data(), payload, payloadLen, sig) != 0)
    {
        return false;
    }

    return true;
}
