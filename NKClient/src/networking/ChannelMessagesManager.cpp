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
        printf("Message ID: %d\n", msg.MessageId);
        fflush(stdout);
        if (!VerifyMessage(msg)) {
            printf("message verification failed\n");
            fflush(stdout);
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
            if (!VerifyMessage(msg)) {
                printf("message verification failed\n");
                fflush(stdout);
                continue;
            }
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
    return true;
    DeviceConn conn;

    if (!DevicesManager::GetConnection(msg.SenderDeviceId, conn)) {
        printf("No valid connection\n");
        fflush(stdout);
        return false;
    }
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
