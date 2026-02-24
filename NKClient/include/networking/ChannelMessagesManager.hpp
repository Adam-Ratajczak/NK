#pragma once
#include "../structs.hpp"

class ChannelMessagesManager {
public:
    static void Register();
    static void Subscribe(ChannelMessageInfoDelegate func);
    static void LoadEncryptedMessages(const std::vector<ChannelEncryptedMessageInfo>& messages);
    static bool GetMessage(unsigned int messageId, ChannelMessageInfo& out);
    static void Reset();
private:
    static void DecryptAllPossibleMessages();

    static bool TryDecryptWithKey(const ChannelEncryptedMessageInfo& enMsg, const ChannelKeyInfo& key, ChannelMessageInfo& msg);
    static bool VerifyMessage(const ChannelEncryptedMessageInfo& msg, const DeviceConn& conn);
    
    static void OnKeysUpdated(const ChannelKeyInfo& key);
    static void OnDevicesUpdated(const DeviceConn& conn);
    static void Notify(const ChannelMessageInfo& msg);
    
    static std::vector<ChannelEncryptedMessageInfo> _encryptedMessages;
    static std::unordered_map<unsigned int, ChannelMessageInfo> _messages;
    static std::vector<ChannelMessageInfoDelegate> _subscribers;
};
