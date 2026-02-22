#pragma once
#include "../structs.hpp"

class ChannelMessagesManager {
public:
    static void Register();
    static void Subscribe(ChannelMessageInfoDelegate func);
    static void LoadMessages(const std::vector<ChannelMessageInfo>& messages);
    static bool GetMessage(unsigned int messageId, ChannelMessageInfo& out);
    static void Reset();
private:
    static void TryDecrypt(ChannelMessageInfo& msg);
    static void TryDecryptWithKey(ChannelMessageInfo& msg, const ChannelKeyInfo& key);
    static void OnKeysUpdated(const ChannelKeyInfo& key);
    static void Notify(const ChannelMessageInfo& msg);
    static bool VerifyMessage(ChannelMessageInfo& msg);
    
    static std::map<unsigned int, ChannelMessageInfo> _messages;
    static std::vector<ChannelMessageInfoDelegate> _subscribers;
};
