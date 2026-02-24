#pragma once
#include "../structs.hpp"

class ChannelForm{
public:
    static DMChannelInfo ChannelInfo;
    static void Create();
    static void Destroy();
    static void Open();
    static void Render();

private:
    static void AddRecipent(const UserInfo& user);
    static void AddChannelKey(const ChannelKeyInfo& channelKey);
    static void AddMessage(const ChannelMessageInfo& message);

    static char _inputBuf[512];
    static float _lastTypingTime;
    static bool _isTyping;
    static UserInfo _recipent;
    static ChannelKeyInfo _channelKey;
    static std::unordered_map<unsigned int, ChannelMessageInfo> _messages;
};
