#pragma once
#include "../structs.hpp"
#include <set>

class ChannelsManager{
public:
    static void Register();
    static void LoadDMInfo(const DMChannelInfo& dmInfo);
    static void LoadRecipents(const unsigned int channelId, const std::vector<unsigned int>& recipents);
    static void StartTyping(const unsigned int channelId, unsigned int userId);
    static void StopTyping(const unsigned int channelId, unsigned int userId);

    static bool GetDMInfo(unsigned int userId, DMChannelInfo& dminfo);
    static bool GetRecipents(unsigned int channelId, RecipentsInfo& recipents);
    static bool GetTyping(unsigned int channelId, TypingInfo& typing);

    static void SubscribeDM(DMChannelInfoDelegate delegate);
    static void SubscribeTyping(TypingInfoDelegate delegate);
    static void SubscribeRecipents(RecipentsInfoDelegate delegate);
    
    static void SyncWithChannel(unsigned int channelId);
private:
    static void FetchDeviceInfoForRecipents(const unsigned int channelId, const std::vector<unsigned int>& recipents);

    static void NotifyDM(const DMChannelInfo& dmChannel);
    static void NotifyRecipents(const RecipentsInfo& recipents);
    static void NotifyTyping(const TypingInfo& typing);

    static void GetDeviceConnFromRecipents(const RecipentsInfo& recipents);
    static void AddDeviceConn(const DeviceConn& conn);
    static void FetchingKeysError(unsigned int errNo);
    static void FetchingKeysSuccess(const ChannelKeyInfo& keyInfo);

    static std::vector<DMChannelInfoDelegate> _subscribersDM;
    static std::vector<TypingInfoDelegate> _subscribersTyping;
    static std::vector<RecipentsInfoDelegate> _subscribersRecipents;
    static std::map<unsigned int, DMChannelInfo> _channelsDM;
    static std::map<unsigned int, TypingInfo> _typing;
    static std::map<unsigned int, RecipentsInfo> _recipents;

    static unsigned int _channelSyncing;
    static RecipentsInfo _recipentsSyncing;
    static std::vector<unsigned int> _usersWithoutDeviceConnectionsSyncing;
    static std::vector<DeviceConn> _deviceConnectionsSyncing;
    static bool _isGenerating;
};
