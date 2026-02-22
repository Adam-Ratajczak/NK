#include "networking/ChannelsManager.hpp"
#include "networking/NetworkManager.hpp"
#include "networking/DevicesManager.hpp"
#include "networking/ChannelKeysManager.hpp"
#include "networking/RequestManager.hpp"
#include "nk_protocol.h"

std::vector<DMChannelInfoDelegate> ChannelsManager::_subscribersDM;
std::vector<TypingInfoDelegate> ChannelsManager::_subscribersTyping;
std::vector<RecipentsInfoDelegate> ChannelsManager::_subscribersRecipents;
std::map<unsigned int, DMChannelInfo> ChannelsManager::_channelsDM;
std::map<unsigned int, TypingInfo> ChannelsManager::_typing;
std::map<unsigned int, RecipentsInfo> ChannelsManager::_recipents;
unsigned int ChannelsManager::_channelSyncing;
RecipentsInfo ChannelsManager::_recipentsSyncing;
std::vector<unsigned int> ChannelsManager::_usersWithoutDeviceConnectionsSyncing;
std::vector<DeviceConn> ChannelsManager::_deviceConnectionsSyncing;

void ChannelsManager::Register(){
    SubscribeRecipents(&ChannelsManager::GetDeviceConnFromRecipents);
    DevicesManager::Subscribe(&ChannelsManager::AddDeviceConn);
    RequestManager::SubscribeErrorRequest(NK_OPCODE_SYNC_CHANNEL_KEYS, &ChannelsManager::FetchingKeysError);
    ChannelKeysManager::Subscribe(&ChannelsManager::FetchingKeysSuccess);
}

void ChannelsManager::LoadDMInfo(const DMChannelInfo& dmInfo){
    _channelsDM[dmInfo.UserId] = dmInfo;
    printf("ChannelsManager::LoadDMInfo\n");
    fflush(stdout);
    NotifyDM(dmInfo);
}

void ChannelsManager::LoadRecipents(const unsigned int channelId, const std::vector<unsigned int>& recipents){
    RecipentsInfo recipentsInfo;
    recipentsInfo.ChannelId = channelId;
    recipentsInfo.Recipents = recipents;

    _recipents[channelId] = recipentsInfo;
    NotifyRecipents(recipentsInfo);
}

void ChannelsManager::StartTyping(const unsigned int channelId, unsigned int userId){
    auto it = _typing.find(channelId);
    if(it != _typing.end()){
        it->second.Typers.emplace_back(userId);
        NotifyTyping(it->second);
    }else{
        TypingInfo typing;
        typing.ChannelId = channelId;
        typing.Typers.emplace_back(userId);
        _typing[channelId] = typing;
        NotifyTyping(typing);
    }
}

void ChannelsManager::StopTyping(const unsigned int channelId, unsigned int userId){
    auto it = _typing.find(channelId);
    if(it != _typing.end()){
        auto userIdIt = std::find(it->second.Typers.begin(), it->second.Typers.end(), userId);
        if(userIdIt != it->second.Typers.end()){
            it->second.Typers.erase(userIdIt);
            NotifyTyping(it->second);
        }
    }
}

bool ChannelsManager::GetDMInfo(unsigned int userId, DMChannelInfo& dminfo){
    auto it = _channelsDM.find(userId);
    if(it == _channelsDM.end()){
        NetworkManager::RequestDM(userId);
        return false;
    }
    
    dminfo = it->second;
    return true;
}

bool ChannelsManager::GetRecipents(unsigned int channelId, RecipentsInfo& recipents){
    auto it = _recipents.find(channelId);
    if(it == _recipents.end()){
        NetworkManager::RequestChannelRecipents(channelId);
        return false;
    }
    
    recipents = it->second;
    return true;
}

bool ChannelsManager::GetTyping(unsigned int channelId, TypingInfo& typing){
    auto it = _typing.find(channelId);
    if(it == _typing.end()){
        return false;
    }

    typing = it->second;
    return true;
}

void ChannelsManager::SubscribeDM(DMChannelInfoDelegate delegate){
    _subscribersDM.emplace_back(delegate);
}

void ChannelsManager::SubscribeTyping(TypingInfoDelegate delegate){
    _subscribersTyping.emplace_back(delegate);
}

void ChannelsManager::SubscribeRecipents(RecipentsInfoDelegate delegate){
    _subscribersRecipents.emplace_back(delegate);
}

void ChannelsManager::SyncWithChannel(unsigned int channelId){
    if(channelId == 0){
        return;
    }

    ChannelKeyInfo keyInfo;
    if(ChannelKeysManager::GetActiveChannelKey(channelId, keyInfo)){
        return;
    }

    _channelSyncing = channelId;
    
    NetworkManager::RequestChannelKeys(_channelSyncing);
}

void ChannelsManager::FetchingKeysSuccess(const ChannelKeyInfo& keyInfo){
    if(keyInfo.ChannelId == _channelSyncing){
        _channelSyncing = 0;
        _recipentsSyncing = RecipentsInfo{};
        _deviceConnectionsSyncing.clear();
    }
}

void ChannelsManager::FetchingKeysError(unsigned int errNo){
    RecipentsInfo recipents;
    if(!GetRecipents(_channelSyncing, recipents)){
        return;
    }
    GetDeviceConnFromRecipents(recipents);
}

void ChannelsManager::GetDeviceConnFromRecipents(const RecipentsInfo& recipents){
    _recipentsSyncing = recipents;
    _usersWithoutDeviceConnectionsSyncing = _recipentsSyncing.Recipents;

    for(auto userId : _usersWithoutDeviceConnectionsSyncing){
        std::vector<DeviceConn> userConnections;
        if(DevicesManager::GetUserConnections(userId, userConnections)){
            for(const auto& conn : userConnections){
                AddDeviceConn(conn);
            }
        }
    }

    if(!_usersWithoutDeviceConnectionsSyncing.empty()){
        NetworkManager::RequestUserDevices(_usersWithoutDeviceConnectionsSyncing);
    }
}

void ChannelsManager::AddDeviceConn(const DeviceConn& conn){
    _deviceConnectionsSyncing.emplace_back(conn);
    auto it = std::find(_usersWithoutDeviceConnectionsSyncing.begin(), _usersWithoutDeviceConnectionsSyncing.end(), conn.OwnerId);
    if(it != _usersWithoutDeviceConnectionsSyncing.end()){
        _usersWithoutDeviceConnectionsSyncing.erase(it);
    }

    if(_usersWithoutDeviceConnectionsSyncing.empty()){
        NetworkManager::GenerateAndSendChannelKey(_channelSyncing, _deviceConnectionsSyncing);
    }
}

void ChannelsManager::NotifyDM(const DMChannelInfo& dmChannel){
    for(auto delegate : _subscribersDM){
        delegate(dmChannel);
    }
}

void ChannelsManager::NotifyRecipents(const RecipentsInfo& recipents){
    for(auto delegate : _subscribersRecipents){
        delegate(recipents);
    }
}

void ChannelsManager::NotifyTyping(const TypingInfo& typing){
    for(auto delegate : _subscribersTyping){
        delegate(typing);
    }
}
