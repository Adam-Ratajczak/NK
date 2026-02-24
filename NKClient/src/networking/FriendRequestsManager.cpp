#include "networking/FriendRequestsManager.hpp"
#include "networking/NetworkManager.hpp"
#include <JsLogger.hpp>

std::unordered_map<unsigned int, FriendRequestInfo> FriendRequestsManager::_friendRequests;
std::vector<FriendRequestInfoDelegate> FriendRequestsManager::_subscribers;
void FriendRequestsManager::LoadFriendRequestInfo(const std::vector<FriendRequestInfo>& friendRequestsInfo){
    for(const auto& friendRequest : friendRequestsInfo){
        _friendRequests[friendRequest.RequestId] = friendRequest;
        Notify(friendRequest);
    }
}

bool FriendRequestsManager::GetFriendRequestInfo(int requestID, FriendRequestInfo& friendRequestInfo){
    auto it = _friendRequests.find(requestID);
    if(it != _friendRequests.end()){
        friendRequestInfo = it->second;
        return true;
    }
    return false;
}

void FriendRequestsManager::Subscribe(FriendRequestInfoDelegate func){
    if(!func){
        return;
    }

    _subscribers.emplace_back(func);
}

void FriendRequestsManager::Unsubscribe(FriendRequestInfoDelegate func){
}

void FriendRequestsManager::Notify(const FriendRequestInfo& friendRequest){
    for(auto& delegate : _subscribers){
        delegate(friendRequest);
    }
}

