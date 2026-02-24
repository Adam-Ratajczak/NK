#pragma once
#include <unordered_map>
#include "../structs.hpp"

class FriendRequestsManager{
public:
    static void Subscribe(FriendRequestInfoDelegate func);
    static void Unsubscribe(FriendRequestInfoDelegate func);

    static void LoadFriendRequestInfo(const std::vector<FriendRequestInfo>& friendRequestsInfo);

    static bool GetFriendRequestInfo(int requestID, FriendRequestInfo& friendRequestInfo);
    
    static void Reset();
private:
    static void Notify(const FriendRequestInfo& friendRequest); 

    static std::unordered_map<unsigned int, FriendRequestInfo> _friendRequests;
    static std::vector<FriendRequestInfoDelegate> _subscribers;
};
