#pragma once
#include "../structs.hpp"
#include <unordered_set>

class RequestsForm{
public:
    static void Create();
    static void Destroy();
    static void Open();
    static void Render();

private:
    static void AddFriendRequest(const FriendRequestInfo& friendRequestInfo);
    static void AddUserInfo(const UserInfo& userInfo);
    static std::unordered_set<int> _userIds;
    static std::unordered_map<int, FriendRequestInfo> _friendRequests;
    static std::unordered_map<int, UserInfo> _users;
};
