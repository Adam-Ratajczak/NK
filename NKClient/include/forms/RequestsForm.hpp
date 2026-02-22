#pragma once
#include "../structs.hpp"
#include <set>

class RequestsForm{
public:
    static void Create();
    static void Destroy();
    static void Open();
    static void Render();

private:
    static void AddFriendRequest(const FriendRequestInfo& friendRequestInfo);
    static void AddUserInfo(const UserInfo& userInfo);
    static std::set<int> _userIds;
    static std::map<int, FriendRequestInfo> _friendRequests;
    static std::map<int, UserInfo> _users;
};
