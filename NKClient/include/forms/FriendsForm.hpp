#pragma once
#include "../structs.hpp"
#include <set>

class FriendsForm{
public:
    static void Create();
    static void Destroy();
    static void Open();
    static void Render();

private:
    static void AddFriendUsers(const UserRelationInfo& userRelation);
    static void AddUserInfo(const UserInfo& user);
    static void OnDMChannelInfo(const DMChannelInfo& DMChannel);
    static void OnOkRequest();
    static void OnErrorRequest(int errNo);
    static std::set<int> _friendUserIds;
    static std::map<int, UserInfo> _friendUsers;
    static std::string _errorMsg;
};
