#pragma once
#include "../structs.hpp"
#include <set>

class BlockedUsersForm{
public:
    static void Create();
    static void Destroy();
    static void Open();
    static void Render();

private:
    static void AddBlockedUser(const UserRelationInfo& userRelation);
    static void AddUserInfo(const UserInfo& user);
    static std::set<int> _blockedUserIds;
    static std::map<int, UserInfo> _blockedUsers;
};
