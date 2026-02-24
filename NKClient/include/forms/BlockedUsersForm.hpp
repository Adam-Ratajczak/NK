#pragma once
#include "../structs.hpp"
#include <unordered_set>

class BlockedUsersForm{
public:
    static void Create();
    static void Destroy();
    static void Open();
    static void Render();

private:
    static void AddBlockedUser(const UserRelationInfo& userRelation);
    static void AddUserInfo(const UserInfo& user);
    static std::unordered_set<int> _blockedUserIds;
    static std::unordered_map<int, UserInfo> _blockedUsers;
};
