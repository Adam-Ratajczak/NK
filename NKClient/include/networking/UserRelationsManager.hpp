#pragma once
#include <unordered_map>
#include "../structs.hpp"

class UserRelationsManager{
public:
    static void Subscribe(UserRelationInfoDelegate func);
    static void Unsubscribe(UserRelationInfoDelegate func);

    static void LoadUserRelationInfo(const std::vector<UserRelationInfo>& friendRequestsInfo);

    static bool GetUserRelationInfo(int relationID, UserRelationInfo& userRelationInfo);
    
    static void Reset();
private:
    static void Notify(const UserRelationInfo& userRelation);

    static std::unordered_map<unsigned int, UserRelationInfo> _userRelations;
    static std::vector<UserRelationInfoDelegate> _subscribers;
};
