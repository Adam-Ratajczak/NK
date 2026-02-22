#pragma once
#include <map>
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

    static std::map<unsigned int, UserRelationInfo> _userRelations;
    static std::vector<UserRelationInfoDelegate> _subscribers;
};
