#include "networking/UserRelationsManager.hpp"
#include "networking/NetworkManager.hpp"
#include <JsLogger.hpp>

std::map<unsigned int, UserRelationInfo> UserRelationsManager::_userRelations;
std::vector<UserRelationInfoDelegate> UserRelationsManager::_subscribers;
void UserRelationsManager::LoadUserRelationInfo(const std::vector<UserRelationInfo>& userRelationsInfo){
    for(const auto& userRelation : userRelationsInfo){
        if(userRelation.StatusCode == UserRelationStatus::REMOVED){
            _userRelations.erase(userRelation.RelationId);    
        }else{
            _userRelations[userRelation.RelationId] = userRelation;
        }
        Notify(userRelation);
    }
}

bool UserRelationsManager::GetUserRelationInfo(int relationID, UserRelationInfo& userRelationInfo){
    auto it = _userRelations.find(relationID);
    if(it != _userRelations.end()){
        userRelationInfo = it->second;
        return true;
    }
    return false;
}

void UserRelationsManager::Subscribe(UserRelationInfoDelegate func){
    if(!func){
        return;
    }

    _subscribers.emplace_back(func);
}

void UserRelationsManager::Unsubscribe(UserRelationInfoDelegate func){
}

void UserRelationsManager::Notify(const UserRelationInfo& userRelation) {
    for(auto& delegate : _subscribers){
        delegate(userRelation);
    }
}

