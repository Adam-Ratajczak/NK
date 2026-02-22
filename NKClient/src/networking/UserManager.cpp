#include "networking/UserManager.hpp"
#include "networking/NetworkManager.hpp"
#include "networking/DevicesManager.hpp"
#include "networking/RequestManager.hpp"
#include "JsLogger.hpp"
#include "nk_protocol.h"

std::map<unsigned int, UserInfo> UserManager::_users;
std::vector<UserInfoDelegate> UserManager::_subscribers;
std::array<unsigned char, 32> UserManager::UMK;
std::array<unsigned char, 16> UserManager::SaltBytes;
std::string UserManager::Username;
std::string UserManager::Password;
unsigned int UserManager::UserId;
void UserManager::Register(){
    RequestManager::SubscribeErrorRequest(NK_OPCODE_LOGIN, &UserManager::OnLoginError);
}
void UserManager::Login(const std::string& username, const std::string& password){
    Username = username;
    Password = password;

    NetworkManager::RequestSalt(username);
}

void UserManager::Logout(){
    NetworkManager::Logout();
}

void UserManager::Unregister(){
    NetworkManager::Unregister();
}

void UserManager::ReceiveSaltBytes(unsigned char* salt){
    memcpy(SaltBytes.data(), salt, SaltBytes.size());

    auto deviceId = DevicesManager::GetDeviceId(Username);
    NetworkManager::Login(deviceId, Username, Password, SaltBytes.data());
}

void UserManager::LoadUserInfo(const std::vector<UserInfo>& userInfo){
    for(const auto& user : userInfo){
        _users[user.UserId] = user;
        Notify(user);
    }
}

bool UserManager::GetUserInfo(int userID, UserInfo& userInfo){
    auto it = _users.find(userID);
    if(it != _users.end()){
        userInfo = it->second;
        return true;
    }
    return false;
}

void UserManager::Reset(){
    UMK.fill(0);
    SaltBytes.fill(0);
    Username = "";
    Password = "";
    UserId = 0;
}

void UserManager::Subscribe(UserInfoDelegate func){
    if(!func){
        return;
    }

    JsLogger::Log("Subscribed to UserManager");
    _subscribers.emplace_back(func);
}

void UserManager::Unsubscribe(UserInfoDelegate func){
}

void UserManager::Notify(const UserInfo& user){ 
    for(auto& delegate : _subscribers){
        delegate(user);
    }
}

void UserManager::OnLoginError(int errNo){
    if(errNo == NK_ERROR_INVALID_DEVICE){
        NetworkManager::Login(NK_INVALID_DEVICE, Username, Password, SaltBytes.data());
    }
}
