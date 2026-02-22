#pragma once
#include <map>
#include "../structs.hpp"

class UserManager{
public:
    static std::array<unsigned char, 32> UMK;
    static std::array<unsigned char, 16> SaltBytes;
    static std::string Username;
    static std::string Password;
    static unsigned int UserId;

    static void Register();
    static void Login(const std::string& username, const std::string& password);
    static void Logout();
    static void Unregister();
    static void ReceiveSaltBytes(unsigned char* salt);

    static void Subscribe(UserInfoDelegate func);
    static void Unsubscribe(UserInfoDelegate func);

    static void LoadUserInfo(const std::vector<UserInfo>& userInfo);

    static bool GetUserInfo(int userID, UserInfo& userInfo);
    
    static void Reset();
private:
    static void Notify(const UserInfo& user); 
    static void OnLoginError(int errNo);

    static std::map<unsigned int, UserInfo> _users;
    static std::vector<UserInfoDelegate> _subscribers;
};
