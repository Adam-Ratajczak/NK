#pragma once
#include "../structs.hpp"

class UserForm{
public:
    static void Create();
    static void Destroy();
    static void Open();
    static void Render();

private:
    static bool PasswordValid(const std::string& password);
    static void Reset();
    static void OnUserDataChangeSuccess();
    static void OnLogoutSuccess();
    static void OnError(int errNo);
    
    static std::string _errorMsg;
    static char _username[64];
    static char _password[64];
    static char _repeatPassword[64];
    static bool _shouldLogOut;
};
