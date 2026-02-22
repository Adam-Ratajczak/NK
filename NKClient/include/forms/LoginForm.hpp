#pragma once
#include <string>

class LoginForm{
public:
    static void Create();
    static void Destroy();
    static void Open();
    static void Render();
    static void HandleSuccess();
    static void HandleError(int errNo);

private:
    static void Reset();
    
    static std::string _errorMsg;
    static char _username[64];
    static char _password[64];
};
