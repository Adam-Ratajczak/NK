#pragma once
#include "../structs.hpp"

class MainBar{
public:
    static void Create();
    static void Destroy();
    static void Open();
    static void Render();

private:
    static void AddUser(const UserInfo& user);
    static UserInfo _selfUser;
};
