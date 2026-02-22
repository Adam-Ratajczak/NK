#pragma once
#include <array>

class SessionManager{
public:
    static std::array<unsigned char, 32> RxKey;
    static std::array<unsigned char, 32> TxKey;

    static void StartSession();
    static void SetServerPublicKey(unsigned char* pk);
private:
    static std::array<unsigned char, 32> ClientPk;
    static std::array<unsigned char, 32> ClientSk;
    static std::array<unsigned char, 32> ServerPk;
};
