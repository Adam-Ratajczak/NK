#include "networking/SessionManager.hpp"
#include "networking/NetworkManager.hpp"
#include "nk_protocol.h"

std::array<unsigned char, 32> SessionManager::RxKey;
std::array<unsigned char, 32> SessionManager::TxKey;
std::array<unsigned char, 32> SessionManager::ClientPk;
std::array<unsigned char, 32> SessionManager::ClientSk;
std::array<unsigned char, 32> SessionManager::ServerPk;
void SessionManager::StartSession(){
    nk_init();
    nk_crypto_x25519_keypair(ClientPk.data(), ClientSk.data());
    NetworkManager::HandshakeServer(ClientPk.data());
}

void SessionManager::SetServerPublicKey(unsigned char* pk){
    memcpy(ServerPk.data(), pk, 32);
    nk_client_derive_keys(RxKey.data(), TxKey.data(), ClientPk.data(), ClientSk.data(), ServerPk.data());
}
