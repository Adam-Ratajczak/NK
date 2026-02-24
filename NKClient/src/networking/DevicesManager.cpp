#include "networking/DevicesManager.hpp"
#include "networking/UserManager.hpp"
#include "networking/NetworkManager.hpp"
#include "JsStorage.hpp"
#include "nk_protocol.h"

#include <cstring>

unsigned int DevicesManager::DeviceId = NK_INVALID_DEVICE;
std::array<unsigned char, 32> DevicesManager::DeviceX25519_pub = {};
std::array<unsigned char, 32> DevicesManager::DeviceX25519_secret = {};

std::array<unsigned char, 32> DevicesManager::DeviceEd25519_pub = {};
std::array<unsigned char, 64> DevicesManager::DeviceEd25519_secret = {};

std::unordered_map<unsigned int, DeviceConn> DevicesManager::_deviceConnections;
std::vector<DeviceConnDelegate> DevicesManager::_subscribers;
unsigned int DevicesManager::GetDeviceId(const std::string& uname){
    const std::string cacheKey = "devid_" + uname;
    if (!JsStorage::Exists(cacheKey)){
        return NK_INVALID_DEVICE;
    }

    std::string idStr = JsStorage::Get(cacheKey);
    if (idStr.empty()){
        return NK_INVALID_DEVICE;
    }

    return std::stoul(idStr);
}

void DevicesManager::GetDeviceKeys(unsigned int deviceId) {
    if(deviceId == NK_INVALID_DEVICE){
        return;
    }
    
    DeviceId = deviceId;
    if (!JsStorage::Exists("devid_" + UserManager::Username)){
        SendDeviceKeys();
        return;
    }

    if (!JsStorage::Exists(GetCacheKey())){
        SendDeviceKeys();
        return;
    }

    std::string b64 = JsStorage::Get(GetCacheKey());
    if (b64.empty()){
        SendDeviceKeys();
        return;
    }

    std::vector<unsigned char> encrypted = Base64Decode(b64);
    if (encrypted.empty()){
        SendDeviceKeys();
        return;
    }

    std::vector<unsigned char> plain;
    plain.resize(4 + 32 + 32 + 32 + 64);

    unsigned int plainSize = 0;

    const auto& umk = UserManager::UMK;

    if (nk_decrypt_payload(umk.data(), encrypted.data(), (unsigned int)encrypted.size(), plain.data(), &plainSize) != 0)
    {
        SendDeviceKeys();
        return;
    }

    if (plainSize != (4 + 32 + 32 + 32 + 64)){
        SendDeviceKeys();
        return;
    }

    const unsigned char* p = plain.data();

    memcpy(&DeviceId, p, 4); p += 4;
    memcpy(DeviceX25519_pub.data(), p, 32); p += 32;
    memcpy(DeviceX25519_secret.data(), p, 32); p += 32;
    memcpy(DeviceEd25519_pub.data(), p, 32); p += 32;
    memcpy(DeviceEd25519_secret.data(), p, 64);
}

void DevicesManager::WriteToCache() {
    std::vector<unsigned char> plain;
    plain.resize(4 + 32 + 32 + 32 + 64);

    unsigned char* p = plain.data();

    memcpy(p, &DeviceId, 4); p += 4;
    memcpy(p, DeviceX25519_pub.data(), 32); p += 32;
    memcpy(p, DeviceX25519_secret.data(), 32); p += 32;
    memcpy(p, DeviceEd25519_pub.data(), 32); p += 32;
    memcpy(p, DeviceEd25519_secret.data(), 64);

    const auto& umk = UserManager::UMK;

    unsigned int encSize = 0;
    unsigned char* enc = nk_encrypt_payload(
        umk.data(),
        plain.data(),
        (unsigned int)plain.size(),
        &encSize
    );

    if (!enc)
        return;

    std::string b64 = Base64Encode(enc, encSize);
    free(enc);

    JsStorage::Set(GetCacheKey(), b64);
    
    const std::string cacheKey = "devid_" + UserManager::Username;
    JsStorage::Set(cacheKey, std::to_string(DeviceId));
}

std::string DevicesManager::GetCacheKey(){
    return "dev_" + std::to_string(DeviceId) + "_keys";
}

void DevicesManager::SendDeviceKeys() {
    nk_crypto_x25519_keypair(DeviceX25519_pub.data(),DeviceX25519_secret.data());
    nk_crypto_ed25519_keypair(DeviceEd25519_pub.data(), DeviceEd25519_secret.data());

    WriteToCache();
    NetworkManager::RegisterNewDeviceKeys(DeviceId, DeviceX25519_pub.data(), DeviceEd25519_pub.data());
}

void DevicesManager::LoadDeviceInfo(const std::vector<DeviceInfo>& devices) {
    printf("Received %d devices\n", devices.size());
    fflush(stdout);
    for (const auto& d : devices) {
        DeviceConn conn{};
        conn.DeviceId = d.DeviceId;
        conn.OwnerId = d.OwnerId;
        conn.Ed25519_pub = d.Ed25519_pub;

        nk_crypto_x25519_shared(DeviceX25519_secret.data(), d.X25519_pub.data(), conn.SharedSecret.data());

        _deviceConnections[d.DeviceId] = conn;
        Notify(conn);
    }

    std::vector<DeviceConn> connectionList;
    for (auto& [_, connection] : _deviceConnections)
        connectionList.push_back(connection);
}

bool DevicesManager::GetConnection(unsigned int deviceId, DeviceConn& out) {
    auto it = _deviceConnections.find(deviceId);
    if (it == _deviceConnections.end())
        return false;

    out = it->second;
    return true;
}

bool DevicesManager::GetUserConnections(unsigned int userId, std::vector<DeviceConn>& out){
    out.clear();
    for(const auto& [devId, conn] : _deviceConnections){
        if(conn.OwnerId == userId){
            out.emplace_back(conn);
        }
    }

    return !out.empty();
}

void DevicesManager::Subscribe(DeviceConnDelegate func) {
    _subscribers.push_back(func);
}

void DevicesManager::Notify(const DeviceConn& deviceConn){
    for(auto delegate : _subscribers){
        delegate(deviceConn);
    }
}

void DevicesManager::Reset() {
    DeviceId = 0;

    DeviceX25519_pub.fill(0);
    DeviceX25519_secret.fill(0);
    DeviceEd25519_pub.fill(0);
    DeviceEd25519_secret.fill(0);

    _deviceConnections.clear();
    _subscribers.clear();
}
