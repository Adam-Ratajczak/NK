#pragma once
#include "../structs.hpp"
#include <map>

class DevicesManager{
public:
    static unsigned int DeviceId;
    static std::array<unsigned char, 32> DeviceX25519_pub;
    static std::array<unsigned char, 32> DeviceX25519_secret;
    static std::array<unsigned char, 32> DeviceEd25519_pub;
    static std::array<unsigned char, 64> DeviceEd25519_secret;

    static unsigned int GetDeviceId(const std::string& uname);
    static void GetDeviceKeys(unsigned int deviceId);
    static void LoadDeviceInfo(const std::vector<DeviceInfo>& deviceInfo);
    static bool GetConnection(unsigned int deviceId, DeviceConn& out);
    static bool GetUserConnections(unsigned int userId, std::vector<DeviceConn>& out);
    static void Subscribe(DeviceConnDelegate func);
    
    static void Reset();
private:
    static void SendDeviceKeys();
    static void WriteToCache();
    static std::string GetCacheKey();

    static void Notify(const DeviceConn& deviceConn);

    static std::map<unsigned int, DeviceConn> _deviceConnections;
    static std::vector<DeviceConnDelegate> _subscribers;
};
