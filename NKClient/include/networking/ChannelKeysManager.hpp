#pragma once
#include "../structs.hpp"

class ChannelKeysManager {
public:
    static void Register(); 
    static void Subscribe(ChannelKeyInfoDelegate func);

    static void LoadDeviceEncryptedKeys(const std::vector<DeviceKeyEncryptedChannelKeyInfo>& keys);
    static void LoadBackupEncryptedKeys(const std::vector<BackupKeyEncryptedChannelKeyInfo>& keys);

    static bool GetChannelKey(unsigned int channelId, unsigned int keyVersion, ChannelKeyInfo& out);
    static bool GetActiveChannelKey(unsigned int channelId, ChannelKeyInfo& out);

    static void Reset();

private:
    static void DecryptAllPossibleKeys();
    static void DecryptByDevice(const DeviceConn& deviceConn);

    static void BackupAllKeys();

    static void Notify(const ChannelKeyInfo& channelKey);

    static unsigned long long MakeKey(unsigned int channelId, unsigned int keyVersion);
    static void OnNewDevices(const DeviceConn& conn);

    static std::vector<DeviceKeyEncryptedChannelKeyInfo> _encryptedKeys;

    static std::unordered_map<unsigned long long, ChannelKeyInfo> _keys;
    static std::vector<ChannelKeyInfoDelegate> _subscribers;
};
