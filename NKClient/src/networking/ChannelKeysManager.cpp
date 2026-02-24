#include "networking/ChannelKeysManager.hpp"
#include "networking/ChannelsManager.hpp"
#include "networking/UserManager.hpp"
#include "networking/DevicesManager.hpp"
#include "networking/NetworkManager.hpp"
#include "nk_protocol.h"
#include <unordered_set>

std::vector<DeviceKeyEncryptedChannelKeyInfo> ChannelKeysManager::_encryptedKeys;
std::unordered_map<unsigned long long, ChannelKeyInfo> ChannelKeysManager::_keys;
std::vector<ChannelKeyInfoDelegate> ChannelKeysManager::_subscribers;
void ChannelKeysManager::Register(){
    DevicesManager::Subscribe(&ChannelKeysManager::OnNewDevices);
}

void ChannelKeysManager::Subscribe(ChannelKeyInfoDelegate func){
    _subscribers.push_back(func);
}

void ChannelKeysManager::LoadDeviceEncryptedKeys(const std::vector<DeviceKeyEncryptedChannelKeyInfo>& keys){
    printf("Device keys: %d\n", keys.size());
    fflush(stdout);
    _encryptedKeys.insert(_encryptedKeys.end(), keys.begin(), keys.end());
    DecryptAllPossibleKeys();
}

void ChannelKeysManager::LoadBackupEncryptedKeys(const std::vector<BackupKeyEncryptedChannelKeyInfo>& keys){
    for (const auto& k : keys){
        std::vector<unsigned char> decrypted(32);
        unsigned int outSize = 0;
        auto ind = MakeKey(k.ChannelId, k.KeyVersion);
        auto it = _keys.find(ind);
        if(it != _keys.end()){
            it->second.HasBackup = true;
            continue;
        }

        if (nk_decrypt_payload(UserManager::UMK.data(), k.EncryptedKey.data(), k.EncryptedKey.size(), decrypted.data(), &outSize) != 0)
        {
            printf("backup key decryption failed\n");
            fflush(stdout);
            continue;
        }

        if (outSize != 32){
            printf("Invalid key size\n");
            fflush(stdout);
            continue;
        }

        ChannelKeyInfo info{};
        info.ChannelId = k.ChannelId;
        info.KeyVersion = k.KeyVersion;
        info.HasBackup = true;
        memcpy(info.Key.data(), decrypted.data(), 32);

        printf("Key version: %d\n", info.KeyVersion);
        fflush(stdout);
        _keys[ind] = info;
        Notify(info);
    }
}

void ChannelKeysManager::DecryptAllPossibleKeys(){
    std::unordered_map<unsigned int, DeviceConn> deviceConnections;
    std::vector<unsigned int> missingDeviceIds;
    for (const auto& ek : _encryptedKeys){
        if(deviceConnections.find(ek.SenderDeviceId) != deviceConnections.end()){
            continue;
        }
        DeviceConn conn;
        if(DevicesManager::GetConnection(ek.SenderDeviceId, conn)){
            deviceConnections[ek.SenderDeviceId] = conn;
        }else{
            auto it = std::find(missingDeviceIds.begin(), missingDeviceIds.end(), ek.SenderDeviceId);
            if(it == missingDeviceIds.end()){
                missingDeviceIds.emplace_back(ek.SenderDeviceId);
            }
        }
    }

    for (auto itEk = _encryptedKeys.begin(); itEk != _encryptedKeys.end();){
        auto ind = MakeKey(itEk->ChannelId, itEk->KeyVersion);
        auto it = _keys.find(ind);
        if(it != _keys.end()){
            itEk++;
            continue;
        }

        auto itDev = deviceConnections.find(itEk->SenderDeviceId);
        if(itDev == deviceConnections.end()){
            itEk++;
            continue;
        }
        std::vector<unsigned char> decrypted(32);
        unsigned int outSize = 0;

        if (nk_decrypt_payload(itDev->second.SharedSecret.data(), itEk->EncryptedKey.data(), (unsigned int)itEk->EncryptedKey.size(), decrypted.data(), &outSize) != 0)
        {
            printf("device key decryption failed\n");
            fflush(stdout);
            itEk++;
            continue;
        }

        if (outSize != 32){
            printf("Invalid key size\n");
            fflush(stdout);
            itEk++;
            continue;
        }

        ChannelKeyInfo info{};
        info.ChannelId = itEk->ChannelId;
        info.KeyVersion = itEk->KeyVersion;
        info.HasBackup = false;
        memcpy(info.Key.data(), decrypted.data(), 32);

        printf("Key version: %d\n", info.KeyVersion);
        fflush(stdout);
        _keys[ind] = info;
        itEk = _encryptedKeys.erase(itEk);

        Notify(info);
    }

    if(!missingDeviceIds.empty()){
        NetworkManager::RequestDevices(missingDeviceIds);
    }
    BackupAllKeys();
}

void ChannelKeysManager::DecryptByDevice(const DeviceConn& deviceConn){
    for (auto itEk = _encryptedKeys.begin(); itEk != _encryptedKeys.end();){
        if(deviceConn.DeviceId != itEk->SenderDeviceId){
            itEk++;
            continue;
        }
        std::vector<unsigned char> decrypted(32);
        unsigned int outSize = 0;

        if (nk_decrypt_payload(deviceConn.SharedSecret.data(), itEk->EncryptedKey.data(), (unsigned int)itEk->EncryptedKey.size(), decrypted.data(), &outSize) != 0)
        {
            itEk++;
            continue;
        }

        if (outSize != 32){
            itEk++;
            continue;
        }

        ChannelKeyInfo info{};
        info.ChannelId = itEk->ChannelId;
        info.KeyVersion = itEk->KeyVersion;
        memcpy(info.Key.data(), decrypted.data(), 32);

        _keys[MakeKey(info.ChannelId, info.KeyVersion)] = info;
        itEk = _encryptedKeys.erase(itEk);

        Notify(info);
    }
    BackupAllKeys();
}

void ChannelKeysManager::BackupAllKeys(){
    std::vector<ChannelKeyInfo> keysToBackup;
    for(auto& [_, key] : _keys){
        if(!key.HasBackup){
            keysToBackup.emplace_back(key);
            key.HasBackup = true;
        }
    }

    if(!keysToBackup.empty()){
        NetworkManager::BackupChannelKeys(keysToBackup);
    }
}

void ChannelKeysManager::Notify(const ChannelKeyInfo& channelKey){
    for(auto delegate : _subscribers){
        delegate(channelKey);
    }
}

bool ChannelKeysManager::GetChannelKey(unsigned int channelId, unsigned int keyVersion, ChannelKeyInfo& out){
    auto it = _keys.find(MakeKey(channelId, keyVersion));
    if (it == _keys.end())
        return false;

    out = it->second;
    return true;
}

bool ChannelKeysManager::GetActiveChannelKey(unsigned int channelId, ChannelKeyInfo& out){
    if(_keys.empty()){
        return false;
    }
    unsigned long long highestKey = 0;
    for(const auto& [key, keyInfo] : _keys){
        if(((key >> 32) & 0xFFFFFFFF) != channelId){
            continue;
        }
        if(key > highestKey){
            highestKey = key;
        }
    }

    if(highestKey == 0){
        return false;
    }

    out = _keys[highestKey];
    return true;
}

void ChannelKeysManager::Reset(){
    _encryptedKeys.clear();
    _keys.clear();
}

unsigned long long ChannelKeysManager::MakeKey(unsigned int channelId, unsigned int keyVersion){
    return (static_cast<unsigned long long>(channelId) << 32) | keyVersion;
}

void ChannelKeysManager::OnNewDevices(const DeviceConn& deviceConn){
    DecryptByDevice(deviceConn);
}
