#include "networking/ChannelKeysManager.hpp"
#include "networking/ChannelsManager.hpp"
#include "networking/UserManager.hpp"
#include "networking/DevicesManager.hpp"
#include "networking/NetworkManager.hpp"
#include "nk_protocol.h"
#include <set>

std::vector<DeviceKeyEncryptedChannelKeyInfo> ChannelKeysManager::_encryptedKeys;
std::map<unsigned long long, ChannelKeyInfo> ChannelKeysManager::_keys;
std::vector<ChannelKeyInfoDelegate> ChannelKeysManager::_subscribers;
void ChannelKeysManager::Register(){
    DevicesManager::Subscribe(&ChannelKeysManager::OnNewDevices);
}

void ChannelKeysManager::Subscribe(ChannelKeyInfoDelegate func){
    _subscribers.push_back(func);
}

void ChannelKeysManager::LoadDeviceEncryptedKeys(const std::vector<DeviceKeyEncryptedChannelKeyInfo>& keys){
    for (const auto& k : keys){
        _encryptedKeys.push_back(k);
    }

    DecryptAllPossibleKeys();
}

void ChannelKeysManager::LoadBackupEncryptedKeys(const std::vector<BackupKeyEncryptedChannelKeyInfo>& keys){
    for (const auto& k : keys){
        std::vector<unsigned char> decrypted(32);
        unsigned int outSize = 0;

        if (nk_decrypt_payload(UserManager::UMK.data(), k.EncryptedKey.data(), k.EncryptedKey.size(), decrypted.data(), &outSize) != 0)
        {
            continue;
        }

        if (outSize != 32)
            continue;

        ChannelKeyInfo info{};
        info.ChannelId = k.ChannelId;
        info.KeyVersion = k.KeyVersion;
        memcpy(info.Key.data(), decrypted.data(), 32);

        _keys[MakeKey(info.ChannelId, info.KeyVersion)] = info;
    }

    DecryptAllPossibleKeys();
    RequestDevices();
}

void ChannelKeysManager::DecryptAllPossibleKeys(){
    std::map<unsigned int, DeviceConn> _deviceConnections;
    for (const auto& ek : _encryptedKeys){
        if(_deviceConnections.find(ek.SenderDeviceId) != _deviceConnections.end()){
            continue;
        }
        DeviceConn conn;
        if(DevicesManager::GetConnection(ek.SenderDeviceId, conn)){
            _deviceConnections[ek.SenderDeviceId] = conn;
        }
    }

    for (auto itEk = _encryptedKeys.begin(); itEk != _encryptedKeys.end();){
        auto itDev = _deviceConnections.find(itEk->SenderDeviceId);
        if(itDev == _deviceConnections.end()){
            itEk++;
            continue;
        }
        std::vector<unsigned char> decrypted(32);
        unsigned int outSize = 0;

        if (nk_decrypt_payload(itDev->second.SharedSecret.data(), itEk->EncryptedKey.data(), (unsigned int)itEk->EncryptedKey.size(), decrypted.data(), &outSize) != 0)
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
}

void ChannelKeysManager::RequestDevices(){
    std::vector<unsigned int> _devicesToFetch;
    for (const auto& ek : _encryptedKeys){
        if(std::find(_devicesToFetch.begin(), _devicesToFetch.end(), ek.SenderDeviceId) != _devicesToFetch.end()){
            continue;
        }
        DeviceConn conn;
        if(!DevicesManager::GetConnection(ek.SenderDeviceId, conn)){
            _devicesToFetch.emplace_back(ek.SenderDeviceId);
        }
    }
    NetworkManager::RequestDevices(_devicesToFetch);
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
