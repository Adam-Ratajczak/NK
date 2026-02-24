#pragma once
#include <cstddef>
#include <string>
#include <vector>
#include <unordered_map>
#include "../structs.hpp"

class NetworkManager{
public:
    static void HandshakeServer(unsigned char* publicKey);
    static void Register(const std::string& login, const std::string& passwd);
    static void RequestSalt(const std::string& login);
    static void Login(const unsigned int deviceId, const std::string& login, const std::string& passwd, const unsigned char* salt);
    static void ChangeUsername(const std::string& username);
    static void ChangePassword(const std::string& password);
    static void RandomizeUserTag();
    static void Logout();
    static void Unregister();

    static void RegisterNewDeviceKeys(const unsigned int deviceId, const unsigned char* x25519_pub, const unsigned char* ed25519_pub);
    static void RequestDevices(const std::vector<unsigned int>& deviceIds);
    static void RequestUserDevices(const std::vector<unsigned int>& userIds);

    static void SendFriendRequest(const std::string& uname, const unsigned int tag);
    static void AcceptFriendRequest(const unsigned int requestId);
    static void DenyFriendRequest(const unsigned int requestId);
    static void BlockUser(const unsigned int userId);
    static void ResetRelation(const unsigned int userId);
    
    static void RequestChannelRecipents(const unsigned int channelId);
    static void RequestDM(const unsigned int userId);
    static void RequestChannelKeys(const unsigned int channelId);
    static void GenerateAndSendChannelKey(const unsigned int channelId, const std::vector<DeviceConn>& connections);
    static void BackupChannelKeys(const std::vector<ChannelKeyInfo>& keyInfo);

    static void SendMessage(const unsigned int channelId, const std::string& payload, const ChannelKeyInfo& keyInfo);
    static void RequestChannelHistory(const unsigned int channelId, const unsigned int fromMessage, const unsigned int limit);
    
    static void StartTyping(const unsigned int channelId);
    static void StopTyping(const unsigned int channelId);

private:
    static void Send(unsigned char* payload, size_t n);
    static unsigned char _lastOpCode;
};
