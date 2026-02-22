#pragma once
#include <chrono>
#include <string>
#include <functional>
#include <vector>
#include <array>
#include <map>

struct UserInfo{
    unsigned int UserId;
    unsigned int UserTag;
    unsigned int UserPfpResourceId;
    std::string UserName;
    std::chrono::system_clock::time_point JoinedDate;
};
typedef std::function<void(const UserInfo&)> UserInfoDelegate;

enum class FriendRequestStatus{
    PENDING = 0,
    ACCEPTED,
    DENIED,
};
struct FriendRequestInfo{
    unsigned int RequestId;
    unsigned int SenderId;
    FriendRequestStatus StatusCode;
    std::chrono::system_clock::time_point UpdateTime;
};
typedef std::function<void(const FriendRequestInfo&)> FriendRequestInfoDelegate;

enum class UserRelationStatus{
    FRIEND = 0,
    BLOCKED,
    REMOVED,
};
struct UserRelationInfo{
    unsigned int RelationId;
    unsigned int RecipentId;
    UserRelationStatus StatusCode;
    std::chrono::system_clock::time_point UpdateTime;
};
typedef std::function<void(const UserRelationInfo&)> UserRelationInfoDelegate;

struct DeviceInfo{
    unsigned int DeviceId;
    unsigned int OwnerId;
    std::array<unsigned char, 32> X25519_pub;
    std::array<unsigned char, 32> Ed25519_pub;
};

struct DeviceConn{
    unsigned int DeviceId;
    unsigned int OwnerId;
    std::array<unsigned char, 32> SharedSecret;
    std::array<unsigned char, 32> Ed25519_pub;
};
typedef std::function<void(const DeviceConn&)> DeviceConnDelegate;

struct DMChannelInfo{
    unsigned int ChannelId;
    unsigned int UserId;
};
typedef std::function<void(const DMChannelInfo&)> DMChannelInfoDelegate;

struct TypingInfo{
    unsigned int ChannelId;
    std::vector<unsigned int> Typers;
};
typedef std::function<void(const TypingInfo&)> TypingInfoDelegate;

struct RecipentsInfo{
    unsigned int ChannelId;
    std::vector<unsigned int> Recipents;
};
typedef std::function<void(const RecipentsInfo&)> RecipentsInfoDelegate;

struct DeviceKeyEncryptedChannelKeyInfo{
    unsigned int ChannelId;
    unsigned int SenderDeviceId;
    unsigned int KeyVersion;
    std::vector<unsigned char> EncryptedKey;
};

struct BackupKeyEncryptedChannelKeyInfo{
    unsigned int ChannelId;
    unsigned int KeyVersion;
    std::vector<unsigned char> EncryptedKey;
};

struct ChannelKeyInfo{
    unsigned int ChannelId;
    unsigned int KeyVersion;
    std::array<unsigned char, 32> Key;
};
typedef std::function<void(const ChannelKeyInfo&)> ChannelKeyInfoDelegate;

struct ChannelMessageInfo {
    unsigned int ChannelId;
    unsigned int MessageId;
    unsigned int SenderId;
    unsigned int SenderDeviceId;
    unsigned int KeyVersion;
    std::chrono::system_clock::time_point Time;
    std::vector<unsigned char> Ciphertext;
    std::vector<unsigned char> Plaintext;
    bool IsDecrypted = false;
};
typedef std::function<void(const ChannelMessageInfo&)> ChannelMessageInfoDelegate;
