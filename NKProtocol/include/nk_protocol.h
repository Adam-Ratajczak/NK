#ifndef NK_PROTOCOL_H
#define NK_PROTOCOL_H
#define NK_PROTOCOL_VERSION 1
#define NK_X25519_KEY_SIZE 32
#define NK_ED25519_PUBLIC_KEY_SIZE 32
#define NK_ED25519_SECRET_KEY_SIZE 64
#define NK_ED25519_SIG_SIZE 64
#define NK_PWHASH_BYTES 32
#define NK_NONCE_SIZE   24
#define NK_HEADER_SIZE  6
#define NK_HASH_SIZE 32
#define NK_SALT_SIZE 16
#define NK_MAC_SIZE 16
#define NK_MAX_USERNAME_SIZE 64
#define NK_MAX_PASSWD_SIZE 64
#define NK_MAX_PAYLOAD_ARRAY_SIZE 64
#define NK_MAX_MESSAGE_SIZE 4096
#define NK_MAX_PAYLOAD_USERINFO_SIZE 70
#define NK_MAX_ENCRYPTED_KEY_SIZE 128

// no encryption
#define NK_OPCODE_HELLO         0x00 // first handshake
#define NK_OPCODE_OK            0x01 // all OK
#define NK_OPCODE_ERROR         0x02 // sth went wrong

// registration and login
#define NK_OPCODE_REGISTER                      0x10 // register new user
#define NK_OPCODE_REQUEST_SALT                  0x11 // request salt bytes
#define NK_OPCODE_REQUEST_SALT_RESULT           0x12 // send salt bytes
#define NK_OPCODE_LOGIN                         0x13 // login user
#define NK_OPCODE_LOGIN_RESULT                  0x14 // login result
#define NK_OPCODE_LOGOUT                        0x15 // logout user
#define NK_OPCODE_UNREGISTER                    0x16 // unregister user
#define NK_OPCODE_UPDATE_USER_DATA              0x17 // update user data

// devices
#define NK_OPCODE_REGISTER_NEW_DEVICE_KEYS      0x20
#define NK_OPCODE_REQUEST_DEVICES               0x21
#define NK_OPCODE_REQUEST_USER_DEVICES          0x22
#define NK_OPCODE_REQUEST_DEVICES_RESULT        0x23

// user data
#define NK_OPCODE_SYNC_USER_DATA            0x30 // receive user data
#define NK_OPCODE_USER_STATUS_UPDATE        0x31 // update status
#define NK_OPCODE_USER_STATUS_BROADCAST     0x32 // broadcast status

// user relations
#define NK_OPCODE_FRIEND_REQUEST                0x40 // friend request
#define NK_OPCODE_FRIEND_REQUEST_UPDATE_STATUS  0x41 // accept / deny friend request
#define NK_OPCODE_USER_RELATION_BLOCK           0x42 // block user
#define NK_OPCODE_USER_RELATION_RESET           0x43 // pardon user, remove friend
#define NK_OPCODE_SYNC_FRIEND_REQUESTS          0x44 // sync friend requests
#define NK_OPCODE_SYNC_RELATIONS                0x45 // sync relations

// channel
#define NK_OPCODE_CHANNEL_REQUEST_RECIPENTS         0x50 // request recipents for a channel
#define NK_OPCODE_CHANNEL_REQUEST_RECIPENTS_RESULT  0x51 // recipents of a channel
#define NK_OPCODE_CHANNEL_REQUEST_DM                0x52 // request DM channel for a friend
#define NK_OPCODE_CHANNEL_REQUEST_DM_RESULT         0x53 // DM channel for a friend
#define NK_OPCODE_CHANNEL_SUBMIT_KEY                0x54 // push new encrypted CK (join / rekey)
#define NK_OPCODE_CHANNEL_SUBMIT_KEY_RESULT         0x55 // push new encrypted CK (join / rekey)
#define NK_OPCODE_CHANNEL_BACKUP_KEY                0x56 // push new backup key for an user
#define NK_OPCODE_SYNC_CHANNEL_KEYS_REQUEST         0x57 // request all keys for channel(s)
#define NK_OPCODE_SYNC_CHANNEL_KEYS                 0x58 // send encrypted CK(s)

// messaging
#define NK_OPCODE_CHANNEL_MESSAGE_SEND              0x60 // send message
#define NK_OPCODE_CHANNEL_MESSAGE_DELIVER           0x61 // receive message
#define NK_OPCODE_SYNC_CHANNEL_HISTORY_REQUEST      0x62 // request messages
#define NK_OPCODE_SYNC_CHANNEL_HISTORY              0x63 // chunked response
#define NK_OPCODE_CHANNEL_TYPING_UPDATE             0x64 // typing start / stop
#define NK_OPCODE_CHANNEL_TYPING_BROADCAST          0x65 // typing status broadcast

// guild management
#define NK_OPCODE_CREATE_GUILD                  0x70 // create guild
#define NK_OPCODE_UPDATE_GUILD_SETTINGS         0x71 // update guild settings
#define NK_OPCODE_DELETE_GUILD                  0x72 // delete guild
#define NK_OPCODE_CREATE_GUILD_CHANNEL          0x73 // create channel
#define NK_OPCODE_UPDATE_GUILD_CHANNEL_SETTINGS 0x74 // update channel
#define NK_OPCODE_DELETE_GUILD_CHANNEL          0x75 // delete channel

// guild members
#define NK_OPCODE_GUILD_INVITE                  0x80 // invite to a guild
#define NK_OPCODE_GUILD_INVITE_UPDATE_STATUS    0x81 // sync friend requests
#define NK_OPCODE_GUILD_USER_PENALTY            0x82 // kick user
#define NK_OPCODE_GUILD_USER_PENALTY_RESET      0x83 // unban user
#define NK_OPCODE_SYNC_GUILD_INVITES            0x84 // sync friend requests
#define NK_OPCODE_SYNC_GUILD_PENALTIES          0x85 // sync relations

#define NK_OPCODE_INVALID           0xFF // invalid opcode

#define NK_ERROR_AUTH_FAILED                    0x1000
#define NK_ERROR_INVALID_FRAME                  0x1001
#define NK_ERROR_USER_EXISTS                    0x1002
#define NK_ERROR_INVALID_USER_OR_PASSWORD       0x1003
#define NK_ERROR_PERMISSION_DENIED              0x1004
#define NK_ERROR_USER_NOT_FOUND                 0x1005
#define NK_ERROR_RECIPENT_CANNOT_BE_SENDER      0x1006
#define NK_ERROR_ALREADY_REQUESTED              0x1007
#define NK_ERROR_INVALID_DEVICE                 0x1008
#define NK_ERROR_DEVICE_NOT_READY               0x1009
#define NK_ERROR_NOTHING_TO_SEND                0x1010
#define NK_ERROR_INVALID_SIGNATURE              0x1011
#define NK_ERROR_OPCODE_NOT_SUPPORTED           0x1FFD
#define NK_ERROR_NOT_IMPLEMENTED                0x1FFE
#define NK_ERROR_INTERNAL                       0x1FFF

#define NK_USERDATA_USERNAME                0x2000
#define NK_USERDATA_PASSWORD                0x2001
#define NK_USERDATA_TAG                     0x2002

typedef struct NKUserData {
    unsigned long long joinedTime;
    unsigned int userId;
    unsigned int userTag;
    unsigned int pfpResourceId;
    unsigned int reserved0;
    char username[NK_MAX_USERNAME_SIZE];
} NKUserData;

#define NK_FRIEND_REQUEST_PENDING           0x3000
#define NK_FRIEND_REQUEST_ACCEPTED          0x3001
#define NK_FRIEND_REQUEST_DENIED            0x3002
typedef struct NKFriendRequestData {
    unsigned long long updateTime;
    unsigned int requestId;
    unsigned int senderId;
    unsigned int statusCode;
    unsigned int reserved0;
} NKFriendRequestData;

#define NK_RELATION_DIR_MUTUAL              0x3010
#define NK_RELATION_DIR_OUTGOING            0x3011
#define NK_RELATION_DIR_INCOMING            0x3012

#define NK_USER_RELATION_FRIEND             0x3020
#define NK_USER_RELATION_BLOCKED            0x3021
#define NK_USER_RELATION_REMOVED            0x3022
typedef struct NKUserRelationData {
    unsigned long long updateTime;
    unsigned int relationId;
    unsigned int recipentId;
    unsigned int statusCode;
    unsigned int direction;
} NKUserRelationData;

#define NK_CHANNEL_TYPE_DM                      0x4000
#define NK_CHANNEL_TYPE_GROUP                   0x4001

#define NK_CHANNEL_TYPING_START                 0x4010
#define NK_CHANNEL_TYPING_STOP                  0x4011

typedef struct NKChannelSubmitDeviceInput {
    unsigned int targetDeviceId;
    unsigned char sharedSecret[NK_X25519_KEY_SIZE];
} NKChannelSubmitDeviceInput;

typedef struct NKChannelSubmitDeviceKey {
    unsigned int targetDeviceId;
    unsigned short encryptedKeySize;
    unsigned char encryptedKey[NK_MAX_ENCRYPTED_KEY_SIZE];
} NKChannelSubmitDeviceKey;

typedef struct NKChannelBackupKeyInput {
    unsigned int channelId;
    const unsigned char channelKey[NK_X25519_KEY_SIZE];
} NKChannelBackupKeyInput;

typedef struct NKEncryptedChannelBackupKeyData {
    unsigned int channelId;
    unsigned int keyVersion;
    unsigned short encryptedKeySize;
    unsigned char encryptedKey[NK_MAX_ENCRYPTED_KEY_SIZE];
} NKEncryptedChannelBackupKeyData;

typedef struct NKChannelDeviceKeyData {
    unsigned int keyVersion;

    unsigned int senderDeviceId;
    unsigned int targetDeviceId;

    unsigned short encryptedKeySize;
    unsigned char encryptedKey[NK_MAX_ENCRYPTED_KEY_SIZE];
} NKChannelDeviceKeyData;

typedef struct NKChannelBackupKeyData {
    unsigned int keyVersion;

    unsigned short encryptedKeySize;
    unsigned char encryptedKey[NK_MAX_ENCRYPTED_KEY_SIZE];
} NKChannelBackupKeyData;

typedef struct NKChannelMessageData {
    unsigned long long updateTime;
    unsigned int messageId;
    unsigned int senderId;
    unsigned int senderDeviceId;
    unsigned int keyVersion;
    unsigned short payloadSize;
    unsigned char payload[NK_MAX_MESSAGE_SIZE];
    unsigned char sig[NK_ED25519_SIG_SIZE];
} NKChannelMessageData;
#define NK_INVALID_MESSAGE                           0xFFFFFFFF

typedef struct NKDeviceData {
    unsigned int userId;
    unsigned int deviceId;
    unsigned char x25519_pub[NK_X25519_KEY_SIZE];
    unsigned char ed25519_pub[NK_ED25519_PUBLIC_KEY_SIZE];
} NKDeviceData;
#define NK_INVALID_DEVICE                           0xFFFFFFFF

#define NK_PROTOCOL_ERROR_NULL_FRAME                0x9000
#define NK_PROTOCOL_ERROR_BAD_HEADER                0x9001
#define NK_PROTOCOL_ERROR_BAD_OPCODE                0x9002
#define NK_PROTOCOL_ERROR_BAD_SIZE                  0x9003
#define NK_PROTOCOL_ERROR_OOM                       0x9004
#define NK_PROTOCOL_ERROR_ENCRYPTION_FAILED         0x9005
#define NK_PROTOCOL_ERROR_DECRYPTION_FAILED         0x9006
#define NK_PROTOCOL_MAX_SIZE_EXCEEDED               0x9007

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>

void nk_get_version(int ver[4]);
void nk_init();
int nk_crypto_x25519_keypair(unsigned char pub[NK_X25519_KEY_SIZE], unsigned char priv[NK_X25519_KEY_SIZE]);
int nk_crypto_x25519_shared(const unsigned char myPriv[NK_X25519_KEY_SIZE], const unsigned char theirPub[NK_X25519_KEY_SIZE], unsigned char shared[NK_X25519_KEY_SIZE]);
int nk_crypto_ed25519_keypair(unsigned char pub[NK_ED25519_PUBLIC_KEY_SIZE], unsigned char priv[NK_ED25519_SECRET_KEY_SIZE]);
int nk_crypto_ed25519_sign(const unsigned char* data, const unsigned int dataLen, const unsigned char priv[NK_ED25519_SECRET_KEY_SIZE], unsigned char sig[NK_ED25519_SIG_SIZE]);
int nk_verify_signature(const unsigned char pub[NK_ED25519_PUBLIC_KEY_SIZE], const unsigned char* msg, const unsigned int msgLen, const unsigned char sig[NK_ED25519_SIG_SIZE]);

int nk_crypto_pwhash(const unsigned char* data, const unsigned int dataLen, const unsigned char salt[NK_SALT_SIZE], unsigned char hash[NK_HASH_SIZE]);

int nk_client_derive_keys(unsigned char rx[NK_X25519_KEY_SIZE], unsigned char tx[NK_X25519_KEY_SIZE], const unsigned char client_pk[NK_X25519_KEY_SIZE], 
                          const unsigned char client_sk[NK_X25519_KEY_SIZE], const unsigned char server_pk[NK_X25519_KEY_SIZE]);
int nk_server_derive_keys(unsigned char rx[NK_X25519_KEY_SIZE], unsigned char tx[NK_X25519_KEY_SIZE], const unsigned char server_pk[NK_X25519_KEY_SIZE],
                          const unsigned char server_sk[NK_X25519_KEY_SIZE], const unsigned char client_pk[NK_X25519_KEY_SIZE]);
                          
unsigned char* nk_encrypt_payload(const unsigned char key[NK_X25519_KEY_SIZE], const unsigned char* plaintext, const unsigned int plaintextSize, unsigned int* ciphertextSize);
int nk_decrypt_payload(const unsigned char key[NK_X25519_KEY_SIZE], const unsigned char* ciphertext, const unsigned int ciphertextSize,
                       unsigned char* plaintext, unsigned int* plaintextSize);

int nk_encode_header(unsigned char* frame, const unsigned int frameSize, const unsigned char opcode, const unsigned int payloadLen);
int nk_decode_header(const unsigned char* frame, const unsigned int frameSize, unsigned char* opcode, unsigned int* payloadLen);
int nk_decode_header_ex(const unsigned char* frame, const unsigned int frameSize, unsigned char* version, unsigned char* opcode, unsigned int* payloadLen);

unsigned char* nk_encode_hello(const unsigned char pk[NK_X25519_KEY_SIZE], unsigned int* frameSize);
int nk_decode_hello(const unsigned char* frame, const unsigned int frameSize, unsigned char pk[NK_X25519_KEY_SIZE]);

unsigned char* nk_encode_ok(const unsigned char errOpcode, const unsigned char txKey[NK_X25519_KEY_SIZE], unsigned int* frameSize);
int nk_decode_ok(const unsigned char* frame, const unsigned int frameSize, const unsigned char rxKey[NK_X25519_KEY_SIZE], 
                 unsigned char *errOpcode);

unsigned char* nk_encode_error(const unsigned char errOpcode, const int errCode, const unsigned char txKey[NK_X25519_KEY_SIZE], unsigned int* frameSize);
int nk_decode_error(const unsigned char* frame, const unsigned int frameSize, const unsigned char rxKey[NK_X25519_KEY_SIZE], 
                  unsigned char *errOpcode, int* errCode);

unsigned char* nk_encode_register(const char username[NK_MAX_USERNAME_SIZE], const unsigned short usernameLen, const char password[NK_MAX_PASSWD_SIZE], const unsigned short passwordLen,
                                  const unsigned char txKey[NK_X25519_KEY_SIZE], unsigned int* frameSize);
    
int nk_decode_register(const unsigned char* frame, const unsigned int frameSize, const unsigned char rxKey[NK_X25519_KEY_SIZE], char username[NK_MAX_USERNAME_SIZE], unsigned short* usernameLen,
                       unsigned char salt[NK_SALT_SIZE], unsigned char passwdHash[NK_HASH_SIZE], unsigned char umkNonce[NK_NONCE_SIZE], unsigned char umkCipher[NK_X25519_KEY_SIZE + NK_MAC_SIZE]);

unsigned char* nk_encode_request_salt(const char username[NK_MAX_USERNAME_SIZE], const unsigned short usernameLen, 
                                      const unsigned char txKey[NK_X25519_KEY_SIZE], unsigned int* frameSize);
int nk_decode_request_salt(const unsigned char* frame, const unsigned int frameSize, const unsigned char rxKey[NK_X25519_KEY_SIZE],
                           char username[NK_MAX_USERNAME_SIZE], unsigned short* usernameLen);

unsigned char* nk_encode_request_salt_result(const unsigned char saltBytes[NK_SALT_SIZE], const unsigned char txKey[NK_X25519_KEY_SIZE], unsigned int* frameSize);
int nk_decode_request_salt_result(const unsigned char* frame, const unsigned int frameSize, const unsigned char rxKey[NK_X25519_KEY_SIZE], unsigned char saltBytes[NK_SALT_SIZE]);

unsigned char* nk_encode_login(const char username[NK_MAX_USERNAME_SIZE], const unsigned short usernameLen,
                               const char password[NK_MAX_PASSWD_SIZE], const unsigned short passwordLen,
                               const unsigned char saltBytes[NK_SALT_SIZE], const unsigned int deviceId, const unsigned char txKey[NK_X25519_KEY_SIZE], unsigned int* frameSize);
int nk_decode_login(const unsigned char* frame, const unsigned int frameSize, const unsigned char rxKey[NK_X25519_KEY_SIZE],
                     char username[NK_MAX_USERNAME_SIZE], unsigned short* usernameLen, unsigned char passwdHash[NK_HASH_SIZE], unsigned int* deviceId);

unsigned char* nk_encode_login_result(const unsigned int userId, const unsigned int deviceId, const unsigned char umkNonce[NK_NONCE_SIZE], const unsigned char umkCipher[NK_X25519_KEY_SIZE + NK_MAC_SIZE],
                                      const unsigned char txKey[NK_X25519_KEY_SIZE], unsigned int* frameSize);
int nk_decode_login_result(const unsigned char* frame, const unsigned int frameSize, const unsigned char rxKey[NK_X25519_KEY_SIZE], const char* password, const unsigned short passwordLen,
                           const unsigned char salt[NK_SALT_SIZE], unsigned int* userId, unsigned int* deviceId, unsigned char umk[NK_X25519_KEY_SIZE]);

unsigned char* nk_encode_logout(const unsigned char txKey[NK_X25519_KEY_SIZE], unsigned int* frameSize);
int nk_decode_logout(const unsigned char* frame, const unsigned int frameSize, const unsigned char rxKey[NK_X25519_KEY_SIZE]);

unsigned char* nk_encode_unregister(const unsigned char txKey[NK_X25519_KEY_SIZE], unsigned int* frameSize);
int nk_decode_unregister(const unsigned char* frame, const unsigned int frameSize, const unsigned char rxKey[NK_X25519_KEY_SIZE]);

unsigned char* nk_encode_register_new_device_keys(const unsigned int deviceId, const unsigned char x25519_pub[NK_X25519_KEY_SIZE], const unsigned char ed25519_pub[NK_X25519_KEY_SIZE], 
                                                  const unsigned char txKey[NK_X25519_KEY_SIZE], unsigned int* frameSize);
int nk_decode_register_new_device_keys(const unsigned char* frame, const unsigned int frameSize, const unsigned char rxKey[NK_X25519_KEY_SIZE], unsigned int* deviceId, 
                                       unsigned char x25519_pub[NK_X25519_KEY_SIZE], unsigned char ed25519_pub[NK_X25519_KEY_SIZE]);

unsigned char* nk_encode_request_devices(const unsigned int deviceIds[NK_MAX_PAYLOAD_ARRAY_SIZE], const unsigned short deviceIdsLen, 
                                         const unsigned char txKey[NK_X25519_KEY_SIZE], unsigned int* frameSize);
int nk_decode_request_devices(const unsigned char* frame, const unsigned int frameSize, const unsigned char rxKey[NK_X25519_KEY_SIZE], 
                              unsigned int deviceIds[NK_MAX_PAYLOAD_ARRAY_SIZE], unsigned short* deviceIdsLen);

unsigned char* nk_encode_request_user_devices(const unsigned int userIds[NK_MAX_PAYLOAD_ARRAY_SIZE], const unsigned short userIdsLen, 
                                         const unsigned char txKey[NK_X25519_KEY_SIZE], unsigned int* frameSize);
int nk_decode_request_user_devices(const unsigned char* frame, const unsigned int frameSize, const unsigned char rxKey[NK_X25519_KEY_SIZE], 
                              unsigned int userIds[NK_MAX_PAYLOAD_ARRAY_SIZE], unsigned short* userIdsLen);

unsigned char* nk_encode_request_devices_result(const NKDeviceData devices[NK_MAX_PAYLOAD_ARRAY_SIZE], const unsigned short devicesLen, 
                                                const unsigned char txKey[NK_X25519_KEY_SIZE], unsigned int* frameSize);
int nk_decode_request_devices_result(const unsigned char* frame, const unsigned int frameSize, const unsigned char rxKey[NK_X25519_KEY_SIZE], 
                                     NKDeviceData devices[NK_MAX_PAYLOAD_ARRAY_SIZE], unsigned short* devicesLen);

unsigned char* nk_encode_update_user_data_change_username_payload(const char username[NK_MAX_PASSWD_SIZE], const unsigned short usernameLen, unsigned short* userDataLen);

int nk_decode_update_user_data_change_username_payload(const unsigned char* payload, const unsigned short payloadLen, 
                                                       char username[NK_MAX_PASSWD_SIZE], unsigned short* usernameLen);

unsigned char* nk_encode_update_user_data_change_password_payload(const char password[NK_MAX_PASSWD_SIZE], const unsigned short passwordLen, unsigned short* userDataLen);

int nk_decode_update_user_data_change_password_payload(const unsigned char* payload, const unsigned short payloadLen, 
                                                       unsigned char saltBytes[NK_SALT_SIZE], unsigned char passwdHash[NK_HASH_SIZE]);

unsigned char* nk_encode_update_user_data_change_tag_payload(unsigned short* userDataLen);

int nk_decode_update_user_data_change_tag_payload(const unsigned char* payload, const unsigned short payloadLen);

unsigned char* nk_encode_update_user_data(const unsigned char* userDataPayload, const unsigned short userDataLen, const unsigned char txKey[NK_X25519_KEY_SIZE], unsigned int* frameSize);

int nk_decode_update_user_data(const unsigned char* frame, const unsigned int frameSize, const unsigned char rxKey[NK_X25519_KEY_SIZE], 
                               unsigned int* userInfoType, unsigned char userDataPayload[NK_MAX_PAYLOAD_USERINFO_SIZE], unsigned short* userDataLen);

unsigned char* nk_encode_sync_user_data(const NKUserData userData[NK_MAX_PAYLOAD_ARRAY_SIZE], const unsigned short userDataLen, const unsigned char txKey[NK_X25519_KEY_SIZE], unsigned int* frameSize);
int nk_decode_sync_user_data(const unsigned char* frame, const unsigned int frameSize, const unsigned char rxKey[NK_X25519_KEY_SIZE],
                                       NKUserData userData[NK_MAX_PAYLOAD_ARRAY_SIZE], unsigned short* userDataLen);

unsigned char* nk_encode_friend_request(const char username[NK_MAX_USERNAME_SIZE], const unsigned short usernameLen, const unsigned int tag, const unsigned char txKey[NK_X25519_KEY_SIZE], unsigned int* frameSize);
int nk_decode_friend_request(const unsigned char* frame, const unsigned int frameSize, const unsigned char rxKey[NK_X25519_KEY_SIZE], 
                            char username[NK_MAX_USERNAME_SIZE], unsigned short* usernameLen, unsigned int* tag);

unsigned char* nk_encode_friend_request_update_status(const unsigned int requestId, const unsigned int statusCode, const unsigned char txKey[NK_X25519_KEY_SIZE], unsigned int* frameSize);
int nk_decode_friend_request_update_status(const unsigned char* frame, const unsigned int frameSize, const unsigned char rxKey[NK_X25519_KEY_SIZE], unsigned int* requestId, unsigned int* statusCode);

unsigned char* nk_encode_user_relation_block(const unsigned int recipentId, const unsigned char txKey[NK_X25519_KEY_SIZE], unsigned int* frameSize);
int nk_decode_user_relation_block(const unsigned char* frame, const unsigned int frameSize, const unsigned char rxKey[NK_X25519_KEY_SIZE], unsigned int* recipentId);

unsigned char* nk_encode_user_relation_reset(const unsigned int recipentId, const unsigned char txKey[NK_X25519_KEY_SIZE], unsigned int* frameSize);
int nk_decode_user_relation_reset(const unsigned char* frame, const unsigned int frameSize, const unsigned char rxKey[NK_X25519_KEY_SIZE], unsigned int* recipentId);

unsigned char* nk_encode_sync_friend_requests(const NKFriendRequestData friendRequestData[NK_MAX_PAYLOAD_ARRAY_SIZE], const unsigned short friendRequestDataLen, const unsigned char txKey[NK_X25519_KEY_SIZE], unsigned int* frameSize);
int nk_decode_sync_friend_requests(const unsigned char* frame, const unsigned int frameSize, const unsigned char rxKey[NK_X25519_KEY_SIZE],
                                   NKFriendRequestData friendRequestData[NK_MAX_PAYLOAD_ARRAY_SIZE], unsigned short* friendRequestDataLen);

unsigned char* nk_encode_sync_relations(const NKUserRelationData userRelationData[NK_MAX_PAYLOAD_ARRAY_SIZE], const unsigned short userRelationDataLen, const unsigned char txKey[NK_X25519_KEY_SIZE], unsigned int* frameSize);
int nk_decode_sync_relations(const unsigned char* frame, const unsigned int frameSize, const unsigned char rxKey[NK_X25519_KEY_SIZE],
                             NKUserRelationData userRelationData[NK_MAX_PAYLOAD_ARRAY_SIZE], unsigned short* userRelationDataLen);

unsigned char* nk_encode_channel_request_recipents(const unsigned int channelId, const unsigned char txKey[NK_X25519_KEY_SIZE], unsigned int* frameSize);
int nk_decode_channel_request_recipents(const unsigned char* frame, const unsigned int frameSize, const unsigned char rxKey[NK_X25519_KEY_SIZE], unsigned int* channelId);

unsigned char* nk_encode_channel_request_recipents_result(const unsigned int channelId, const unsigned int userIds[NK_MAX_PAYLOAD_ARRAY_SIZE], const unsigned short userIdsLen, 
                                                          const unsigned char txKey[NK_X25519_KEY_SIZE], unsigned int* frameSize);
int nk_decode_channel_request_recipents_result(const unsigned char* frame, const unsigned int frameSize, const unsigned char rxKey[NK_X25519_KEY_SIZE], unsigned int* channelId,
                                               unsigned int userIds[NK_MAX_PAYLOAD_ARRAY_SIZE], unsigned short* userIdsLen);

unsigned char* nk_encode_channel_request_dm(const unsigned int userId, const unsigned char txKey[NK_X25519_KEY_SIZE], unsigned int* frameSize);
int nk_decode_channel_request_dm(const unsigned char* frame, const unsigned int frameSize, const unsigned char rxKey[NK_X25519_KEY_SIZE], unsigned int* userId);

unsigned char* nk_encode_channel_request_dm_result(const unsigned int userId, const unsigned int channelId, const unsigned char txKey[NK_X25519_KEY_SIZE], unsigned int* frameSize);
int nk_decode_channel_request_dm_result(const unsigned char* frame, const unsigned int frameSize, const unsigned char rxKey[NK_X25519_KEY_SIZE], unsigned int* userId, unsigned int* channelId);

unsigned char* nk_encode_channel_submit_key(const unsigned int channelId, const NKChannelSubmitDeviceInput devices[NK_MAX_PAYLOAD_ARRAY_SIZE], const unsigned short deviceCount, 
                                            const unsigned char umk[NK_X25519_KEY_SIZE], const unsigned char ed25519_sk[NK_ED25519_SECRET_KEY_SIZE],
                                            const unsigned char txKey[NK_X25519_KEY_SIZE], unsigned int* frameSize);
int nk_decode_channel_submit_key(const unsigned char* frame, const unsigned int frameSize, const unsigned char rxKey[NK_X25519_KEY_SIZE], unsigned int* channelId,
                                 NKChannelSubmitDeviceKey deviceKeys[NK_MAX_PAYLOAD_ARRAY_SIZE], unsigned short* deviceKeysLen, unsigned char umkEncryptedKey[NK_MAX_ENCRYPTED_KEY_SIZE],
                                 unsigned short* umkKeySize);

unsigned char* nk_encode_channel_submit_key_result(const unsigned int channelId, const unsigned int keyVersion, const unsigned char umkEncryptedKey[NK_MAX_ENCRYPTED_KEY_SIZE],
                                            const unsigned short umkKeySize, const unsigned char txKey[NK_X25519_KEY_SIZE], unsigned int* frameSize);
int nk_decode_channel_submit_key_result(const unsigned char* frame, const unsigned int frameSize, const unsigned char rxKey[NK_X25519_KEY_SIZE], unsigned int* channelId,
                                        unsigned int* keyVersion, unsigned char umkEncryptedKey[NK_MAX_ENCRYPTED_KEY_SIZE], unsigned short* umkKeySize);

unsigned char* nk_encode_channel_backup_keys(const NKChannelBackupKeyInput keys[NK_MAX_PAYLOAD_ARRAY_SIZE],const unsigned short keysLen, const unsigned char umk[NK_X25519_KEY_SIZE],
                                             const unsigned char txKey[NK_X25519_KEY_SIZE], unsigned int* frameSize);
int nk_decode_channel_backup_keys(const unsigned char* frame, const unsigned int frameSize, const unsigned char rxKey[NK_X25519_KEY_SIZE], 
                                  NKEncryptedChannelBackupKeyData keys[NK_MAX_PAYLOAD_ARRAY_SIZE], unsigned short* keysLen);

unsigned char* nk_encode_sync_channel_keys_request(const unsigned int channelId, const unsigned char txKey[NK_X25519_KEY_SIZE], unsigned int* frameSize);
int nk_decode_sync_channel_keys_request(const unsigned char* frame, const unsigned int frameSize, const unsigned char rxKey[NK_X25519_KEY_SIZE], unsigned int* channelId);
                                                
unsigned char* nk_encode_sync_channel_keys(const unsigned int channelId, const NKChannelDeviceKeyData deviceKeys[NK_MAX_PAYLOAD_ARRAY_SIZE], const unsigned short deviceKeysLen,
                                           const NKChannelBackupKeyData backupKeys[NK_MAX_PAYLOAD_ARRAY_SIZE], const unsigned short backupKeysLen,
                                           const unsigned char txKey[NK_X25519_KEY_SIZE], unsigned int* frameSize);
int nk_decode_sync_channel_keys(const unsigned char* frame, const unsigned int frameSize, const unsigned char rxKey[NK_X25519_KEY_SIZE], unsigned int* channelId, 
                                NKChannelDeviceKeyData deviceKeys[NK_MAX_PAYLOAD_ARRAY_SIZE], unsigned short* deviceKeysLen,
                                NKChannelBackupKeyData backupKeys[NK_MAX_PAYLOAD_ARRAY_SIZE], unsigned short* backupKeysLen);

unsigned char* nk_encode_channel_message_send(const unsigned int channelId, const unsigned int keyVersion, const unsigned char* plaintext, const unsigned short plaintextSize,
                                              const unsigned char channelKey[NK_X25519_KEY_SIZE], const unsigned char ed25519_sk[NK_ED25519_SECRET_KEY_SIZE], 
                                              const unsigned char txKey[NK_X25519_KEY_SIZE], unsigned int* frameSize);
int nk_decode_channel_message_send(const unsigned char* frame, const unsigned int frameSize, const unsigned char rxKey[NK_X25519_KEY_SIZE], 
                                   unsigned int* channelId, unsigned int* keyVersion, unsigned char payload[NK_MAX_MESSAGE_SIZE], unsigned short* payloadSize,
                                   unsigned char signature[NK_ED25519_SIG_SIZE], unsigned char* signedBuf, unsigned int* signedLen);

unsigned char* nk_encode_channel_message_deliver(const unsigned int channelId, const NKChannelMessageData* message, 
                                                 const unsigned char txKey[NK_X25519_KEY_SIZE], unsigned int* frameSize);
int nk_decode_channel_message_deliver(const unsigned char* frame, const unsigned int frameSize, const unsigned char rxKey[NK_X25519_KEY_SIZE], 
                                      unsigned int* channelId, NKChannelMessageData* message);

unsigned char* nk_encode_sync_channel_history_request(const unsigned int channelId, const unsigned int fromMessageId, const unsigned int limit,
                                                      const unsigned char txKey[NK_X25519_KEY_SIZE], unsigned int* frameSize);
int nk_decode_sync_channel_history_request(const unsigned char* frame, const unsigned int frameSize, const unsigned char rxKey[NK_X25519_KEY_SIZE], 
                                           unsigned int* channelId, unsigned int* fromMessageId, unsigned int* limit);

unsigned char* nk_encode_sync_channel_history(const unsigned int channelId, const NKChannelMessageData messages[NK_MAX_PAYLOAD_ARRAY_SIZE], 
                                              const unsigned short messagesLen, const unsigned char txKey[NK_X25519_KEY_SIZE], unsigned int* frameSize);
int nk_decode_sync_channel_history(const unsigned char* frame, const unsigned int frameSize, const unsigned char rxKey[NK_X25519_KEY_SIZE], unsigned int* channelId,
                                   NKChannelMessageData messages[NK_MAX_PAYLOAD_ARRAY_SIZE], unsigned short* messagesLen);
                                   
unsigned char* nk_encode_channel_typing_update(const unsigned int channelId, const unsigned int typingStatus, const unsigned char txKey[NK_X25519_KEY_SIZE], unsigned int* frameSize);
int nk_decode_channel_typing_update(const unsigned char* frame, const unsigned int frameSize, const unsigned char rxKey[NK_X25519_KEY_SIZE], unsigned int* channelId, unsigned int* typingStatus);
                                   
unsigned char* nk_encode_channel_typing_broadcast(const unsigned int userId, const unsigned int channelId, const unsigned int typingStatus, const unsigned char txKey[NK_X25519_KEY_SIZE], unsigned int* frameSize);
int nk_decode_channel_typing_broadcast(const unsigned char* frame, const unsigned int frameSize, const unsigned char rxKey[NK_X25519_KEY_SIZE], unsigned int* userId, unsigned int* channelId, unsigned int* typingStatus);
                     
#ifdef __cplusplus
}
#endif

#endif
