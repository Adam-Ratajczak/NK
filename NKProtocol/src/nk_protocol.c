#include "nk_protocol.h"
#include "sodium.h"
#include <stdlib.h>
#include <string.h>
#include <memory.h>
#include <stdio.h>

void nk_get_version(int ver[4]){
    ver[0] = 1;
    ver[1] = 0;
    ver[2] = 0;
    ver[3] = 2;
}

void nk_init(){
    if (sodium_init() < 0)
    {
        abort();
    }
}

int nk_crypto_x25519_keypair(unsigned char pub[NK_X25519_KEY_SIZE], unsigned char priv[NK_X25519_KEY_SIZE])
{
    if (!pub || !priv)
        return -1;

    if (crypto_kx_keypair(pub, priv) != 0)
    {
        return -1;
    }

    return 0;
}

int nk_crypto_x25519_shared(const unsigned char myPriv[NK_X25519_KEY_SIZE], const unsigned char theirPub[NK_X25519_KEY_SIZE], unsigned char shared[NK_X25519_KEY_SIZE])
{
    if (!myPriv || !theirPub || !shared)
        return -1;

    if (crypto_scalarmult(shared, myPriv, theirPub) != 0)
    {
        return -1;
    }

    return 0;
}

int nk_crypto_ed25519_keypair(unsigned char pub[NK_ED25519_PUBLIC_KEY_SIZE], unsigned char priv[NK_ED25519_SECRET_KEY_SIZE])
{
    if (!pub || !priv)
        return -1;

    if (crypto_sign_keypair(pub, priv) != 0)
    {
        return -1;
    }

    return 0;
}

int nk_crypto_ed25519_sign(const unsigned char* data, const unsigned int dataLen, const unsigned char priv[NK_ED25519_SECRET_KEY_SIZE], unsigned char sig[NK_ED25519_SIG_SIZE])
{
    if (!data || !priv || !sig)
        return -1;

    if (crypto_sign_detached(sig, NULL, data, dataLen, priv) != 0)
    {
        return -1;
    }

    return 0;
}

int nk_verify_signature(const unsigned char pub[NK_ED25519_PUBLIC_KEY_SIZE], const unsigned char* msg, const unsigned int msgLen, const unsigned char sig[NK_ED25519_SIG_SIZE]) {
    if (!pub || !msg || !sig)
        return -1;

    if (crypto_sign_verify_detached(sig, msg, msgLen, pub) != 0)
    {
        return -1;
    }

    return 0;
}

int nk_crypto_pwhash(const unsigned char* data, const unsigned int dataLen, const unsigned char salt[NK_SALT_SIZE], unsigned char hash[NK_HASH_SIZE]){
    if(!data || !salt || !hash){
        return -1;
    }

    return crypto_pwhash(
            hash,
            NK_HASH_SIZE,
            data,
            dataLen,
            salt,
            crypto_pwhash_OPSLIMIT_INTERACTIVE,
            crypto_pwhash_MEMLIMIT_INTERACTIVE,
            crypto_pwhash_ALG_DEFAULT);
}

int nk_client_derive_keys(unsigned char rx[NK_X25519_KEY_SIZE], unsigned char tx[NK_X25519_KEY_SIZE], const unsigned char client_pk[NK_X25519_KEY_SIZE], 
                          const unsigned char client_sk[NK_X25519_KEY_SIZE], const unsigned char server_pk[NK_X25519_KEY_SIZE]){
    if(crypto_kx_client_session_keys(rx, tx, client_pk, client_sk, server_pk) != 0){
        return -1;
    }
    return 0;
}

int nk_server_derive_keys(unsigned char rx[NK_X25519_KEY_SIZE], unsigned char tx[NK_X25519_KEY_SIZE], const unsigned char server_pk[NK_X25519_KEY_SIZE],
                          const unsigned char server_sk[NK_X25519_KEY_SIZE], const unsigned char client_pk[NK_X25519_KEY_SIZE]){
    if(crypto_kx_server_session_keys(rx, tx, server_pk, server_sk, client_pk) != 0){
        return -1;
    }
    return 0;
}


unsigned char* nk_encrypt_payload(const unsigned char key[NK_X25519_KEY_SIZE], const unsigned char* plaintext, const unsigned int plaintextSize, unsigned int* ciphertextSize){
    if (!key || !plaintext || !ciphertextSize)
        return NULL;

    unsigned int cipherLen = plaintextSize + crypto_aead_xchacha20poly1305_ietf_ABYTES;
    unsigned int payloadLen = NK_NONCE_SIZE + cipherLen;

    unsigned char* payload = malloc(payloadLen);
    if (!payload)
        return NULL;

    unsigned char* nonce = payload;
    unsigned char* cipher = nonce + NK_NONCE_SIZE;

    randombytes_buf(nonce, NK_NONCE_SIZE);

    unsigned long long realCipherLen = 0;

    if (crypto_aead_xchacha20poly1305_ietf_encrypt(
            cipher,
            &realCipherLen,
            plaintext,
            plaintextSize,
            NULL,
            0,
            NULL,
            nonce,
            key) != 0)
    {
        free(payload);
        return NULL;
    }

    *ciphertextSize = NK_NONCE_SIZE + (unsigned int)realCipherLen;

    return payload;
}

int nk_decrypt_payload(const unsigned char key[NK_X25519_KEY_SIZE], const unsigned char* ciphertext, const unsigned int ciphertextSize,
                       unsigned char* plaintext, unsigned int* plaintextSize){
    if (!key || !ciphertext || !plaintext || !plaintextSize)
        return -1;

    if (ciphertextSize < NK_NONCE_SIZE + NK_MAC_SIZE)
        return -1;

    const unsigned char* nonce  = ciphertext;
    const unsigned char* cipher = ciphertext + NK_NONCE_SIZE;

    unsigned int cipherLen = ciphertextSize - NK_NONCE_SIZE;

    unsigned long long realPlainLen = 0;

    if (crypto_aead_xchacha20poly1305_ietf_decrypt(
            plaintext,
            &realPlainLen,
            NULL,
            cipher,
            cipherLen,
            NULL,
            0,
            nonce,
            key) != 0)
    {
        return -1;
    }

    *plaintextSize = (unsigned int)realPlainLen;

    return 0;
}

int nk_encode_s8(unsigned char* buffer, char data){
    buffer[0] = (unsigned char)(data & 0xFF);
    
    return 1;
}

int nk_decode_s8(const unsigned char* buffer, char* data){
    *data = ((char)buffer[0]);
    
    return 1;
}

int nk_encode_u8(unsigned char* buffer, unsigned char data){
    buffer[0] = (unsigned char)(data & 0xFF);
    
    return 1;
}

int nk_decode_u8(const unsigned char* buffer, unsigned char* data){
    *data = ((unsigned char)buffer[0]);
    
    return 1;
}

int nk_encode_s16(unsigned char* buffer, short data){
    buffer[0] = (unsigned char)(data & 0xFF);
    buffer[1] = (unsigned char)((data >> 8) & 0xFF);
    
    return 2;
}

int nk_decode_s16(const unsigned char* buffer, short* data){
    *data = 
        ((short)buffer[0]) |
        ((short)buffer[1] << 8);
    
    return 2;
}

int nk_encode_u16(unsigned char* buffer, unsigned short data){
    buffer[0] = (unsigned char)(data & 0xFF);
    buffer[1] = (unsigned char)((data >> 8) & 0xFF);
    
    return 2;
}

int nk_decode_u16(const unsigned char* buffer, unsigned short* data){
    *data = 
        ((unsigned short)buffer[0]) |
        ((unsigned short)buffer[1] << 8);
    
    return 2;
}

int nk_encode_s32(unsigned char* buffer, int data){
    buffer[0] = (unsigned char)(data & 0xFF);
    buffer[1] = (unsigned char)((data >> 8) & 0xFF);
    buffer[2] = (unsigned char)((data >> 16) & 0xFF);
    buffer[3] = (unsigned char)((data >> 24) & 0xFF);
    
    return 4;
}

int nk_decode_s32(const unsigned char* buffer, int* data){
    *data = 
        ((int)buffer[0]) |
        ((int)buffer[1] << 8) |
        ((int)buffer[2] << 16) |
        ((int)buffer[3] << 24);
    
    return 4;
}

int nk_encode_u32(unsigned char* buffer, unsigned int data){
    buffer[0] = (unsigned char)(data & 0xFF);
    buffer[1] = (unsigned char)((data >> 8) & 0xFF);
    buffer[2] = (unsigned char)((data >> 16) & 0xFF);
    buffer[3] = (unsigned char)((data >> 24) & 0xFF);
    
    return 4;
}

int nk_decode_u32(const unsigned char* buffer, unsigned int* data){
    *data = 
        ((unsigned int)buffer[0]) |
        ((unsigned int)buffer[1] << 8) |
        ((unsigned int)buffer[2] << 16) |
        ((unsigned int)buffer[3] << 24);
    
    return 4;
}

int nk_encode_s64(unsigned char* buffer, long long data){
    buffer[0] = (unsigned char)(data & 0xFF);
    buffer[1] = (unsigned char)((data >> 8) & 0xFF);
    buffer[2] = (unsigned char)((data >> 16) & 0xFF);
    buffer[3] = (unsigned char)((data >> 24) & 0xFF);
    
    return 8;
}

int nk_decode_s64(const unsigned char* buffer, long long* data){
    *data = 
        ((long long)buffer[0]) |
        ((long long)buffer[1] << 8) |
        ((long long)buffer[2] << 16) |
        ((long long)buffer[3] << 24) |
        ((long long)buffer[4] << 32) |
        ((long long)buffer[5] << 40) |
        ((long long)buffer[6] << 48) |
        ((long long)buffer[7] << 56);
    
    return 8;
}

int nk_encode_u64(unsigned char* buffer, unsigned long long data){
    buffer[0] = (unsigned char)(data & 0xFF);
    buffer[1] = (unsigned char)((data >> 8) & 0xFF);
    buffer[2] = (unsigned char)((data >> 16) & 0xFF);
    buffer[3] = (unsigned char)((data >> 24) & 0xFF);
    buffer[4] = (unsigned char)((data >> 32) & 0xFF);
    buffer[5] = (unsigned char)((data >> 40) & 0xFF);
    buffer[6] = (unsigned char)((data >> 48) & 0xFF);
    buffer[7] = (unsigned char)((data >> 56) & 0xFF);
    
    return 8;
}

int nk_decode_u64(const unsigned char* buffer, unsigned long long* data){
    *data = 
        ((unsigned long long)buffer[0]) |
        ((unsigned long long)buffer[1] << 8) |
        ((unsigned long long)buffer[2] << 16) |
        ((unsigned long long)buffer[3] << 24) |
        ((unsigned long long)buffer[4] << 32) |
        ((unsigned long long)buffer[5] << 40) |
        ((unsigned long long)buffer[6] << 48) |
        ((unsigned long long)buffer[7] << 56);
    
    return 8;
}

int nk_encode_bytes(unsigned char* buffer, const unsigned char* data, const unsigned int len){
    memcpy(buffer, data, len);
    return len;
}

int nk_decode_bytes(const unsigned char* buffer, unsigned char* data, const unsigned int len){
    memcpy(data, buffer, len);
    return len;
}

int nk_encode_header(unsigned char* frame, const unsigned int frameSize, const unsigned char opcode, const unsigned int payloadLen){
    if(!frame){
        return -1;
    }
    if(frameSize < NK_HEADER_SIZE){
        return -1;
    }

    nk_encode_u8(frame, NK_PROTOCOL_VERSION);
    nk_encode_u8(frame+1, opcode);
    nk_encode_u32(frame+2,payloadLen);
    return 0;
}

int nk_decode_header(const unsigned char* frame, const unsigned int frameSize, unsigned char* opcode, unsigned int* payloadLen)
{
    if (!frame || !opcode || !payloadLen){
        return -1;
    }
        
    if (frameSize < NK_HEADER_SIZE){
        return -1;
    }

    nk_decode_u8(frame+1, opcode);
    nk_decode_u32(frame+2, payloadLen);
    return 0;
}

int nk_decode_header_ex(const unsigned char* frame, const unsigned int frameSize, unsigned char* version, unsigned char* opcode, unsigned int* payloadLen)
{
    if (!frame || !version || !opcode || !payloadLen){
        return -1;
    }
        
    if (frameSize < NK_HEADER_SIZE){
        return -1;
    }

    nk_decode_u8(frame, version);
    nk_decode_u8(frame+1, opcode);
    nk_decode_u32(frame+2, payloadLen);
    return 0;
}

unsigned char* nk_encode_hello(const unsigned char pk[NK_X25519_KEY_SIZE], unsigned int* frameSize)
{
    if (!pk || !frameSize)
        return NULL;

    int len = NK_HEADER_SIZE + NK_X25519_KEY_SIZE;
    unsigned char* buffer = (unsigned char*)malloc(len);
    if (!buffer)
        return NULL;

    if(nk_encode_header(buffer, len, NK_OPCODE_HELLO, NK_X25519_KEY_SIZE) != 0){
        return NULL;
    }
    nk_encode_bytes(buffer + NK_HEADER_SIZE, pk, NK_X25519_KEY_SIZE);
    *frameSize = len;

    return buffer;
}

int nk_decode_hello(const unsigned char* frame, const unsigned int frameSize, unsigned char pk[NK_X25519_KEY_SIZE])
{
    if (!frame || !pk){
        printf("NULL frame\n");
        return -1;
    }

    if (frameSize < NK_HEADER_SIZE){
        printf("Invalid size\n");
        return -1;
    }

    unsigned char opcode = 0;
    unsigned int payloadLen = 0;
    if(nk_decode_header(frame, frameSize, &opcode, &payloadLen) != 0){
        printf("Invalid header\n");
        return -1;
    }

    if (opcode != NK_OPCODE_HELLO){
        printf("Invalid opcode\n");
        return -1;
    }

    if ((int)payloadLen != NK_X25519_KEY_SIZE){
        printf("Invalid payload size\n");
        return -1;
    }

    nk_decode_bytes(frame+NK_HEADER_SIZE, pk, NK_X25519_KEY_SIZE);
    return 0;
}

unsigned char* nk_encode_ok(const unsigned char errOpcode, const unsigned char txKey[NK_X25519_KEY_SIZE], unsigned int* frameSize){
    if (!txKey || !frameSize)
        return NULL;

    int plainLen = 1;
    unsigned char* plain = malloc(plainLen);
    if (!plain)
        return NULL;

    unsigned char* p = plain;

    p += nk_encode_u8(p, errOpcode);

    unsigned int payloadLen = 0;
    unsigned char* payload = nk_encrypt_payload(txKey, plain, p - plain, &payloadLen);

    free(plain);

    if (!payload)
        return NULL;

    unsigned int totalLen = NK_HEADER_SIZE + payloadLen;

    unsigned char* frame = malloc(totalLen);
    if (!frame) {
        free(payload);
        return NULL;
    }

    nk_encode_header(frame, totalLen, NK_OPCODE_OK, payloadLen);
    memcpy(frame + NK_HEADER_SIZE, payload, payloadLen);

    free(payload);
    *frameSize = totalLen;

    return frame;
}

int nk_decode_ok(const unsigned char* frame, const unsigned int frameSize, const unsigned char rxKey[NK_X25519_KEY_SIZE], 
                 unsigned char *errOpcode){
    if (!frame || !rxKey || !errOpcode){
        return -1;
    }

    unsigned char opcode = 0;
    unsigned int payloadLen = 0;
    if(nk_decode_header(frame, frameSize, &opcode, &payloadLen) != 0){
        return -1;
    }

    if (opcode != NK_OPCODE_OK){
        return -1;
    }

    unsigned char* plain = malloc(payloadLen);
    if (!plain)
        return -1;

    unsigned int plainLen = 0;
    if (nk_decrypt_payload(rxKey, frame + NK_HEADER_SIZE, payloadLen, plain, &plainLen) != 0) {
        free(plain);
        return -1;
    }

    const unsigned char* p = plain;
    p += nk_decode_u8(p, errOpcode);

    sodium_memzero(plain, plainLen);
    free(plain);

    return 0;
}

unsigned char* nk_encode_error(const unsigned char errOpcode, const int errCode, const unsigned char txKey[NK_X25519_KEY_SIZE], unsigned int* frameSize){
    if (!txKey || !frameSize)
        return NULL;

    int plainLen = 5;
    unsigned char* plain = malloc(plainLen);
    if (!plain)
        return NULL;

    unsigned char* p = plain;

    p += nk_encode_u8(p, errOpcode);
    p += nk_encode_s32(p, errCode);

    unsigned int payloadLen = 0;
    unsigned char* payload = nk_encrypt_payload(txKey, plain, p - plain, &payloadLen);

    free(plain);

    if (!payload)
        return NULL;

    unsigned int totalLen = NK_HEADER_SIZE + payloadLen;

    unsigned char* frame = malloc(totalLen);
    if (!frame) {
        free(payload);
        return NULL;
    }

    nk_encode_header(frame, totalLen, NK_OPCODE_ERROR, payloadLen);
    memcpy(frame + NK_HEADER_SIZE, payload, payloadLen);

    free(payload);
    *frameSize = totalLen;

    return frame;
}

int nk_decode_error(const unsigned char* frame, const unsigned int frameSize, const unsigned char rxKey[NK_X25519_KEY_SIZE], 
                  unsigned char *errOpcode, int* errCode){
    if (!frame || !rxKey || !errOpcode || !errCode){
        return -1;
    }

    unsigned char opcode = 0;
    unsigned int payloadLen = 0;
    if(nk_decode_header(frame, frameSize, &opcode, &payloadLen) != 0){
        return -1;
    }

    if (opcode != NK_OPCODE_ERROR){
        return -1;
    }

    unsigned char* plain = malloc(payloadLen);
    if (!plain)
        return -1;

    unsigned int plainLen = 0;
    if (nk_decrypt_payload(rxKey, frame + NK_HEADER_SIZE, payloadLen, plain, &plainLen) != 0) {
        free(plain);
        return -1;
    }

    const unsigned char* p = plain;
    p += nk_decode_u8(p, errOpcode);
    p += nk_decode_s32(p, errCode);

    sodium_memzero(plain, plainLen);
    free(plain);

    return 0;
}
unsigned char* nk_encode_register(const char username[NK_MAX_USERNAME_SIZE], const unsigned short usernameLen, const char password[NK_MAX_PASSWD_SIZE], const unsigned short passwordLen,
                                  const unsigned char txKey[NK_X25519_KEY_SIZE], unsigned int* frameSize)
{
    if (!username || !password || !txKey || !frameSize)
        return NULL;

    unsigned char salt[NK_SALT_SIZE];
    unsigned char hash[NK_HASH_SIZE];

    unsigned char umk[NK_X25519_KEY_SIZE];
    unsigned char kdfKey[NK_X25519_KEY_SIZE];

    randombytes_buf(salt, NK_SALT_SIZE);
    randombytes_buf(umk, NK_X25519_KEY_SIZE);

    if (nk_crypto_pwhash(password, passwordLen, salt, hash) != 0)
    {
        return NULL;
    }

    if (nk_crypto_pwhash(password, passwordLen, salt, kdfKey) != 0)
    {
        sodium_memzero(hash, NK_HASH_SIZE);
        return NULL;
    }

    unsigned int umkEncSize = 0;
    unsigned char* umkEnc = nk_encrypt_payload(
        kdfKey,
        umk,
        NK_X25519_KEY_SIZE,
        &umkEncSize
    );

    if (!umkEnc) {
        sodium_memzero(hash, NK_HASH_SIZE);
        sodium_memzero(kdfKey, NK_X25519_KEY_SIZE);
        return NULL;
    }

    unsigned int plainLen = 2 + usernameLen + NK_SALT_SIZE + NK_HASH_SIZE + umkEncSize;

    unsigned char* plain = malloc(plainLen);
    if (!plain) {
        free(umkEnc);
        sodium_memzero(hash, NK_HASH_SIZE);
        sodium_memzero(kdfKey, NK_X25519_KEY_SIZE);
        return NULL;
    }

    unsigned char* p = plain;

    p += nk_encode_u16(p, usernameLen);
    p += nk_encode_bytes(p, username, usernameLen);

    p += nk_encode_bytes(p, salt, NK_SALT_SIZE);
    p += nk_encode_bytes(p, hash, NK_HASH_SIZE);

    p += nk_encode_bytes(p, umkEnc, umkEncSize);

    if ((unsigned int)(p - plain) != plainLen) {
        free(umkEnc);
        sodium_memzero(plain, plainLen);
        sodium_memzero(hash, NK_HASH_SIZE);
        sodium_memzero(kdfKey, NK_X25519_KEY_SIZE);
        free(plain);
        return NULL;
    }

    unsigned int payloadLen = 0;
    unsigned char* payload = nk_encrypt_payload(txKey, plain, plainLen, &payloadLen);

    sodium_memzero(plain, plainLen);
    sodium_memzero(umk, NK_X25519_KEY_SIZE);
    sodium_memzero(kdfKey, NK_X25519_KEY_SIZE);
    sodium_memzero(hash, NK_HASH_SIZE);

    free(plain);
    free(umkEnc);

    if (!payload)
        return NULL;

    unsigned int totalLen = NK_HEADER_SIZE + payloadLen;

    unsigned char* frame = malloc(totalLen);
    if (!frame) {
        free(payload);
        return NULL;
    }

    if (nk_encode_header(frame, totalLen, NK_OPCODE_REGISTER, payloadLen) != 0) {
        free(payload);
        free(frame);
        return NULL;
    }

    memcpy(frame + NK_HEADER_SIZE, payload, payloadLen);

    free(payload);
    *frameSize = totalLen;

    return frame;
}


int nk_decode_register(const unsigned char* frame, const unsigned int frameSize, const unsigned char rxKey[NK_X25519_KEY_SIZE], char username[NK_MAX_USERNAME_SIZE], unsigned short* usernameLen,
                       unsigned char salt[NK_SALT_SIZE], unsigned char passwdHash[NK_HASH_SIZE], unsigned char umkNonce[NK_NONCE_SIZE], unsigned char umkCipher[NK_X25519_KEY_SIZE + NK_MAC_SIZE])
{
    if (!frame || !rxKey || !username || !usernameLen ||
        !salt || !passwdHash || !umkNonce || !umkCipher)
        return -1;

    unsigned char opcode = 0;
    unsigned int payloadLen = 0;

    if (nk_decode_header(frame, frameSize, &opcode, &payloadLen) != 0)
        return -1;

    if (opcode != NK_OPCODE_REGISTER)
        return -1;

    const unsigned char* payload = frame + NK_HEADER_SIZE;

    unsigned char* plain = malloc(payloadLen);
    if (!plain)
        return -1;

    unsigned int plainLen = 0;

    if (nk_decrypt_payload(rxKey, payload, payloadLen, plain, &plainLen) != 0) {
        free(plain);
        return -1;
    }

    const unsigned char* p = plain;

    unsigned short uLen = 0;
    p += nk_decode_u16(p, &uLen);

    if (uLen > NK_MAX_USERNAME_SIZE) {
        free(plain);
        return -1;
    }

    unsigned int expected = 2 + uLen + NK_SALT_SIZE + NK_HASH_SIZE + NK_NONCE_SIZE + (NK_X25519_KEY_SIZE + NK_MAC_SIZE);

    if (plainLen != expected) {
        free(plain);
        return -1;
    }

    p += nk_decode_bytes(p, username, uLen);
    *usernameLen = uLen;

    p += nk_decode_bytes(p, salt, NK_SALT_SIZE);
    p += nk_decode_bytes(p, passwdHash, NK_HASH_SIZE);
    p += nk_decode_bytes(p, umkNonce, NK_NONCE_SIZE);
    p += nk_decode_bytes(p, umkCipher, NK_X25519_KEY_SIZE + NK_MAC_SIZE);

    sodium_memzero(plain, plainLen);
    free(plain);

    return 0;
}

unsigned char* nk_encode_request_salt(const char username[NK_MAX_USERNAME_SIZE], const unsigned short usernameLen, 
                                      const unsigned char txKey[NK_X25519_KEY_SIZE], unsigned int* frameSize){
    if (!username || !txKey || !frameSize)
        return NULL;

    int plainLen = 2 + usernameLen;

    unsigned char* plain = malloc(plainLen);
    if (!plain)
        return NULL;

    unsigned char* p = plain;
    p += nk_encode_u16(p, usernameLen);
    p += nk_encode_bytes(p, username, (unsigned)usernameLen);

    unsigned int payloadLen = 0;
    unsigned char* payload = nk_encrypt_payload(txKey, plain, p - plain, &payloadLen);

    free(plain);

    if (!payload)
        return NULL;

    unsigned int totalLen = NK_HEADER_SIZE + payloadLen;

    unsigned char* frame = malloc(totalLen);
    if (!frame) {
        free(payload);
        return NULL;
    }

    nk_encode_header(frame, totalLen, NK_OPCODE_REQUEST_SALT, payloadLen);
    memcpy(frame + NK_HEADER_SIZE, payload, payloadLen);

    free(payload);
    *frameSize = totalLen;

    return frame;
}

int nk_decode_request_salt(const unsigned char* frame, const unsigned int frameSize, const unsigned char rxKey[NK_X25519_KEY_SIZE],
                           char username[NK_MAX_USERNAME_SIZE], unsigned short* usernameLen){
    if (!frame || !rxKey || !username || !usernameLen){
        return -1;
    }

    unsigned char opcode = 0;
    unsigned int payloadLen = 0;
    if(nk_decode_header(frame, frameSize, &opcode, &payloadLen) != 0){
        return -1;
    }

    if (opcode != NK_OPCODE_REQUEST_SALT){
        return -1;
    }

    unsigned char* plain = malloc(payloadLen);
    if (!plain)
        return -1;

    unsigned int plainLen = 0;
    if (nk_decrypt_payload(rxKey, frame + NK_HEADER_SIZE, payloadLen, plain, &plainLen) != 0) {
        free(plain);
        return -1;
    }

    const unsigned char* p = plain;

    unsigned short uLen = 0;
    p += nk_decode_u16(p, &uLen);

    if (uLen > NK_MAX_USERNAME_SIZE) {
        sodium_memzero(plain, plainLen);
        free(plain);
        return -1;
    }

    p += nk_decode_bytes(p, username, uLen);
    *usernameLen = uLen;

    sodium_memzero(plain, plainLen);
    free(plain);

    return 0;
}

unsigned char* nk_encode_request_salt_result(const unsigned char saltBytes[NK_SALT_SIZE], const unsigned char txKey[NK_X25519_KEY_SIZE], unsigned int* frameSize)
{
    if (!saltBytes || !txKey || !frameSize)
        return NULL;

    int plainLen = NK_SALT_SIZE;

    unsigned char* plain = malloc(plainLen);
    if (!plain)
        return NULL;

    unsigned char* p = plain;
    p += nk_encode_bytes(plain, saltBytes, NK_SALT_SIZE);

    unsigned int payloadLen = 0;
    unsigned char* payload = nk_encrypt_payload(txKey, plain, p - plain, &payloadLen);

    free(plain);

    if (!payload)
        return NULL;

    unsigned int totalLen = NK_HEADER_SIZE + payloadLen;

    unsigned char* frame = malloc(totalLen);
    if (!frame) {
        free(payload);
        return NULL;
    }

    nk_encode_header(frame, totalLen, NK_OPCODE_REQUEST_SALT_RESULT, payloadLen);
    memcpy(frame + NK_HEADER_SIZE, payload, payloadLen);

    free(payload);
    *frameSize = totalLen;

    return frame;
}

int nk_decode_request_salt_result(const unsigned char* frame, const unsigned int frameSize, const unsigned char rxKey[NK_X25519_KEY_SIZE], unsigned char saltBytes[NK_SALT_SIZE])
{
    if (!frame || !rxKey || !saltBytes)
        return -1;

    unsigned char opcode = 0;
    unsigned int payloadLen = 0;
    if(nk_decode_header(frame, frameSize, &opcode, &payloadLen) != 0){
        return -1;
    }

    if (opcode != NK_OPCODE_REQUEST_SALT_RESULT){
        return -1;
    }

    unsigned char* plain = malloc(payloadLen);
    if (!plain)
        return -1;

    unsigned int plainLen = 0;
    if (nk_decrypt_payload(rxKey, frame + NK_HEADER_SIZE, payloadLen, plain, &plainLen) != 0) {
        free(plain);
        return -1;
    }

    if (plainLen != NK_SALT_SIZE) {
        sodium_memzero(plain, plainLen);
        free(plain);
        return -1;
    }

    nk_decode_bytes(plain, saltBytes, NK_SALT_SIZE);
    sodium_memzero(plain, plainLen);
    free(plain);

    return 0;
}

unsigned char* nk_encode_login(const char username[NK_MAX_USERNAME_SIZE], const unsigned short usernameLen,
                               const char password[NK_MAX_PASSWD_SIZE], const unsigned short passwordLen,
                               const unsigned char saltBytes[NK_SALT_SIZE], const unsigned int deviceId, const unsigned char txKey[NK_X25519_KEY_SIZE], unsigned int* frameSize){
    if (!username || !password || !saltBytes || !txKey || !frameSize)
        return NULL;

    unsigned char hash[NK_HASH_SIZE];

    if (nk_crypto_pwhash(password, passwordLen, saltBytes, hash) != 0)
    {
        return NULL;
    }

    int plainLen = 6 + usernameLen + NK_HASH_SIZE;

    unsigned char* plain = malloc(plainLen);
    if (!plain)
        return NULL;

    unsigned char* p = plain;
    p += nk_encode_u16(p, usernameLen);
    p += nk_encode_bytes(p, username, (unsigned)usernameLen);
    p += nk_encode_bytes(p, hash, NK_HASH_SIZE);
    p += nk_encode_u32(p, deviceId);

    unsigned int payloadLen = 0;
    unsigned char* payload = nk_encrypt_payload(txKey, plain, p - plain, &payloadLen);

    free(plain);

    if (!payload)
        return NULL;

    unsigned int totalLen = NK_HEADER_SIZE + payloadLen;

    unsigned char* frame = malloc(totalLen);
    if (!frame) {
        free(payload);
        return NULL;
    }

    nk_encode_header(frame, totalLen, NK_OPCODE_LOGIN, payloadLen);
    memcpy(frame + NK_HEADER_SIZE, payload, payloadLen);

    free(payload);
    *frameSize = totalLen;

    return frame;
}

int nk_decode_login(const unsigned char* frame, const unsigned int frameSize, const unsigned char rxKey[NK_X25519_KEY_SIZE],
                     char username[NK_MAX_USERNAME_SIZE], unsigned short* usernameLen, unsigned char passwdHash[NK_HASH_SIZE], unsigned int* deviceId){
    if (!frame || !rxKey || !username || !usernameLen || !passwdHash || !deviceId){
        return -1;
    }

    unsigned char opcode = 0;
    unsigned int payloadLen = 0;
    if(nk_decode_header(frame, frameSize, &opcode, &payloadLen) != 0){
        return -1;
    }

    if (opcode != NK_OPCODE_LOGIN){
        return -1;
    }

    unsigned char* plain = malloc(payloadLen);
    if (!plain)
        return -1;

    unsigned int plainLen = 0;
    if (nk_decrypt_payload(rxKey, frame + NK_HEADER_SIZE, payloadLen, plain, &plainLen) != 0) {
        free(plain);
        return -1;
    }

    const unsigned char* p = plain;
    unsigned short uLen = 0;
    p += nk_decode_u16(p, &uLen);

    if (uLen > NK_MAX_USERNAME_SIZE) {
        sodium_memzero(plain, plainLen);
        free(plain);
        return -1;
    }

    *usernameLen = uLen;
    p += nk_decode_bytes(p, username, *usernameLen);
    p += nk_decode_bytes(p, passwdHash, NK_HASH_SIZE);
    p += nk_decode_u32(p, deviceId);

    sodium_memzero(plain, plainLen);
    free(plain);

    return 0;
}

unsigned char* nk_encode_login_result(const unsigned int userId, const unsigned int deviceId, const unsigned char umkNonce[NK_NONCE_SIZE], 
                                      const unsigned char umkCipher[NK_X25519_KEY_SIZE + NK_MAC_SIZE], const unsigned char txKey[NK_X25519_KEY_SIZE], unsigned int* frameSize)
{
    if (!txKey || !frameSize || !umkNonce || !umkCipher)
        return NULL;

    unsigned int plainLen = 4 + 4 + NK_NONCE_SIZE + (NK_X25519_KEY_SIZE + NK_MAC_SIZE);

    unsigned char plain[4 + NK_NONCE_SIZE + NK_X25519_KEY_SIZE + NK_MAC_SIZE];
    unsigned char* p = plain;

    p += nk_encode_u32(p, userId);
    p += nk_encode_u32(p, deviceId);
    p += nk_encode_bytes(p, umkNonce, NK_NONCE_SIZE);
    p += nk_encode_bytes(p, umkCipher, NK_X25519_KEY_SIZE + NK_MAC_SIZE);

    if ((unsigned int)(p - plain) != plainLen)
        return NULL;

    unsigned int payloadLen = 0;
    unsigned char* payload = nk_encrypt_payload(txKey, plain, plainLen, &payloadLen);
    if (!payload)
        return NULL;

    unsigned int totalLen = NK_HEADER_SIZE + payloadLen;

    unsigned char* frame = malloc(totalLen);
    if (!frame) {
        free(payload);
        return NULL;
    }

    if (nk_encode_header(frame, totalLen, NK_OPCODE_LOGIN_RESULT, payloadLen) != 0) {
        free(payload);
        free(frame);
        return NULL;
    }

    memcpy(frame + NK_HEADER_SIZE, payload, payloadLen);

    free(payload);
    *frameSize = totalLen;

    return frame;
}

int nk_decode_login_result(const unsigned char* frame, const unsigned int frameSize, const unsigned char rxKey[NK_X25519_KEY_SIZE], const char* password, const unsigned short passwordLen,
                           const unsigned char salt[NK_SALT_SIZE], unsigned int* userId, unsigned int* deviceId, unsigned char umk[NK_X25519_KEY_SIZE])
{
    if (!frame || !rxKey || !password || !salt || !userId || !umk)
        return -1;

    unsigned char opcode = 0;
    unsigned int payloadLen = 0;

    if (nk_decode_header(frame, frameSize, &opcode, &payloadLen) != 0)
        return -1;

    if (opcode != NK_OPCODE_LOGIN_RESULT)
        return -1;

    const unsigned char* payload = frame + NK_HEADER_SIZE;

    unsigned char* plain = malloc(payloadLen);
    if (!plain)
        return -1;

    unsigned int plainLen = 0;

    if (nk_decrypt_payload(rxKey, payload, payloadLen, plain, &plainLen) != 0) {
        free(plain);
        return -1;
    }

    const unsigned char* p = plain;

    unsigned char umkNonce[NK_NONCE_SIZE];
    unsigned char umkCipher[NK_X25519_KEY_SIZE + NK_MAC_SIZE];

    p += nk_decode_u32(p, userId);
    p += nk_decode_u32(p, deviceId);
    p += nk_decode_bytes(p, umkNonce, NK_NONCE_SIZE);
    p += nk_decode_bytes(p, umkCipher, NK_X25519_KEY_SIZE + NK_MAC_SIZE);

    unsigned char kdfKey[NK_X25519_KEY_SIZE];

    if (nk_crypto_pwhash(password, passwordLen, salt, kdfKey) != 0)
    {
        sodium_memzero(plain, plainLen);
        free(plain);
        return -1;
    }

    unsigned char cipherTextUMK[NK_NONCE_SIZE + NK_X25519_KEY_SIZE + NK_MAC_SIZE];

    memcpy(cipherTextUMK, umkNonce, NK_NONCE_SIZE);
    memcpy(cipherTextUMK + NK_NONCE_SIZE, umkCipher, NK_X25519_KEY_SIZE + NK_MAC_SIZE);

    unsigned int umkLen = 0;

    if (nk_decrypt_payload(kdfKey, cipherTextUMK, sizeof(cipherTextUMK), umk, &umkLen) != 0)
    {
        sodium_memzero(kdfKey, NK_X25519_KEY_SIZE);
        sodium_memzero(plain, plainLen);
        return -1;
    }

    sodium_memzero(kdfKey, NK_X25519_KEY_SIZE);
    sodium_memzero(plain, plainLen);
    free(plain);

    return 0;
}

unsigned char* nk_encode_logout(const unsigned char txKey[NK_X25519_KEY_SIZE], unsigned int* frameSize){
    if (!txKey || !frameSize)
        return NULL;

    unsigned int totalLen = NK_HEADER_SIZE;

    unsigned char* frame = malloc(totalLen);
    if (!frame) {
        return NULL;
    }

    nk_encode_header(frame, totalLen, NK_OPCODE_LOGOUT, 0);
    *frameSize = totalLen;

    return frame;
}

int nk_decode_logout(const unsigned char* frame, const unsigned int frameSize, const unsigned char rxKey[NK_X25519_KEY_SIZE]){
    if (!frame || !rxKey){
        return -1;
    }

    unsigned char opcode = 0;
    unsigned int payloadLen = 0;

    if (nk_decode_header(frame, frameSize, &opcode, &payloadLen) != 0)
        return -1;

    if (opcode != NK_OPCODE_LOGOUT)
        return -1;

    return 0;
}

unsigned char* nk_encode_unregister(const unsigned char txKey[NK_X25519_KEY_SIZE], unsigned int* frameSize){
    if (!txKey || !frameSize)
        return NULL;

    unsigned int totalLen = NK_HEADER_SIZE;

    unsigned char* frame = malloc(totalLen);
    if (!frame) {
        return NULL;
    }

    nk_encode_header(frame, totalLen, NK_OPCODE_UNREGISTER, 0);
    *frameSize = totalLen;

    return frame;
}

int nk_decode_unregister(const unsigned char* frame, const unsigned int frameSize, const unsigned char rxKey[NK_X25519_KEY_SIZE]){
    if (!frame || !rxKey){
        return -1;
    }

    unsigned char opcode = 0;
    unsigned int payloadLen = 0;

    if (nk_decode_header(frame, frameSize, &opcode, &payloadLen) != 0)
        return -1;

    if (opcode != NK_OPCODE_UNREGISTER)
        return -1;

    return 0;
}

unsigned char* nk_encode_register_new_device_keys(const unsigned int deviceId, const unsigned char x25519_pub[NK_X25519_KEY_SIZE], const unsigned char ed25519_pub[NK_X25519_KEY_SIZE], 
                                             const unsigned char txKey[NK_X25519_KEY_SIZE], unsigned int* frameSize)
{
    if (!x25519_pub || !ed25519_pub || !txKey || !frameSize)
        return NULL;

    unsigned int plainLen = 4 + 32 + 32;

    unsigned char plain[64];
    unsigned char* p = plain;

    p += nk_encode_u32(p, deviceId);
    p += nk_encode_bytes(p, x25519_pub, 32);
    p += nk_encode_bytes(p, ed25519_pub, 32);

    unsigned int cipherSize = 0;
    unsigned char* payload = nk_encrypt_payload(txKey, plain, plainLen, &cipherSize);

    if (!payload)
        return NULL;

    unsigned int totalLen = NK_HEADER_SIZE + cipherSize;

    unsigned char* frame = malloc(totalLen);
    if (!frame) {
        free(payload);
        return NULL;
    }

    if (nk_encode_header(frame, totalLen, NK_OPCODE_REGISTER_NEW_DEVICE_KEYS, cipherSize) != 0) {
        free(payload);
        free(frame);
        return NULL;
    }

    memcpy(frame + NK_HEADER_SIZE, payload, cipherSize);

    free(payload);
    *frameSize = totalLen;

    return frame;
}

int nk_decode_register_new_device_keys(const unsigned char* frame, const unsigned int frameSize, const unsigned char rxKey[NK_X25519_KEY_SIZE], 
                                       unsigned int* deviceId, unsigned char x25519_pub[NK_X25519_KEY_SIZE], unsigned char ed25519_pub[NK_X25519_KEY_SIZE])
{
    if (!frame || !rxKey || !deviceId || !x25519_pub || !ed25519_pub)
        return -1;

    unsigned char opcode = 0;
    unsigned int payloadLen = 0;

    if (nk_decode_header(frame, frameSize, &opcode, &payloadLen) != 0)
        return -1;

    if (opcode != NK_OPCODE_REGISTER_NEW_DEVICE_KEYS)
        return -1;

    const unsigned char* payload = frame + NK_HEADER_SIZE;

    unsigned char plain[4 + 64];
    unsigned int plainLen = 0;

    if (nk_decrypt_payload(rxKey, payload, payloadLen, plain, &plainLen) != 0)
        return -1;

    const unsigned char* p = plain;

    p += nk_decode_u32(p, deviceId);
    p += nk_decode_bytes(p, x25519_pub, 32);
    p += nk_decode_bytes(p, ed25519_pub, 32);

    return 0;
}

unsigned char* nk_encode_request_devices(const unsigned int deviceIds[NK_MAX_PAYLOAD_ARRAY_SIZE], const unsigned short deviceIdsLen, 
                                         const unsigned char txKey[NK_X25519_KEY_SIZE], unsigned int* frameSize)
{
    if (!deviceIds || !txKey || !frameSize)
        return NULL;

    unsigned int plainLen = 2 + deviceIdsLen * sizeof(unsigned int);

    unsigned char* plain = malloc(plainLen);
    if (!plain)
        return NULL;

    unsigned char* p = plain;
    p += nk_encode_u16(p, deviceIdsLen);
    p += nk_encode_bytes(p, (const char*)deviceIds, deviceIdsLen * sizeof(unsigned int));

    unsigned int cipherSize = 0;
    unsigned char* payload = nk_encrypt_payload(txKey, plain, 4, &cipherSize);

    if (!payload)
        return NULL;

    unsigned int totalLen = NK_HEADER_SIZE + cipherSize;

    unsigned char* frame = malloc(totalLen);
    if (!frame) {
        free(payload);
        return NULL;
    }

    if (nk_encode_header(frame, totalLen, NK_OPCODE_REQUEST_DEVICES, cipherSize) != 0) {
        free(payload);
        free(frame);
        return NULL;
    }

    memcpy(frame + NK_HEADER_SIZE, payload, cipherSize);

    free(payload);
    *frameSize = totalLen;

    return frame;
}

int nk_decode_request_devices(const unsigned char* frame, const unsigned int frameSize, const unsigned char rxKey[NK_X25519_KEY_SIZE], 
                              unsigned int deviceIds[NK_MAX_PAYLOAD_ARRAY_SIZE], unsigned short* deviceIdsLen)
{
    if (!frame || !rxKey || !deviceIds || !deviceIdsLen)
        return -1;

    unsigned char opcode = 0;
    unsigned int payloadLen = 0;

    if (nk_decode_header(frame, frameSize, &opcode, &payloadLen) != 0)
        return -1;

    if (opcode != NK_OPCODE_REQUEST_DEVICES)
        return -1;

    const unsigned char* payload = frame + NK_HEADER_SIZE;

    unsigned char* plain = malloc(payloadLen);
    if (!plain)
        return -1;

    unsigned int plainLen = 0;

    if (nk_decrypt_payload(rxKey, payload, payloadLen, plain, &plainLen) != 0) {
        free(plain);
        return -1;
    }

    const unsigned char* p = plain;
    p += nk_decode_u16(p, deviceIdsLen);
    p += nk_decode_bytes(p, (unsigned char*)deviceIds, *deviceIdsLen * sizeof(unsigned int));

    return 0;
}

unsigned char* nk_encode_request_user_devices(const unsigned int userIds[NK_MAX_PAYLOAD_ARRAY_SIZE], const unsigned short userIdsLen, 
                                              const unsigned char txKey[NK_X25519_KEY_SIZE], unsigned int* frameSize){
    if (!userIds || !txKey || !frameSize)
        return NULL;

    unsigned int plainLen = 2 + userIdsLen * sizeof(unsigned int);

    unsigned char* plain = malloc(plainLen);
    if (!plain)
        return NULL;

    unsigned char* p = plain;
    p += nk_encode_u16(p, userIdsLen);
    p += nk_encode_bytes(p, (unsigned char*)userIds, userIdsLen * sizeof(unsigned int));

    unsigned int cipherSize = 0;
    unsigned char* payload = nk_encrypt_payload(txKey, plain, plainLen, &cipherSize);

    if (!payload)
        return NULL;

    unsigned int totalLen = NK_HEADER_SIZE + cipherSize;

    unsigned char* frame = malloc(totalLen);
    if (!frame) {
        free(payload);
        return NULL;
    }

    if (nk_encode_header(frame, totalLen, NK_OPCODE_REQUEST_USER_DEVICES, cipherSize) != 0) {
        free(payload);
        free(frame);
        return NULL;
    }

    memcpy(frame + NK_HEADER_SIZE, payload, cipherSize);

    free(payload);
    free(plain);
    *frameSize = totalLen;

    return frame;
}

int nk_decode_request_user_devices(const unsigned char* frame, const unsigned int frameSize, const unsigned char rxKey[NK_X25519_KEY_SIZE], 
                                   unsigned int userIds[NK_MAX_PAYLOAD_ARRAY_SIZE], unsigned short* userIdsLen){
    if (!frame || !rxKey || !userIds || !userIdsLen)
        return -1;

    unsigned char opcode = 0;
    unsigned int payloadLen = 0;

    if (nk_decode_header(frame, frameSize, &opcode, &payloadLen) != 0)
        return -1;

    if (opcode != NK_OPCODE_REQUEST_USER_DEVICES)
        return -1;

    const unsigned char* payload = frame + NK_HEADER_SIZE;

    unsigned char* plain = malloc(payloadLen);
    if (!plain)
        return -1;

    unsigned int plainLen = 0;

    if (nk_decrypt_payload(rxKey, payload, payloadLen, plain, &plainLen) != 0) {
        free(plain);
        return -1;
    }

    const unsigned char* p = plain;
    p += nk_decode_u16(p, userIdsLen);
    p += nk_decode_bytes(p, (unsigned char*)userIds, *userIdsLen * sizeof(unsigned int));

    return 0;
}

unsigned char* nk_encode_request_devices_result(const NKDeviceData devices[NK_MAX_PAYLOAD_ARRAY_SIZE], const unsigned short devicesLen, 
                                                const unsigned char txKey[NK_X25519_KEY_SIZE], unsigned int* frameSize)
{
    if (!devices || !txKey || !frameSize)
        return NULL;

    unsigned int plainLen = 2 + devicesLen * sizeof(NKDeviceData);

    unsigned char* plain = malloc(plainLen);
    if (!plain)
        return NULL;

    unsigned char* p = plain;

    p += nk_encode_u16(p, devicesLen);
    p += nk_encode_bytes(p, (unsigned char*)devices, devicesLen * sizeof(NKDeviceData));

    unsigned int cipherSize = 0;
    unsigned char* payload = nk_encrypt_payload(txKey, plain, p - plain, &cipherSize);

    sodium_memzero(plain, p - plain);
    free(plain);

    if (!payload)
        return NULL;

    unsigned int totalLen = NK_HEADER_SIZE + cipherSize;

    unsigned char* frame = malloc(totalLen);
    if (!frame) {
        free(payload);
        return NULL;
    }

    if (nk_encode_header(frame, totalLen, NK_OPCODE_REQUEST_DEVICES_RESULT, cipherSize) != 0) {
        free(payload);
        free(frame);
        return NULL;
    }

    memcpy(frame + NK_HEADER_SIZE, payload, cipherSize);

    free(payload);
    *frameSize = totalLen;

    return frame;
}

int nk_decode_request_devices_result(const unsigned char* frame, const unsigned int frameSize, const unsigned char rxKey[NK_X25519_KEY_SIZE], 
                                     NKDeviceData devices[NK_MAX_PAYLOAD_ARRAY_SIZE], unsigned short* devicesLen)
{
    if (!frame || !rxKey || !devices || !devicesLen)
        return -1;

    unsigned char opcode = 0;
    unsigned int payloadLen = 0;

    if (nk_decode_header(frame, frameSize, &opcode, &payloadLen) != 0)
        return -1;

    if (opcode != NK_OPCODE_REQUEST_DEVICES_RESULT)
        return -1;

    const unsigned char* payload = frame + NK_HEADER_SIZE;

    unsigned char* plain = malloc(payloadLen);
    if (!plain)
        return -1;

    unsigned int plainLen = 0;

    if (nk_decrypt_payload(rxKey, payload, payloadLen, plain, &plainLen) != 0) {
        free(plain);
        return -1;
    }

    const unsigned char* p = plain;

    p += nk_decode_u16(p, devicesLen);

    if (*devicesLen > NK_MAX_PAYLOAD_ARRAY_SIZE) {
        free(plain);
        return -1;
    }

    p += nk_decode_bytes(p, (unsigned char*)devices, *devicesLen * sizeof(NKDeviceData));

    sodium_memzero(plain, plainLen);
    free(plain);

    return 0;
}

unsigned char* nk_encode_update_user_data_change_username_payload(const char username[NK_MAX_PASSWD_SIZE], const unsigned short usernameLen, unsigned short* userDataLen){
    if(!username || !userDataLen){
        return NULL;
    }

    int plainLen = 6 + usernameLen;
    unsigned char* plain = malloc(plainLen);
    if(!plain){
        return NULL;
    }
    unsigned char* p = plain;
    p += nk_encode_u32(p, NK_USERDATA_USERNAME);
    p += nk_encode_u16(p, usernameLen);
    p += nk_encode_bytes(p, username, usernameLen);
    *userDataLen = plainLen;

    return plain;
}

int nk_decode_update_user_data_change_username_payload(const unsigned char* payload, const unsigned short payloadLen, 
                                                       char username[NK_MAX_PASSWD_SIZE], unsigned short* usernameLen){
    if(!payload || !username || !usernameLen){
        return -1;
    }
    
    unsigned int dataCode = 0;
    unsigned char* p = payload;
    p += nk_decode_u32(p, &dataCode);
    if(dataCode != NK_USERDATA_USERNAME){
        return -1;
    }
    p += nk_decode_u16(p, usernameLen);
    p += nk_decode_bytes(p, username, *usernameLen);

    return 0;
}

unsigned char* nk_encode_update_user_data_change_password_payload(const char password[NK_MAX_PASSWD_SIZE], const unsigned short passwordLen, unsigned short* userDataLen){
    if (!password || !userDataLen)
        return NULL;

    unsigned char salt[NK_SALT_SIZE];
    unsigned char hash[NK_HASH_SIZE];

    randombytes_buf(salt, NK_SALT_SIZE);

    if (nk_crypto_pwhash(password, passwordLen, salt, hash) != 0)
    {
        return NULL;
    }

    int plainLen = 4 + NK_SALT_SIZE + NK_HASH_SIZE;
    unsigned char* plain = malloc(plainLen);
    if (!plain)
        return NULL;

    unsigned char* p = plain;
    p += nk_encode_u32(p, NK_USERDATA_PASSWORD);
    p += nk_encode_bytes(p, salt, NK_SALT_SIZE);
    p += nk_encode_bytes(p, hash, NK_HASH_SIZE);
    *userDataLen = plainLen;

    return plain;
}

int nk_decode_update_user_data_change_password_payload(const unsigned char* payload, const unsigned short payloadLen, 
                                                       unsigned char saltBytes[NK_SALT_SIZE], unsigned char passwdHash[NK_HASH_SIZE]){
    if(!payload || !saltBytes || !passwdHash){
        return -1;
    }
    
    unsigned int dataCode = 0;
    unsigned char* p = payload;
    p += nk_decode_u32(p, &dataCode);
    if(dataCode != NK_USERDATA_PASSWORD){
        return -1;
    }
    p += nk_decode_bytes(p, saltBytes, NK_SALT_SIZE);
    p += nk_decode_bytes(p, passwdHash, NK_HASH_SIZE);

    return 0;
}

unsigned char* nk_encode_update_user_data_change_tag_payload(unsigned short* userDataLen){
    if (!userDataLen)
        return NULL;

    int plainLen = 4;
    unsigned char* plain = malloc(plainLen);
    if (!plain)
        return NULL;

    unsigned char* p = plain;
    p += nk_encode_u32(p, NK_USERDATA_TAG);
    *userDataLen = plainLen;

    return plain;
}

int nk_decode_update_user_data_change_tag_payload(const unsigned char* payload, const unsigned short payloadLen){
    if(!payload){
        return -1;
    }
    
    unsigned int dataCode = 0;
    unsigned char* p = payload;
    p += nk_decode_u32(p, &dataCode);
    if(dataCode != NK_USERDATA_TAG){
        return -1;
    }
    return 0;
}

unsigned char* nk_encode_update_user_data(const unsigned char* userDataPayload, const unsigned short userDataLen, const unsigned char txKey[NK_X25519_KEY_SIZE], unsigned int* frameSize){
    if (!userDataPayload || !txKey || !frameSize)
        return NULL;

    int plainLen = 2 + userDataLen;

    unsigned char* plain = malloc(plainLen);
    if (!plain)
        return NULL;

    unsigned char* p = plain;
    p += nk_encode_u16(p, userDataLen);
    p += nk_encode_bytes(p, userDataPayload, userDataLen);

    unsigned int payloadLen = 0;
    unsigned char* payload = nk_encrypt_payload(txKey, plain, p - plain, &payloadLen);

    free(plain);

    if (!payload)
        return NULL;

    unsigned int totalLen = NK_HEADER_SIZE + payloadLen;

    unsigned char* frame = malloc(totalLen);
    if (!frame) {
        free(payload);
        return NULL;
    }

    nk_encode_header(frame, totalLen, NK_OPCODE_UPDATE_USER_DATA, payloadLen);
    memcpy(frame + NK_HEADER_SIZE, payload, payloadLen);

    free(payload);
    *frameSize = totalLen;

    return frame;
}

int nk_decode_update_user_data(const unsigned char* frame, const unsigned int frameSize, const unsigned char rxKey[NK_X25519_KEY_SIZE], 
                               unsigned int* userInfoType, unsigned char userDataPayload[NK_MAX_PAYLOAD_USERINFO_SIZE], unsigned short* userDataLen){
    if (!frame || !rxKey || !userInfoType || !userDataPayload || !userDataLen){
        return -1;
    }

    unsigned char opcode = 0;
    unsigned int payloadLen = 0;

    if (nk_decode_header(frame, frameSize, &opcode, &payloadLen) != 0)
        return -1;

    if (opcode != NK_OPCODE_UPDATE_USER_DATA)
        return -1;

    const unsigned char* payload = frame + NK_HEADER_SIZE;

    unsigned char* plain = malloc(payloadLen);
    if (!plain)
        return -1;

    unsigned int plainLen = 0;

    if (nk_decrypt_payload(rxKey, payload, payloadLen, plain, &plainLen) != 0) {
        free(plain);
        return -1;
    }

    const unsigned char* p = plain;
    p += nk_decode_u16(p, userDataLen);
    nk_decode_u32(p, userInfoType);
    p += nk_decode_bytes(p, userDataPayload, *userDataLen);

    sodium_memzero(plain, plainLen);
    free(plain);

    return 0;
}

unsigned char* nk_encode_sync_user_data(const NKUserData userData[NK_MAX_PAYLOAD_ARRAY_SIZE], const unsigned short userDataLen, const unsigned char txKey[NK_X25519_KEY_SIZE], unsigned int* frameSize){
    if (!userData || !txKey || !frameSize)
        return NULL;

    int plainLen = 2 + sizeof(NKUserData) * userDataLen;

    unsigned char* plain = malloc(plainLen);
    if (!plain)
        return NULL;

    unsigned char* p = plain;
    p += nk_encode_u16(p, userDataLen);
    p += nk_encode_bytes(p, (unsigned char*)userData, sizeof(NKUserData) * userDataLen);

    unsigned int payloadLen = 0;
    unsigned char* payload = nk_encrypt_payload(txKey, plain, p - plain, &payloadLen);

    free(plain);

    if (!payload)
        return NULL;

    unsigned int totalLen = NK_HEADER_SIZE + payloadLen;

    unsigned char* frame = malloc(totalLen);
    if (!frame) {
        free(payload);
        return NULL;
    }

    nk_encode_header(frame, totalLen, NK_OPCODE_SYNC_USER_DATA, payloadLen);
    memcpy(frame + NK_HEADER_SIZE, payload, payloadLen);

    free(payload);
    *frameSize = totalLen;

    return frame;
}

int nk_decode_sync_user_data(const unsigned char* frame, const unsigned int frameSize, const unsigned char rxKey[NK_X25519_KEY_SIZE],
                             NKUserData userData[NK_MAX_PAYLOAD_ARRAY_SIZE], unsigned short* userDataLen){
    if (!frame || !rxKey || !userData || !userDataLen){
        return -1;
    }

    unsigned char opcode = 0;
    unsigned int payloadLen = 0;

    if (nk_decode_header(frame, frameSize, &opcode, &payloadLen) != 0)
        return -1;

    if (opcode != NK_OPCODE_SYNC_USER_DATA)
        return -1;

    const unsigned char* payload = frame + NK_HEADER_SIZE;

    unsigned char* plain = malloc(payloadLen);
    if (!plain)
        return -1;

    unsigned int plainLen = 0;

    if (nk_decrypt_payload(rxKey, payload, payloadLen, plain, &plainLen) != 0) {
        free(plain);
        return -1;
    }

    const unsigned char* p = plain;
    p += nk_decode_u16(p, userDataLen);
    p += nk_decode_bytes(p, (unsigned char*)userData, *userDataLen * sizeof(NKUserData));

    sodium_memzero(plain, plainLen);
    free(plain);

    return 0;
}

unsigned char* nk_encode_friend_request(const char username[NK_MAX_USERNAME_SIZE], const unsigned short usernameLen, const unsigned int tag, const unsigned char txKey[NK_X25519_KEY_SIZE], unsigned int* frameSize){
    if (!txKey || !frameSize)
        return NULL;

    int plainLen = 6 + usernameLen;

    unsigned char* plain = malloc(plainLen);
    if (!plain)
        return NULL;

    unsigned char* p = plain;
    p += nk_encode_u16(p, usernameLen);
    p += nk_encode_bytes(p, username, usernameLen);
    p += nk_encode_u32(p, tag);

    unsigned int payloadLen = 0;
    unsigned char* payload = nk_encrypt_payload(txKey, plain, p - plain, &payloadLen);

    free(plain);

    if (!payload)
        return NULL;

    unsigned int totalLen = NK_HEADER_SIZE + payloadLen;

    unsigned char* frame = malloc(totalLen);
    if (!frame) {
        free(payload);
        return NULL;
    }

    nk_encode_header(frame, totalLen, NK_OPCODE_FRIEND_REQUEST, payloadLen);
    memcpy(frame + NK_HEADER_SIZE, payload, payloadLen);

    free(payload);
    *frameSize = totalLen;

    return frame;
}

int nk_decode_friend_request(const unsigned char* frame, const unsigned int frameSize, const unsigned char rxKey[NK_X25519_KEY_SIZE], 
                             char username[NK_MAX_USERNAME_SIZE], unsigned short* usernameLen, unsigned int* tag){
    
    if (!frame || !rxKey || !username || !usernameLen || !tag){
        return -1;
    }

    unsigned char opcode = 0;
    unsigned int payloadLen = 0;

    if (nk_decode_header(frame, frameSize, &opcode, &payloadLen) != 0)
        return -1;

    if (opcode != NK_OPCODE_FRIEND_REQUEST)
        return -1;

    const unsigned char* payload = frame + NK_HEADER_SIZE;

    unsigned char* plain = malloc(payloadLen);
    if (!plain)
        return -1;

    unsigned int plainLen = 0;

    if (nk_decrypt_payload(rxKey, payload, payloadLen, plain, &plainLen) != 0) {
        free(plain);
        return -1;
    }

    const unsigned char* p = plain;
    p += nk_decode_u16(p, usernameLen);
    p += nk_decode_bytes(p, (unsigned char*)username, *usernameLen);
    p += nk_decode_u32(p, tag);

    sodium_memzero(plain, plainLen);
    free(plain);

    return 0;
}

unsigned char* nk_encode_friend_request_update_status(const unsigned int requestId, const unsigned int statusCode, const unsigned char txKey[NK_X25519_KEY_SIZE], unsigned int* frameSize){
    if (!txKey || !frameSize)
        return NULL;

    int plainLen = 8;

    unsigned char* plain = malloc(plainLen);
    if (!plain)
        return NULL;

    unsigned char* p = plain;
    p += nk_encode_u32(p, requestId);
    p += nk_encode_u32(p, statusCode);

    unsigned int payloadLen = 0;
    unsigned char* payload = nk_encrypt_payload(txKey, plain, p - plain, &payloadLen);

    free(plain);

    if (!payload)
        return NULL;

    unsigned int totalLen = NK_HEADER_SIZE + payloadLen;

    unsigned char* frame = malloc(totalLen);
    if (!frame) {
        free(payload);
        return NULL;
    }

    nk_encode_header(frame, totalLen, NK_OPCODE_FRIEND_REQUEST_UPDATE_STATUS, payloadLen);
    memcpy(frame + NK_HEADER_SIZE, payload, payloadLen);

    free(payload);
    *frameSize = totalLen;

    return frame;
}

int nk_decode_friend_request_update_status(const unsigned char* frame, const unsigned int frameSize, const unsigned char rxKey[NK_X25519_KEY_SIZE], unsigned int* requestId, unsigned int* statusCode){
    if (!frame || !rxKey || !requestId || !statusCode){
        return -1;
    }

    unsigned char opcode = 0;
    unsigned int payloadLen = 0;

    if (nk_decode_header(frame, frameSize, &opcode, &payloadLen) != 0)
        return -1;

    if (opcode != NK_OPCODE_FRIEND_REQUEST_UPDATE_STATUS)
        return -1;

    const unsigned char* payload = frame + NK_HEADER_SIZE;

    unsigned char* plain = malloc(payloadLen);
    if (!plain)
        return -1;

    unsigned int plainLen = 0;

    if (nk_decrypt_payload(rxKey, payload, payloadLen, plain, &plainLen) != 0) {
        free(plain);
        return -1;
    }

    const unsigned char* p = plain;
    p += nk_decode_u32(p, requestId);
    p += nk_decode_u32(p, statusCode);

    sodium_memzero(plain, plainLen);
    free(plain);

    return 0;
}

unsigned char* nk_encode_user_relation_block(const unsigned int recipentId, const unsigned char txKey[NK_X25519_KEY_SIZE], unsigned int* frameSize){
    if (!txKey || !frameSize)
        return NULL;

    int plainLen = 4;

    unsigned char* plain = malloc(plainLen);
    if (!plain)
        return NULL;

    unsigned char* p = plain;
    p += nk_encode_u32(p, recipentId);

    unsigned int payloadLen = 0;
    unsigned char* payload = nk_encrypt_payload(txKey, plain, p - plain, &payloadLen);

    free(plain);

    if (!payload)
        return NULL;

    unsigned int totalLen = NK_HEADER_SIZE + payloadLen;

    unsigned char* frame = malloc(totalLen);
    if (!frame) {
        free(payload);
        return NULL;
    }

    nk_encode_header(frame, totalLen, NK_OPCODE_USER_RELATION_BLOCK, payloadLen);
    memcpy(frame + NK_HEADER_SIZE, payload, payloadLen);

    free(payload);
    *frameSize = totalLen;

    return frame;
}

int nk_decode_user_relation_block(const unsigned char* frame, const unsigned int frameSize, const unsigned char rxKey[NK_X25519_KEY_SIZE], unsigned int* recipentId){
    if (!frame || !rxKey || !recipentId){
        return -1;
    }

    unsigned char opcode = 0;
    unsigned int payloadLen = 0;

    if (nk_decode_header(frame, frameSize, &opcode, &payloadLen) != 0)
        return -1;

    if (opcode != NK_OPCODE_USER_RELATION_BLOCK)
        return -1;

    const unsigned char* payload = frame + NK_HEADER_SIZE;

    unsigned char* plain = malloc(payloadLen);
    if (!plain)
        return -1;

    unsigned int plainLen = 0;

    if (nk_decrypt_payload(rxKey, payload, payloadLen, plain, &plainLen) != 0) {
        free(plain);
        return -1;
    }

    const unsigned char* p = plain;
    p += nk_decode_u32(p, recipentId);

    sodium_memzero(plain, plainLen);
    free(plain);

    return 0;
}

unsigned char* nk_encode_user_relation_reset(const unsigned int recipentId, const unsigned char txKey[NK_X25519_KEY_SIZE], unsigned int* frameSize){
    if (!txKey || !frameSize)
        return NULL;

    int plainLen = 4;

    unsigned char* plain = malloc(plainLen);
    if (!plain)
        return NULL;

    unsigned char* p = plain;
    p += nk_encode_u32(p, recipentId);

    unsigned int payloadLen = 0;
    unsigned char* payload = nk_encrypt_payload(txKey, plain, p - plain, &payloadLen);

    free(plain);

    if (!payload)
        return NULL;

    unsigned int totalLen = NK_HEADER_SIZE + payloadLen;

    unsigned char* frame = malloc(totalLen);
    if (!frame) {
        free(payload);
        return NULL;
    }

    nk_encode_header(frame, totalLen, NK_OPCODE_USER_RELATION_RESET, payloadLen);
    memcpy(frame + NK_HEADER_SIZE, payload, payloadLen);

    free(payload);
    *frameSize = totalLen;

    return frame;
}

int nk_decode_user_relation_reset(const unsigned char* frame, const unsigned int frameSize, const unsigned char rxKey[NK_X25519_KEY_SIZE], unsigned int* recipentId){
    if (!frame || !rxKey || !recipentId){
        return -1;
    }

    unsigned char opcode = 0;
    unsigned int payloadLen = 0;

    if (nk_decode_header(frame, frameSize, &opcode, &payloadLen) != 0)
        return -1;

    if (opcode != NK_OPCODE_USER_RELATION_RESET)
        return -1;

    const unsigned char* payload = frame + NK_HEADER_SIZE;

    unsigned char* plain = malloc(payloadLen);
    if (!plain)
        return -1;

    unsigned int plainLen = 0;

    if (nk_decrypt_payload(rxKey, payload, payloadLen, plain, &plainLen) != 0) {
        free(plain);
        return -1;
    }

    const unsigned char* p = plain;
    p += nk_decode_u32(p, recipentId);

    sodium_memzero(plain, plainLen);
    free(plain);

    return 0;
}

unsigned char* nk_encode_sync_friend_requests(const NKFriendRequestData friendRequestData[NK_MAX_PAYLOAD_ARRAY_SIZE], const unsigned short friendRequestDataLen, const unsigned char txKey[NK_X25519_KEY_SIZE], unsigned int* frameSize){
    if (!friendRequestData || !txKey || !frameSize)
        return NULL;

    int plainLen = 2 + sizeof(NKFriendRequestData) * friendRequestDataLen;

    unsigned char* plain = malloc(plainLen);
    if (!plain)
        return NULL;

    unsigned char* p = plain;
    p += nk_encode_u16(p, friendRequestDataLen);
    p += nk_encode_bytes(p, (unsigned char*)friendRequestData, sizeof(NKFriendRequestData) * friendRequestDataLen);

    unsigned int payloadLen = 0;
    unsigned char* payload = nk_encrypt_payload(txKey, plain, p - plain, &payloadLen);

    free(plain);

    if (!payload)
        return NULL;

    unsigned int totalLen = NK_HEADER_SIZE + payloadLen;

    unsigned char* frame = malloc(totalLen);
    if (!frame) {
        free(payload);
        return NULL;
    }

    nk_encode_header(frame, totalLen, NK_OPCODE_SYNC_FRIEND_REQUESTS, payloadLen);
    memcpy(frame + NK_HEADER_SIZE, payload, payloadLen);

    free(payload);
    *frameSize = totalLen;

    return frame;
}

int nk_decode_sync_friend_requests(const unsigned char* frame, const unsigned int frameSize, const unsigned char rxKey[NK_X25519_KEY_SIZE],
                                       NKFriendRequestData friendRequestData[NK_MAX_PAYLOAD_ARRAY_SIZE], unsigned short* friendRequestDataLen){
    if (!frame || !rxKey || !friendRequestData || !friendRequestDataLen){
        return -1;
    }

    unsigned char opcode = 0;
    unsigned int payloadLen = 0;

    if (nk_decode_header(frame, frameSize, &opcode, &payloadLen) != 0)
        return -1;

    if (opcode != NK_OPCODE_SYNC_FRIEND_REQUESTS)
        return -1;

    const unsigned char* payload = frame + NK_HEADER_SIZE;

    unsigned char* plain = malloc(payloadLen);
    if (!plain)
        return -1;

    unsigned int plainLen = 0;

    if (nk_decrypt_payload(rxKey, payload, payloadLen, plain, &plainLen) != 0) {
        free(plain);
        return -1;
    }

    const unsigned char* p = plain;
    p += nk_decode_u16(p, friendRequestDataLen);
    p += nk_decode_bytes(p, (unsigned char*)friendRequestData, *friendRequestDataLen * sizeof(NKFriendRequestData));

    sodium_memzero(plain, plainLen);
    free(plain);

    return 0;
}

unsigned char* nk_encode_sync_relations(const NKUserRelationData userRelationData[NK_MAX_PAYLOAD_ARRAY_SIZE], const unsigned short userRelationDataLen, const unsigned char txKey[NK_X25519_KEY_SIZE], unsigned int* frameSize){
    if (!userRelationData || !txKey || !frameSize)
        return NULL;

    int plainLen = 2 + sizeof(NKUserRelationData) * userRelationDataLen;

    unsigned char* plain = malloc(plainLen);
    if (!plain)
        return NULL;

    unsigned char* p = plain;
    p += nk_encode_u16(p, userRelationDataLen);
    p += nk_encode_bytes(p, (unsigned char*)userRelationData, sizeof(NKUserRelationData) * userRelationDataLen);

    unsigned int payloadLen = 0;
    unsigned char* payload = nk_encrypt_payload(txKey, plain, p - plain, &payloadLen);

    free(plain);

    if (!payload)
        return NULL;

    unsigned int totalLen = NK_HEADER_SIZE + payloadLen;

    unsigned char* frame = malloc(totalLen);
    if (!frame) {
        free(payload);
        return NULL;
    }

    nk_encode_header(frame, totalLen, NK_OPCODE_SYNC_RELATIONS, payloadLen);
    memcpy(frame + NK_HEADER_SIZE, payload, payloadLen);

    free(payload);
    *frameSize = totalLen;

    return frame;
}

int nk_decode_sync_relations(const unsigned char* frame, const unsigned int frameSize, const unsigned char rxKey[NK_X25519_KEY_SIZE],
                                       NKUserRelationData userRelationData[NK_MAX_PAYLOAD_ARRAY_SIZE], unsigned short* userRelationDataLen){
    if (!frame || !rxKey || !userRelationData || !userRelationDataLen){
        return -1;
    }

    unsigned char opcode = 0;
    unsigned int payloadLen = 0;

    if (nk_decode_header(frame, frameSize, &opcode, &payloadLen) != 0)
        return -1;

    if (opcode != NK_OPCODE_SYNC_RELATIONS)
        return -1;

    const unsigned char* payload = frame + NK_HEADER_SIZE;

    unsigned char* plain = malloc(payloadLen);
    if (!plain)
        return -1;

    unsigned int plainLen = 0;

    if (nk_decrypt_payload(rxKey, payload, payloadLen, plain, &plainLen) != 0) {
        free(plain);
        return -1;
    }

    const unsigned char* p = plain;
    p += nk_decode_u16(p, userRelationDataLen);
    p += nk_decode_bytes(p, (unsigned char*)userRelationData, *userRelationDataLen * sizeof(NKUserRelationData));

    sodium_memzero(plain, plainLen);
    free(plain);

    return 0;
}

unsigned char* nk_encode_channel_request_recipents(const unsigned int channelId, const unsigned char txKey[NK_X25519_KEY_SIZE], unsigned int* frameSize){
    if (!txKey || !frameSize)
        return NULL;

    int plainLen = 4;

    unsigned char* plain = malloc(plainLen);
    if (!plain)
        return NULL;

    unsigned char* p = plain;
    p += nk_encode_u32(p, channelId);

    unsigned int payloadLen = 0;
    unsigned char* payload = nk_encrypt_payload(txKey, plain, p - plain, &payloadLen);

    free(plain);

    if (!payload)
        return NULL;

    unsigned int totalLen = NK_HEADER_SIZE + payloadLen;

    unsigned char* frame = malloc(totalLen);
    if (!frame) {
        free(payload);
        return NULL;
    }

    nk_encode_header(frame, totalLen, NK_OPCODE_CHANNEL_REQUEST_RECIPENTS, payloadLen);
    memcpy(frame + NK_HEADER_SIZE, payload, payloadLen);

    free(payload);
    *frameSize = totalLen;

    return frame;
}

int nk_decode_channel_request_recipents(const unsigned char* frame, const unsigned int frameSize, const unsigned char rxKey[NK_X25519_KEY_SIZE], unsigned int* channelId){
    if (!frame || !rxKey || !channelId){
        return -1;
    }

    unsigned char opcode = 0;
    unsigned int payloadLen = 0;

    if (nk_decode_header(frame, frameSize, &opcode, &payloadLen) != 0)
        return -1;

    if (opcode != NK_OPCODE_CHANNEL_REQUEST_RECIPENTS)
        return -1;

    const unsigned char* payload = frame + NK_HEADER_SIZE;

    unsigned char* plain = malloc(payloadLen);
    if (!plain)
        return -1;

    unsigned int plainLen = 0;

    if (nk_decrypt_payload(rxKey, payload, payloadLen, plain, &plainLen) != 0) {
        free(plain);
        return -1;
    }

    const unsigned char* p = plain;
    p += nk_decode_u32(p, channelId);

    sodium_memzero(plain, plainLen);
    free(plain);

    return 0;
}

unsigned char* nk_encode_channel_request_recipents_result(const unsigned int channelId, const unsigned int userIds[NK_MAX_PAYLOAD_ARRAY_SIZE], const unsigned short userIdsLen, 
                                                          const unsigned char txKey[NK_X25519_KEY_SIZE], unsigned int* frameSize){
    if (!txKey || !frameSize)
        return NULL;

    int plainLen = 6 + userIdsLen * sizeof(unsigned int);

    unsigned char* plain = malloc(plainLen);
    if (!plain)
        return NULL;

    unsigned char* p = plain;
    p += nk_encode_u32(p, channelId);
    p += nk_encode_u16(p, userIdsLen);
    p += nk_encode_bytes(p, (unsigned char*)userIds, sizeof(unsigned int) * userIdsLen);

    unsigned int payloadLen = 0;
    unsigned char* payload = nk_encrypt_payload(txKey, plain, p - plain, &payloadLen);

    free(plain);

    if (!payload)
        return NULL;

    unsigned int totalLen = NK_HEADER_SIZE + payloadLen;

    unsigned char* frame = malloc(totalLen);
    if (!frame) {
        free(payload);
        return NULL;
    }

    nk_encode_header(frame, totalLen, NK_OPCODE_CHANNEL_REQUEST_RECIPENTS_RESULT, payloadLen);
    memcpy(frame + NK_HEADER_SIZE, payload, payloadLen);

    free(payload);
    *frameSize = totalLen;

    return frame;
}
int nk_decode_channel_request_recipents_result(const unsigned char* frame, const unsigned int frameSize, const unsigned char rxKey[NK_X25519_KEY_SIZE], unsigned int* channelId,
                                               unsigned int userIds[NK_MAX_PAYLOAD_ARRAY_SIZE], unsigned short* userIdsLen){
    if (!frame || !rxKey || !channelId){
        return -1;
    }

    unsigned char opcode = 0;
    unsigned int payloadLen = 0;

    if (nk_decode_header(frame, frameSize, &opcode, &payloadLen) != 0)
        return -1;

    if (opcode != NK_OPCODE_CHANNEL_REQUEST_RECIPENTS_RESULT)
        return -1;

    const unsigned char* payload = frame + NK_HEADER_SIZE;

    unsigned char* plain = malloc(payloadLen);
    if (!plain)
        return -1;

    unsigned int plainLen = 0;

    if (nk_decrypt_payload(rxKey, payload, payloadLen, plain, &plainLen) != 0) {
        free(plain);
        return -1;
    }

    const unsigned char* p = plain;
    p += nk_decode_u32(p, channelId);
    p += nk_decode_u16(p, userIdsLen);
    p += nk_decode_bytes(p, (unsigned char*)userIds, sizeof(unsigned int) * *userIdsLen);

    sodium_memzero(plain, plainLen);
    free(plain);

    return 0;
}


unsigned char* nk_encode_channel_request_dm(const unsigned int userId, const unsigned char txKey[NK_X25519_KEY_SIZE], unsigned int* frameSize){
    if (!txKey || !frameSize)
        return NULL;

    int plainLen = 4;

    unsigned char* plain = malloc(plainLen);
    if (!plain)
        return NULL;

    unsigned char* p = plain;
    p += nk_encode_u32(p, userId);

    unsigned int payloadLen = 0;
    unsigned char* payload = nk_encrypt_payload(txKey, plain, p - plain, &payloadLen);

    free(plain);

    if (!payload)
        return NULL;

    unsigned int totalLen = NK_HEADER_SIZE + payloadLen;

    unsigned char* frame = malloc(totalLen);
    if (!frame) {
        free(payload);
        return NULL;
    }

    nk_encode_header(frame, totalLen, NK_OPCODE_CHANNEL_REQUEST_DM, payloadLen);
    memcpy(frame + NK_HEADER_SIZE, payload, payloadLen);

    free(payload);
    *frameSize = totalLen;

    return frame;
}

int nk_decode_channel_request_dm(const unsigned char* frame, const unsigned int frameSize, const unsigned char rxKey[NK_X25519_KEY_SIZE], unsigned int* userId){
    if (!frame || !rxKey || !userId){
        return -1;
    }

    unsigned char opcode = 0;
    unsigned int payloadLen = 0;

    if (nk_decode_header(frame, frameSize, &opcode, &payloadLen) != 0)
        return -1;

    if (opcode != NK_OPCODE_CHANNEL_REQUEST_DM)
        return -1;

    const unsigned char* payload = frame + NK_HEADER_SIZE;

    unsigned char* plain = malloc(payloadLen);
    if (!plain)
        return -1;

    unsigned int plainLen = 0;

    if (nk_decrypt_payload(rxKey, payload, payloadLen, plain, &plainLen) != 0) {
        free(plain);
        return -1;
    }

    const unsigned char* p = plain;
    p += nk_decode_u32(p, userId);

    sodium_memzero(plain, plainLen);
    free(plain);

    return 0;
}

unsigned char* nk_encode_channel_request_dm_result(const unsigned int userId, const unsigned int channelId, const unsigned char txKey[NK_X25519_KEY_SIZE], unsigned int* frameSize){
    if (!txKey || !frameSize)
        return NULL;

    int plainLen = 8;

    unsigned char* plain = malloc(plainLen);
    if (!plain)
        return NULL;

    unsigned char* p = plain;
    p += nk_encode_u32(p, userId);
    p += nk_encode_u32(p, channelId);

    unsigned int payloadLen = 0;
    unsigned char* payload = nk_encrypt_payload(txKey, plain, p - plain, &payloadLen);

    free(plain);

    if (!payload)
        return NULL;

    unsigned int totalLen = NK_HEADER_SIZE + payloadLen;

    unsigned char* frame = malloc(totalLen);
    if (!frame) {
        free(payload);
        return NULL;
    }

    nk_encode_header(frame, totalLen, NK_OPCODE_CHANNEL_REQUEST_DM_RESULT, payloadLen);
    memcpy(frame + NK_HEADER_SIZE, payload, payloadLen);

    free(payload);
    *frameSize = totalLen;

    return frame;
}

int nk_decode_channel_request_dm_result(const unsigned char* frame, const unsigned int frameSize, const unsigned char rxKey[NK_X25519_KEY_SIZE], unsigned int* userId, unsigned int* channelId){
    if (!frame || !rxKey || !userId || !channelId){
        return -1;
    }

    unsigned char opcode = 0;
    unsigned int payloadLen = 0;

    if (nk_decode_header(frame, frameSize, &opcode, &payloadLen) != 0)
        return -1;

    if (opcode != NK_OPCODE_CHANNEL_REQUEST_DM_RESULT)
        return -1;

    const unsigned char* payload = frame + NK_HEADER_SIZE;

    unsigned char* plain = malloc(payloadLen);
    if (!plain)
        return -1;

    unsigned int plainLen = 0;

    if (nk_decrypt_payload(rxKey, payload, payloadLen, plain, &plainLen) != 0) {
        free(plain);
        return -1;
    }

    const unsigned char* p = plain;
    p += nk_decode_u32(p, userId);
    p += nk_decode_u32(p, channelId);

    sodium_memzero(plain, plainLen);
    free(plain);

    return 0;
}

unsigned char* nk_encode_channel_submit_key(const unsigned int channelId, const NKChannelSubmitDeviceInput devices[NK_MAX_PAYLOAD_ARRAY_SIZE], const unsigned short deviceCount, 
                                            const unsigned char umk[NK_X25519_KEY_SIZE], const unsigned char ed25519_sk[NK_ED25519_SECRET_KEY_SIZE],
                                            const unsigned char txKey[NK_X25519_KEY_SIZE], unsigned int* frameSize)
{
    if (!devices || !umk || !ed25519_sk || !txKey || !frameSize)
        return NULL;

    unsigned char ck[NK_X25519_KEY_SIZE];
    randombytes_buf(ck, NK_X25519_KEY_SIZE);

    NKChannelSubmitDeviceKey outKeys[NK_MAX_PAYLOAD_ARRAY_SIZE];

    for (unsigned short i = 0; i < deviceCount; i++) {
        unsigned int size = 0;

        unsigned char* enc = nk_encrypt_payload(devices[i].sharedSecret, ck, NK_X25519_KEY_SIZE, &size);

        if (!enc)
            return NULL;

        if (size > NK_MAX_ENCRYPTED_KEY_SIZE) {
            free(enc);
            return NULL;
        }

        outKeys[i].targetDeviceId = devices[i].targetDeviceId;
        outKeys[i].encryptedKeySize = size;
        memcpy(outKeys[i].encryptedKey, enc, size);

        free(enc);
    }

    unsigned int umkKeySize = 0;
    unsigned char* umkKey = nk_encrypt_payload(
        umk,
        ck,
        NK_X25519_KEY_SIZE,
        &umkKeySize
    );

    if (!umkKey)
        return NULL;

    unsigned int plainLen = 4 + 2 + 2 + umkKeySize + NK_ED25519_SIG_SIZE;

    for (unsigned short i = 0; i < deviceCount; i++) {
        plainLen += 4 + 2 + outKeys[i].encryptedKeySize;
    }

    unsigned char* plain = malloc(plainLen);
    if (!plain) {
        free(umkKey);
        return NULL;
    }

    unsigned char* p = plain;

    p += nk_encode_u32(p, channelId);
    p += nk_encode_u16(p, deviceCount);

    for (unsigned short i = 0; i < deviceCount; i++) {
        NKChannelSubmitDeviceKey* k = &outKeys[i];

        p += nk_encode_u32(p, k->targetDeviceId);
        p += nk_encode_u16(p, k->encryptedKeySize);
        p += nk_encode_bytes(p, k->encryptedKey, k->encryptedKeySize);
    }

    p += nk_encode_u16(p, umkKeySize);
    p += nk_encode_bytes(p, umkKey, umkKeySize);

    unsigned int signedLen = p - plain;

    unsigned char signature[NK_ED25519_SIG_SIZE];

    crypto_sign_detached(signature, NULL, plain, signedLen, ed25519_sk);

    p += nk_encode_bytes(p, signature, NK_ED25519_SIG_SIZE);

    unsigned int payloadLen = 0;
    unsigned char* payload = nk_encrypt_payload(txKey, plain, p - plain, &payloadLen);

    sodium_memzero(plain, p - plain);
    sodium_memzero(ck, NK_X25519_KEY_SIZE);

    free(plain);
    free(umkKey);

    if (!payload)
        return NULL;

    unsigned int totalLen = NK_HEADER_SIZE + payloadLen;

    unsigned char* frame = malloc(totalLen);
    if (!frame) {
        free(payload);
        return NULL;
    }

    if (nk_encode_header(frame, totalLen, NK_OPCODE_CHANNEL_SUBMIT_KEY, payloadLen) != 0) {
        free(payload);
        free(frame);
        return NULL;
    }

    memcpy(frame + NK_HEADER_SIZE, payload, payloadLen);

    free(payload);
    *frameSize = totalLen;

    return frame;
}

int nk_decode_channel_submit_key(const unsigned char* frame, const unsigned int frameSize, const unsigned char rxKey[NK_X25519_KEY_SIZE], unsigned int* channelId,
                                 NKChannelSubmitDeviceKey deviceKeys[NK_MAX_PAYLOAD_ARRAY_SIZE], unsigned short* deviceKeysLen, unsigned char umkEncryptedKey[NK_MAX_ENCRYPTED_KEY_SIZE],
                                 unsigned short* umkKeySize)
{
    if (!frame || !rxKey || !channelId || !deviceKeys || !deviceKeysLen || !umkEncryptedKey || !umkKeySize)
        return -1;

    unsigned char opcode = 0;
    unsigned int payloadLen = 0;

    if (nk_decode_header(frame, frameSize, &opcode, &payloadLen) != 0)
        return -1;

    if (opcode != NK_OPCODE_CHANNEL_SUBMIT_KEY)
        return -1;

    const unsigned char* payload = frame + NK_HEADER_SIZE;

    unsigned char* plain = malloc(payloadLen);
    if (!plain)
        return -1;

    unsigned int plainLen = 0;

    if (nk_decrypt_payload(rxKey, payload, payloadLen, plain, &plainLen) != 0) {
        free(plain);
        return -1;
    }

    const unsigned char* p = plain;
    const unsigned char* end = plain + plainLen;

    p += nk_decode_u32(p, channelId);
    p += nk_decode_u16(p, deviceKeysLen);

    if (*deviceKeysLen > NK_MAX_PAYLOAD_ARRAY_SIZE)
        goto fail;

    for (unsigned short i = 0; i < *deviceKeysLen; i++) {
        NKChannelSubmitDeviceKey* k = &deviceKeys[i];

        p += nk_decode_u32(p, &k->targetDeviceId);
        p += nk_decode_u16(p, &k->encryptedKeySize);
        if (k->encryptedKeySize > NK_MAX_ENCRYPTED_KEY_SIZE)
            goto fail;

        p += nk_decode_bytes(p, k->encryptedKey, k->encryptedKeySize);
    }

    p += nk_decode_u16(p, umkKeySize);

    if (*umkKeySize > NK_MAX_ENCRYPTED_KEY_SIZE)
        goto fail;

    p += nk_decode_bytes(p, umkEncryptedKey, *umkKeySize);

    unsigned char signature[NK_ED25519_SIG_SIZE];
    p += nk_decode_bytes(p, signature, NK_ED25519_SIG_SIZE);

    sodium_memzero(plain, plainLen);
    free(plain);

    return 0;

fail:
    sodium_memzero(plain, plainLen);
    free(plain);
    return -1;
}

unsigned char* nk_encode_channel_submit_key_result(const unsigned int channelId, const unsigned int keyVersion, const unsigned char umkEncryptedKey[NK_MAX_ENCRYPTED_KEY_SIZE],
                                                   const unsigned short umkKeySize, const unsigned char txKey[NK_X25519_KEY_SIZE], unsigned int* frameSize){
    if (!txKey || !frameSize)
        return NULL;

    int plainLen = 10 + umkKeySize;

    unsigned char* plain = malloc(plainLen);
    if (!plain)
        return NULL;

    unsigned char* p = plain;
    p += nk_encode_u32(p, channelId);
    p += nk_encode_u32(p, keyVersion);
    p += nk_encode_u16(p, umkKeySize);
    p += nk_encode_bytes(p, umkEncryptedKey, umkKeySize);

    unsigned int payloadLen = 0;
    unsigned char* payload = nk_encrypt_payload(txKey, plain, p - plain, &payloadLen);

    free(plain);

    if (!payload)
        return NULL;

    unsigned int totalLen = NK_HEADER_SIZE + payloadLen;

    unsigned char* frame = malloc(totalLen);
    if (!frame) {
        free(payload);
        return NULL;
    }

    nk_encode_header(frame, totalLen, NK_OPCODE_CHANNEL_SUBMIT_KEY_RESULT, payloadLen);
    memcpy(frame + NK_HEADER_SIZE, payload, payloadLen);

    free(payload);
    *frameSize = totalLen;

    return frame;
}

int nk_decode_channel_submit_key_result(const unsigned char* frame, const unsigned int frameSize, const unsigned char rxKey[NK_X25519_KEY_SIZE], unsigned int* channelId,
                                        unsigned int* keyVersion, unsigned char umkEncryptedKey[NK_MAX_ENCRYPTED_KEY_SIZE], unsigned short* umkKeySize){
    if (!frame || !rxKey || !channelId || !umkEncryptedKey || !umkKeySize){
        return -1;
    }

    unsigned char opcode = 0;
    unsigned int payloadLen = 0;

    if (nk_decode_header(frame, frameSize, &opcode, &payloadLen) != 0)
        return -1;

    if (opcode != NK_OPCODE_CHANNEL_REQUEST_DM)
        return -1;

    const unsigned char* payload = frame + NK_HEADER_SIZE;

    unsigned char* plain = malloc(payloadLen);
    if (!plain)
        return -1;

    unsigned int plainLen = 0;

    if (nk_decrypt_payload(rxKey, payload, payloadLen, plain, &plainLen) != 0) {
        free(plain);
        return -1;
    }

    const unsigned char* p = plain;
    p += nk_decode_u32(p, channelId);
    p += nk_decode_u32(p, keyVersion);
    p += nk_decode_u16(p, umkKeySize);
    p += nk_decode_bytes(p, umkEncryptedKey, *umkKeySize);

    sodium_memzero(plain, plainLen);
    free(plain);

    return 0;
}

unsigned char* nk_encode_channel_backup_keys(const NKChannelBackupKeyInput keys[NK_MAX_PAYLOAD_ARRAY_SIZE],const unsigned short keysLen, const unsigned char umk[NK_X25519_KEY_SIZE],
                                             const unsigned char txKey[NK_X25519_KEY_SIZE], unsigned int* frameSize)
{
    if (!keys || !umk || !txKey || !frameSize)
        return NULL;

    unsigned char encKeys[NK_MAX_PAYLOAD_ARRAY_SIZE][NK_MAX_ENCRYPTED_KEY_SIZE];
    unsigned short encSizes[NK_MAX_PAYLOAD_ARRAY_SIZE];

    for (unsigned short i = 0; i < keysLen; i++) {
        unsigned int size = 0;

        unsigned char* enc = nk_encrypt_payload(
            umk,
            keys[i].channelKey,
            NK_X25519_KEY_SIZE,
            &size
        );

        if (!enc)
            return NULL;

        if (size > NK_MAX_ENCRYPTED_KEY_SIZE) {
            free(enc);
            return NULL;
        }

        memcpy(encKeys[i], enc, size);
        encSizes[i] = size;

        free(enc);
    }

    unsigned int plainLen = 2;

    for (unsigned short i = 0; i < keysLen; i++) {
        plainLen += 4 + 2 + encSizes[i];
    }

    unsigned char* plain = malloc(plainLen);
    if (!plain)
        return NULL;

    unsigned char* p = plain;

    p += nk_encode_u16(p, keysLen);

    for (unsigned short i = 0; i < keysLen; i++) {
        p += nk_encode_u32(p, keys[i].channelId);
        p += nk_encode_u16(p, encSizes[i]);
        p += nk_encode_bytes(p, encKeys[i], encSizes[i]);
    }

    unsigned int payloadLen = 0;
    unsigned char* payload = nk_encrypt_payload(txKey, plain, p - plain, &payloadLen);

    sodium_memzero(plain, p - plain);
    free(plain);

    if (!payload)
        return NULL;

    unsigned int totalLen = NK_HEADER_SIZE + payloadLen;

    unsigned char* frame = malloc(totalLen);
    if (!frame) {
        free(payload);
        return NULL;
    }

    if (nk_encode_header(frame, totalLen, NK_OPCODE_CHANNEL_BACKUP_KEY, payloadLen) != 0) {
        free(payload);
        free(frame);
        return NULL;
    }

    memcpy(frame + NK_HEADER_SIZE, payload, payloadLen);

    free(payload);
    *frameSize = totalLen;

    return frame;
}

int nk_decode_channel_backup_keys(const unsigned char* frame, const unsigned int frameSize, const unsigned char rxKey[NK_X25519_KEY_SIZE], 
                                  NKEncryptedChannelBackupKeyData keys[NK_MAX_PAYLOAD_ARRAY_SIZE], unsigned short* keysLen)
{
    if (!frame || !rxKey || !keys || !keysLen)
        return -1;

    unsigned char opcode;
    unsigned int payloadLen;

    if (nk_decode_header(frame, frameSize, &opcode, &payloadLen) != 0)
        return -1;

    if (opcode != NK_OPCODE_CHANNEL_BACKUP_KEY)
        return -1;

    unsigned char* plain = malloc(payloadLen);
    if (!plain)
        return -1;

    unsigned int plainLen = 0;

    if (nk_decrypt_payload(rxKey, frame + NK_HEADER_SIZE, payloadLen, plain, &plainLen) != 0) {
        free(plain);
        return -1;
    }

    const unsigned char* p = plain;

    p += nk_decode_u16(p, keysLen);

    if (*keysLen > NK_MAX_PAYLOAD_ARRAY_SIZE)
        goto fail;

    for (unsigned short i = 0; i < *keysLen; i++) {
        NKEncryptedChannelBackupKeyData* k = &keys[i];

        p += nk_decode_u32(p, &k->channelId);
        p += nk_decode_u32(p, &k->keyVersion);
        p += nk_decode_u16(p, &k->encryptedKeySize);

        if (k->encryptedKeySize > NK_MAX_ENCRYPTED_KEY_SIZE)
            goto fail;

        p += nk_decode_bytes(p, k->encryptedKey, k->encryptedKeySize);
    }

    sodium_memzero(plain, plainLen);
    free(plain);

    return 0;

fail:
    sodium_memzero(plain, plainLen);
    free(plain);
    return -1;
}

unsigned char* nk_encode_sync_channel_keys_request(const unsigned int channelId, const unsigned char txKey[NK_X25519_KEY_SIZE], unsigned int* frameSize){
    if (!txKey || !frameSize)
        return NULL;

    int plainLen = 4;

    unsigned char* plain = malloc(plainLen);
    if (!plain)
        return NULL;

    unsigned char* p = plain;
    p += nk_encode_u32(p, channelId);

    unsigned int payloadLen = 0;
    unsigned char* payload = nk_encrypt_payload(txKey, plain, p - plain, &payloadLen);

    free(plain);

    if (!payload)
        return NULL;

    unsigned int totalLen = NK_HEADER_SIZE + payloadLen;

    unsigned char* frame = malloc(totalLen);
    if (!frame) {
        free(payload);
        return NULL;
    }

    nk_encode_header(frame, totalLen, NK_OPCODE_SYNC_CHANNEL_KEYS_REQUEST, payloadLen);
    memcpy(frame + NK_HEADER_SIZE, payload, payloadLen);

    free(payload);
    *frameSize = totalLen;

    return frame;
}

int nk_decode_sync_channel_keys_request(const unsigned char* frame, const unsigned int frameSize, const unsigned char rxKey[NK_X25519_KEY_SIZE], unsigned int* channelId){
    if (!frame || !rxKey || !channelId){
        return -1;
    }

    unsigned char opcode = 0;
    unsigned int payloadLen = 0;

    if (nk_decode_header(frame, frameSize, &opcode, &payloadLen) != 0)
        return -1;

    if (opcode != NK_OPCODE_SYNC_CHANNEL_KEYS_REQUEST)
        return -1;

    const unsigned char* payload = frame + NK_HEADER_SIZE;

    unsigned char* plain = malloc(payloadLen);
    if (!plain)
        return -1;

    unsigned int plainLen = 0;

    if (nk_decrypt_payload(rxKey, payload, payloadLen, plain, &plainLen) != 0) {
        free(plain);
        return -1;
    }

    const unsigned char* p = plain;
    p += nk_decode_u32(p, channelId);

    sodium_memzero(plain, plainLen);
    free(plain);

    return 0;
}

unsigned char* nk_encode_sync_channel_keys(const unsigned int channelId, const NKChannelDeviceKeyData deviceKeys[NK_MAX_PAYLOAD_ARRAY_SIZE], const unsigned short deviceKeysLen,
                                           const NKChannelBackupKeyData backupKeys[NK_MAX_PAYLOAD_ARRAY_SIZE], const unsigned short backupKeysLen,
                                           const unsigned char txKey[NK_X25519_KEY_SIZE], unsigned int* frameSize)
{
    if (!txKey || !frameSize)
        return NULL;

    unsigned int plainLen = 4 + 2 + 2;

    for (unsigned short i = 0; i < deviceKeysLen; i++) {
        plainLen += 4 + 4 + 4 + 4 + 2 + deviceKeys[i].encryptedKeySize;
    }

    for (unsigned short i = 0; i < backupKeysLen; i++) {
        plainLen += 4 + 4 + 2 + backupKeys[i].encryptedKeySize;
    }

    unsigned char* plain = malloc(plainLen);
    if (!plain)
        return NULL;

    unsigned char* p = plain;

    p += nk_encode_u32(p, channelId);
    p += nk_encode_u16(p, deviceKeysLen);

    for (unsigned short i = 0; i < deviceKeysLen; i++) {
        const NKChannelDeviceKeyData* k = &deviceKeys[i];

        p += nk_encode_u32(p, k->keyVersion);
        p += nk_encode_u32(p, k->senderDeviceId);
        p += nk_encode_u32(p, k->targetDeviceId);

        p += nk_encode_u16(p, k->encryptedKeySize);
        p += nk_encode_bytes(p, k->encryptedKey, k->encryptedKeySize);
    }

    p += nk_encode_u16(p, backupKeysLen);

    for (unsigned short i = 0; i < backupKeysLen; i++) {
        const NKChannelBackupKeyData* k = &backupKeys[i];

        p += nk_encode_u32(p, k->keyVersion);

        p += nk_encode_u16(p, k->encryptedKeySize);
        p += nk_encode_bytes(p, k->encryptedKey, k->encryptedKeySize);
    }

    unsigned int payloadLen = 0;
    unsigned char* payload = nk_encrypt_payload(txKey, plain, p - plain, &payloadLen);

    sodium_memzero(plain, p - plain);
    free(plain);

    if (!payload)
        return NULL;

    unsigned int totalLen = NK_HEADER_SIZE + payloadLen;

    unsigned char* frame = malloc(totalLen);
    if (!frame) {
        free(payload);
        return NULL;
    }

    if (nk_encode_header(frame, totalLen, NK_OPCODE_SYNC_CHANNEL_KEYS, payloadLen) != 0) {
        free(payload);
        free(frame);
        return NULL;
    }

    memcpy(frame + NK_HEADER_SIZE, payload, payloadLen);

    free(payload);
    *frameSize = totalLen;

    return frame;
}
int nk_decode_sync_channel_keys(const unsigned char* frame, const unsigned int frameSize, const unsigned char rxKey[NK_X25519_KEY_SIZE], unsigned int* channelId, 
                                NKChannelDeviceKeyData deviceKeys[NK_MAX_PAYLOAD_ARRAY_SIZE], unsigned short* deviceKeysLen,
                                NKChannelBackupKeyData backupKeys[NK_MAX_PAYLOAD_ARRAY_SIZE], unsigned short* backupKeysLen)
{
    if (!frame || !rxKey || !deviceKeys || !deviceKeysLen ||
        !backupKeys || !backupKeysLen)
        return -1;

    unsigned char opcode = 0;
    unsigned int payloadLen = 0;

    if (nk_decode_header(frame, frameSize, &opcode, &payloadLen) != 0)
        return -1;

    if (opcode != NK_OPCODE_SYNC_CHANNEL_KEYS)
        return -1;

    const unsigned char* payload = frame + NK_HEADER_SIZE;

    unsigned char* plain = malloc(payloadLen);
    if (!plain)
        return -1;

    unsigned int plainLen = 0;

    if (nk_decrypt_payload(rxKey, payload, payloadLen, plain, &plainLen) != 0) {
        free(plain);
        return -1;
    }

    const unsigned char* p = plain;

    p += nk_decode_u32(p, channelId);
    p += nk_decode_u16(p, deviceKeysLen);

    if (*deviceKeysLen > NK_MAX_PAYLOAD_ARRAY_SIZE)
        goto fail;

    for (unsigned short i = 0; i < *deviceKeysLen; i++) {
        NKChannelDeviceKeyData* k = &deviceKeys[i];

        p += nk_decode_u32(p, &k->keyVersion);
        p += nk_decode_u32(p, &k->senderDeviceId);
        p += nk_decode_u32(p, &k->targetDeviceId);

        p += nk_decode_u16(p, &k->encryptedKeySize);

        if (k->encryptedKeySize > NK_MAX_ENCRYPTED_KEY_SIZE)
            goto fail;

        p += nk_decode_bytes(p, k->encryptedKey, k->encryptedKeySize);
    }

    p += nk_decode_u16(p, backupKeysLen);

    if (*backupKeysLen > NK_MAX_PAYLOAD_ARRAY_SIZE)
        goto fail;

    for (unsigned short i = 0; i < *backupKeysLen; i++) {
        NKChannelBackupKeyData* k = &backupKeys[i];

        p += nk_decode_u32(p, &k->keyVersion);
        p += nk_decode_u16(p, &k->encryptedKeySize);

        if (k->encryptedKeySize > NK_MAX_ENCRYPTED_KEY_SIZE)
            goto fail;

        p += nk_decode_bytes(p, k->encryptedKey, k->encryptedKeySize);
    }

    sodium_memzero(plain, plainLen);
    free(plain);

    return 0;

fail:
    sodium_memzero(plain, plainLen);
    free(plain);
    return -1;
}

unsigned char* nk_encode_channel_message_send(const unsigned int channelId, const unsigned int keyVersion, const unsigned char* plaintext, const unsigned short plaintextSize,
                                              const unsigned char channelKey[NK_X25519_KEY_SIZE], const unsigned char ed25519_sk[NK_ED25519_SECRET_KEY_SIZE], 
                                              const unsigned char txKey[NK_X25519_KEY_SIZE], unsigned int* frameSize)
{
    if (!plaintext || !channelKey || !ed25519_sk || !txKey || !frameSize)
        return NULL;

    unsigned int encSize = 0;
    unsigned char* enc = nk_encrypt_payload(channelKey, plaintext, plaintextSize, &encSize);

    if (!enc)
        return NULL;

    unsigned int plainLen = 4 + 4 + 2 + encSize + NK_ED25519_SIG_SIZE;

    unsigned char* plain = malloc(plainLen);
    if (!plain) {
        free(enc);
        return NULL;
    }

    unsigned char* p = plain;

    p += nk_encode_u32(p, channelId);
    p += nk_encode_u32(p, keyVersion);

    p += nk_encode_u16(p, encSize);
    p += nk_encode_bytes(p, enc, encSize);

    unsigned int signedLen = p - plain;

    unsigned char sig[NK_ED25519_SIG_SIZE];
    crypto_sign_detached(sig, NULL, plain, signedLen, ed25519_sk);

    p += nk_encode_bytes(p, sig, NK_ED25519_SIG_SIZE);

    unsigned int payloadLen = 0;
    unsigned char* payload = nk_encrypt_payload(txKey, plain, p - plain, &payloadLen);

    sodium_memzero(plain, p - plain);
    free(plain);
    free(enc);

    if (!payload)
        return NULL;

    unsigned int totalLen = NK_HEADER_SIZE + payloadLen;

    unsigned char* frame = malloc(totalLen);
    if (!frame) {
        free(payload);
        return NULL;
    }

    nk_encode_header(frame, totalLen, NK_OPCODE_CHANNEL_MESSAGE_SEND, payloadLen);
    memcpy(frame + NK_HEADER_SIZE, payload, payloadLen);

    free(payload);
    *frameSize = totalLen;

    return frame;
}

int nk_decode_channel_message_send(const unsigned char* frame, const unsigned int frameSize, const unsigned char rxKey[NK_X25519_KEY_SIZE], 
                                   unsigned int* channelId, unsigned int* keyVersion, unsigned char payload[NK_MAX_MESSAGE_SIZE], unsigned short* payloadSize,
                                   unsigned char signature[NK_ED25519_SIG_SIZE], unsigned char* signedBuf, unsigned int* signedLen){
    if (!frame || !rxKey || !channelId || !keyVersion ||
        !payload || !payloadSize || !signature ||
        !signedBuf || !signedLen)
        return -1;

    unsigned char opcode = 0;
    unsigned int payloadLen = 0;

    if (nk_decode_header(frame, frameSize, &opcode, &payloadLen) != 0)
        return -1;

    if (opcode != NK_OPCODE_CHANNEL_MESSAGE_SEND)
        return -1;

    unsigned char* plain = malloc(payloadLen);
    if (!plain)
        return -1;

    unsigned int plainLen = 0;

    if (nk_decrypt_payload(
            rxKey,
            frame + NK_HEADER_SIZE,
            payloadLen,
            plain,
            &plainLen) != 0)
    {
        free(plain);
        return -1;
    }

    const unsigned char* p = plain;

    p += nk_decode_u32(p, channelId);
    p += nk_decode_u32(p, keyVersion);

    p += nk_decode_u16(p, payloadSize);

    if (*payloadSize > NK_MAX_MESSAGE_SIZE) {
        sodium_memzero(plain, plainLen);
        free(plain);
        return -1;
    }

    p += nk_decode_bytes(p, payload, *payloadSize);

    *signedLen = 4 + 4 + 2 + *payloadSize;

    memcpy(signedBuf, plain, *signedLen);

    p += nk_decode_bytes(p, signature, NK_ED25519_SIG_SIZE);

    sodium_memzero(plain, plainLen);
    free(plain);

    return 0;
}

unsigned char* nk_encode_channel_message_deliver(const unsigned int channelId, const NKChannelMessageData* message, 
                                                 const unsigned char txKey[NK_ED25519_SECRET_KEY_SIZE], unsigned int* frameSize)
{
    if (!message || !txKey || !frameSize)
        return NULL;

    unsigned int plainLen = 4 + sizeof(unsigned int) * 4 + 2 + message->payloadSize;

    unsigned char* plain = malloc(plainLen);
    if (!plain)
        return NULL;

    unsigned char* p = plain;

    p += nk_encode_u32(p, channelId);

    p += nk_encode_u32(p, message->messageId);
    p += nk_encode_u32(p, message->senderId);
    p += nk_encode_u32(p, message->senderDeviceId);
    p += nk_encode_u32(p, message->keyVersion);

    p += nk_encode_u16(p, message->payloadSize);
    p += nk_encode_bytes(p, message->payload, message->payloadSize);

    unsigned int payloadLen = 0;
    unsigned char* payload = nk_encrypt_payload(txKey, plain, p - plain, &payloadLen);

    free(plain);

    if (!payload)
        return NULL;

    unsigned int totalLen = NK_HEADER_SIZE + payloadLen;

    unsigned char* frame = malloc(totalLen);
    if (!frame) {
        free(payload);
        return NULL;
    }

    nk_encode_header(frame, totalLen, NK_OPCODE_CHANNEL_MESSAGE_DELIVER, payloadLen);
    memcpy(frame + NK_HEADER_SIZE, payload, payloadLen);

    free(payload);
    *frameSize = totalLen;

    return frame;
}

int nk_decode_channel_message_deliver(const unsigned char* frame, const unsigned int frameSize, const unsigned char rxKey[NK_ED25519_SECRET_KEY_SIZE],
                                      unsigned int* channelId, NKChannelMessageData* message)
{
    if (!frame || !rxKey || !channelId || !message)
        return -1;

    unsigned char opcode;
    unsigned int payloadLen;

    if (nk_decode_header(frame, frameSize, &opcode, &payloadLen) != 0)
        return -1;

    if (opcode != NK_OPCODE_CHANNEL_MESSAGE_DELIVER)
        return -1;

    unsigned char* plain = malloc(payloadLen);
    if (!plain)
        return -1;

    unsigned int plainLen = 0;

    if (nk_decrypt_payload(rxKey, frame + NK_HEADER_SIZE, payloadLen, plain, &plainLen) != 0) {
        free(plain);
        return -1;
    }

    const unsigned char* p = plain;

    p += nk_decode_u32(p, channelId);

    p += nk_decode_u32(p, &message->messageId);
    p += nk_decode_u32(p, &message->senderId);
    p += nk_decode_u32(p, &message->senderDeviceId);
    p += nk_decode_u32(p, &message->keyVersion);

    p += nk_decode_u16(p, &message->payloadSize);
    p += nk_decode_bytes(p, message->payload, message->payloadSize);

    free(plain);
    return 0;
}

unsigned char* nk_encode_sync_channel_history_request(const unsigned int channelId, const unsigned int fromMessageId, const unsigned int limit,
                                                      const unsigned char txKey[NK_X25519_KEY_SIZE], unsigned int* frameSize){
    if (!txKey || !frameSize)
        return NULL;

    int plainLen = 12;

    unsigned char* plain = malloc(plainLen);
    if (!plain)
        return NULL;

    unsigned char* p = plain;
    p += nk_encode_u32(p, channelId);
    p += nk_encode_u32(p, fromMessageId);
    p += nk_encode_u32(p, limit);

    unsigned int payloadLen = 0;
    unsigned char* payload = nk_encrypt_payload(txKey, plain, p - plain, &payloadLen);

    free(plain);

    if (!payload)
        return NULL;

    unsigned int totalLen = NK_HEADER_SIZE + payloadLen;

    unsigned char* frame = malloc(totalLen);
    if (!frame) {
        free(payload);
        return NULL;
    }

    nk_encode_header(frame, totalLen, NK_OPCODE_SYNC_CHANNEL_HISTORY_REQUEST, payloadLen);
    memcpy(frame + NK_HEADER_SIZE, payload, payloadLen);

    free(payload);
    *frameSize = totalLen;

    return frame;
}

int nk_decode_sync_channel_history_request(const unsigned char* frame, const unsigned int frameSize, const unsigned char rxKey[NK_X25519_KEY_SIZE], 
                                           unsigned int* channelId, unsigned int* fromMessageId, unsigned int* limit){
    if (!frame || !rxKey || !channelId || !fromMessageId || !limit){
        return -1;
    }

    unsigned char opcode = 0;
    unsigned int payloadLen = 0;
    if(nk_decode_header(frame, frameSize, &opcode, &payloadLen) != 0){
        return -1;
    }

    if (opcode != NK_OPCODE_SYNC_CHANNEL_HISTORY_REQUEST){
        return -1;
    }

    unsigned char* plain = malloc(payloadLen);
    if (!plain)
        return -1;

    unsigned int plainLen = 0;
    if (nk_decrypt_payload(rxKey, frame + NK_HEADER_SIZE, payloadLen, plain, &plainLen) != 0) {
        free(plain);
        return -1;
    }

    const unsigned char* p = plain;
    p += nk_decode_u32(p, channelId);
    p += nk_decode_u32(p, fromMessageId);
    p += nk_decode_u32(p, limit);

    sodium_memzero(plain, plainLen);
    free(plain);

    return 0;
}

unsigned char* nk_encode_sync_channel_history(const unsigned int channelId, const NKChannelMessageData messages[NK_MAX_PAYLOAD_ARRAY_SIZE], const unsigned short messagesLen,
                                              const unsigned char txKey[NK_ED25519_SECRET_KEY_SIZE], unsigned int* frameSize)
{
    if (!messages || !txKey || !frameSize)
        return NULL;

    unsigned int plainLen = 4 + 2;

    for (unsigned short i = 0; i < messagesLen; i++) {
        plainLen += sizeof(unsigned int) * 4 + 2 + messages[i].payloadSize;
    }

    unsigned char* plain = malloc(plainLen);
    if (!plain)
        return NULL;

    unsigned char* p = plain;

    p += nk_encode_u32(p, channelId);
    p += nk_encode_u16(p, messagesLen);

    for (unsigned short i = 0; i < messagesLen; i++) {
        const NKChannelMessageData* m = &messages[i];

        p += nk_encode_u32(p, m->messageId);
        p += nk_encode_u32(p, m->senderId);
        p += nk_encode_u32(p, m->senderDeviceId);
        p += nk_encode_u32(p, m->keyVersion);

        p += nk_encode_u16(p, m->payloadSize);
        p += nk_encode_bytes(p, m->payload, m->payloadSize);
    }

    unsigned int payloadLen = 0;
    unsigned char* payload = nk_encrypt_payload(txKey, plain, p - plain, &payloadLen);

    free(plain);

    if (!payload)
        return NULL;

    unsigned int totalLen = NK_HEADER_SIZE + payloadLen;

    unsigned char* frame = malloc(totalLen);
    if (!frame) {
        free(payload);
        return NULL;
    }

    nk_encode_header(frame, totalLen, NK_OPCODE_SYNC_CHANNEL_HISTORY, payloadLen);
    memcpy(frame + NK_HEADER_SIZE, payload, payloadLen);

    free(payload);
    *frameSize = totalLen;

    return frame;
}

int nk_decode_sync_channel_history(const unsigned char* frame, const unsigned int frameSize, const unsigned char rxKey[NK_ED25519_SECRET_KEY_SIZE], unsigned int* channelId, 
                                   NKChannelMessageData messages[NK_MAX_PAYLOAD_ARRAY_SIZE], unsigned short* messagesLen)
{
    if (!frame || !rxKey || !channelId || !messages || !messagesLen)
        return -1;

    unsigned char opcode;
    unsigned int payloadLen;

    if (nk_decode_header(frame, frameSize, &opcode, &payloadLen) != 0)
        return -1;

    if (opcode != NK_OPCODE_SYNC_CHANNEL_HISTORY)
        return -1;

    unsigned char* plain = malloc(payloadLen);
    if (!plain)
        return -1;

    unsigned int plainLen = 0;

    if (nk_decrypt_payload(rxKey, frame + NK_HEADER_SIZE, payloadLen, plain, &plainLen) != 0) {
        free(plain);
        return -1;
    }

    const unsigned char* p = plain;

    p += nk_decode_u32(p, channelId);
    p += nk_decode_u16(p, messagesLen);

    if (*messagesLen > NK_MAX_PAYLOAD_ARRAY_SIZE)
        goto fail;

    for (unsigned short i = 0; i < *messagesLen; i++) {
        NKChannelMessageData* m = &messages[i];

        p += nk_decode_u32(p, &m->messageId);
        p += nk_decode_u32(p, &m->senderId);
        p += nk_decode_u32(p, &m->senderDeviceId);
        p += nk_decode_u32(p, &m->keyVersion);

        p += nk_decode_u16(p, &m->payloadSize);
        p += nk_decode_bytes(p, m->payload, m->payloadSize);
    }

    free(plain);
    return 0;

fail:
    free(plain);
    return -1;
}

unsigned char* nk_encode_channel_typing_update(const unsigned int channelId, const unsigned int typingStatus, const unsigned char txKey[NK_X25519_KEY_SIZE], unsigned int* frameSize){
    if (!txKey || !frameSize)
        return NULL;

    int plainLen = 8;

    unsigned char* plain = malloc(plainLen);
    if (!plain)
        return NULL;

    unsigned char* p = plain;
    p += nk_encode_u32(p, channelId);
    p += nk_encode_u32(p, typingStatus);

    unsigned int payloadLen = 0;
    unsigned char* payload = nk_encrypt_payload(txKey, plain, p - plain, &payloadLen);

    free(plain);

    if (!payload)
        return NULL;

    unsigned int totalLen = NK_HEADER_SIZE + payloadLen;

    unsigned char* frame = malloc(totalLen);
    if (!frame) {
        free(payload);
        return NULL;
    }

    nk_encode_header(frame, totalLen, NK_OPCODE_CHANNEL_TYPING_UPDATE, payloadLen);
    memcpy(frame + NK_HEADER_SIZE, payload, payloadLen);

    free(payload);
    *frameSize = totalLen;

    return frame;
}

int nk_decode_channel_typing_update(const unsigned char* frame, const unsigned int frameSize, const unsigned char rxKey[NK_X25519_KEY_SIZE], unsigned int* channelId, unsigned int* typingStatus){
    if (!frame || !rxKey || !channelId){
        return -1;
    }

    unsigned char opcode = 0;
    unsigned int payloadLen = 0;

    if (nk_decode_header(frame, frameSize, &opcode, &payloadLen) != 0)
        return -1;

    if (opcode != NK_OPCODE_CHANNEL_TYPING_UPDATE)
        return -1;

    const unsigned char* payload = frame + NK_HEADER_SIZE;

    unsigned char* plain = malloc(payloadLen);
    if (!plain)
        return -1;

    unsigned int plainLen = 0;

    if (nk_decrypt_payload(rxKey, payload, payloadLen, plain, &plainLen) != 0) {
        free(plain);
        return -1;
    }

    const unsigned char* p = plain;
    p += nk_decode_u32(p, channelId);
    p += nk_decode_u32(p, typingStatus);

    sodium_memzero(plain, plainLen);
    free(plain);

    return 0;
}
                                   
unsigned char* nk_encode_channel_typing_broadcast(const unsigned int userId, const unsigned int channelId, const unsigned int typingStatus, const unsigned char txKey[NK_X25519_KEY_SIZE], unsigned int* frameSize){
    if (!txKey || !frameSize)
        return NULL;

    int plainLen = 12;

    unsigned char* plain = malloc(plainLen);
    if (!plain)
        return NULL;

    unsigned char* p = plain;
    p += nk_encode_u32(p, userId);
    p += nk_encode_u32(p, channelId);
    p += nk_encode_u32(p, typingStatus);

    unsigned int payloadLen = 0;
    unsigned char* payload = nk_encrypt_payload(txKey, plain, p - plain, &payloadLen);

    free(plain);

    if (!payload)
        return NULL;

    unsigned int totalLen = NK_HEADER_SIZE + payloadLen;

    unsigned char* frame = malloc(totalLen);
    if (!frame) {
        free(payload);
        return NULL;
    }

    nk_encode_header(frame, totalLen, NK_OPCODE_CHANNEL_TYPING_UPDATE, payloadLen);
    memcpy(frame + NK_HEADER_SIZE, payload, payloadLen);

    free(payload);
    *frameSize = totalLen;

    return frame;
}

int nk_decode_channel_typing_broadcast(const unsigned char* frame, const unsigned int frameSize, const unsigned char rxKey[NK_X25519_KEY_SIZE], unsigned int* userId, unsigned int* channelId, unsigned int* typingStatus){
    if (!frame || !rxKey || !channelId){
        return -1;
    }

    unsigned char opcode = 0;
    unsigned int payloadLen = 0;

    if (nk_decode_header(frame, frameSize, &opcode, &payloadLen) != 0)
        return -1;

    if (opcode != NK_OPCODE_CHANNEL_TYPING_UPDATE)
        return -1;

    const unsigned char* payload = frame + NK_HEADER_SIZE;

    unsigned char* plain = malloc(payloadLen);
    if (!plain)
        return -1;

    unsigned int plainLen = 0;

    if (nk_decrypt_payload(rxKey, payload, payloadLen, plain, &plainLen) != 0) {
        free(plain);
        return -1;
    }

    const unsigned char* p = plain;
    p += nk_decode_u32(p, userId);
    p += nk_decode_u32(p, channelId);
    p += nk_decode_u32(p, typingStatus);

    sodium_memzero(plain, plainLen);
    free(plain);

    return 0;
}
