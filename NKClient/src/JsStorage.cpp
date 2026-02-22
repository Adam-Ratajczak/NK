#include <JsStorage.hpp>
#include <JsLogger.hpp>
#include <emscripten.h>

EM_JS(void, js_set, (const char* key, const char* value), {
    localStorage.setItem(UTF8ToString(key), UTF8ToString(value));
});

EM_JS(int, js_get, (const char* key, char* out, int maxLen), {
    const k = UTF8ToString(key);
    const v = localStorage.getItem(k);
    if (!v) return 0;

    const len = lengthBytesUTF8(v);
    if (len + 1 > maxLen) return -1;

    stringToUTF8(v, out, maxLen);
    return len;
});

EM_JS(void, js_remove, (const char* key), {
    localStorage.removeItem(UTF8ToString(key));
});

EM_JS(int, js_exists, (const char* key), {
    return localStorage.getItem(UTF8ToString(key)) !== null ? 1 : 0;
});

void JsStorage::Set(const std::string& key, const std::string& value) {
    js_set(key.c_str(), value.c_str());
}

std::string JsStorage::Get(const std::string& key) {
    char buffer[4096] = {0};
    int len = js_get(key.c_str(), buffer, sizeof(buffer));
    if (len <= 0) return "";
    return std::string(buffer, len);
}

void JsStorage::Remove(const std::string& key) {
    js_remove(key.c_str());
}

bool JsStorage::Exists(const std::string& key) {
    return js_exists(key.c_str()) != 0;
}

std::string Base64Encode(const unsigned char* data, size_t len) {
    int outLen = EM_ASM_INT({
        const bytes = HEAPU8.subarray($0, $0 + $1);

        let binary = "";
        for (let i = 0; i < bytes.length; i++) {
            binary += String.fromCharCode(bytes[i]);
        }

        const b64 = btoa(binary);
        return lengthBytesUTF8(b64) + 1;
    }, data, len);

    std::string out(outLen, '\0');

    EM_ASM({
        const bytes = HEAPU8.subarray($0, $0 + $1);

        let binary = "";
        for (let i = 0; i < bytes.length; i++) {
            binary += String.fromCharCode(bytes[i]);
        }

        const b64 = btoa(binary);
        stringToUTF8(b64, $2, $3);
    }, data, len, out.data(), outLen);

    return out.c_str();
}

std::vector<unsigned char> Base64Decode(const std::string& str) {
    int outLen = EM_ASM_INT({
        const b64 = UTF8ToString($0);
        const raw = atob(b64);
        return raw.length;
    }, str.c_str());

    std::vector<unsigned char> out(outLen);

    EM_ASM({
        const b64 = UTF8ToString($0);
        const raw = atob(b64);

        for (let i = 0; i < raw.length; i++) {
            HEAPU8[$1 + i] = raw.charCodeAt(i);
        }
    }, str.c_str(), out.data());

    return out;
}
