#pragma once
#include <string>
#include <vector>

class JsStorage {
public:
    static void Set(const std::string& key, const std::string& value);
    static std::string Get(const std::string& key);
    static void Remove(const std::string& key);
    static bool Exists(const std::string& key);
};

std::string Base64Encode(const unsigned char* data, size_t len);
std::vector<unsigned char> Base64Decode(const std::string& str);
