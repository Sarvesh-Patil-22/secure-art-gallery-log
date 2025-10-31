// hmac.cpp
// Cryptographic integrity support for the Secure Art Gallery Log.
// Uses HMAC-SHA256 to chain and protect log entries.
// NOTE: Requires OpenSSL (-lcrypto).

#include "hmac.h"
#include <openssl/hmac.h>
#include <stdexcept>

// convert raw bytes -> lowercase hex string
static std::string toHex(const unsigned char* data, unsigned int len) {
    static const char* hex = "0123456789abcdef";
    std::string out;
    out.reserve(len * 2);
    for (unsigned int i = 0; i < len; i++) {
        unsigned char c = data[i];
        out.push_back(hex[c >> 4]);
        out.push_back(hex[c & 0x0f]);
    }
    return out;
}

std::string computeHMAC_SHA256(const std::string &key,
                               const std::string &data) {
    unsigned int len = 0;
    unsigned char buff[EVP_MAX_MD_SIZE];

    unsigned char* res = HMAC(EVP_sha256(),
                              key.data(), key.size(),
                              reinterpret_cast<const unsigned char*>(data.data()),
                              data.size(),
                              buff, &len);

    if (!res) {
        throw std::runtime_error("HMAC failed");
    }

    return toHex(buff, len); // we store/compare hex
}