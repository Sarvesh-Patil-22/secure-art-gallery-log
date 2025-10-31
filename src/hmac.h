#pragma once
#include <string>

// Compute HMAC-SHA256(key, data) and return it as a hex string.
// We use this for tamper-evident log entries.
std::string computeHMAC_SHA256(const std::string &key,
                               const std::string &data);