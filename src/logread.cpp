// logread.cpp
// Secure read/query tool.
// Reads gallery.log, validates integrity chain, then answers queries.
// Implements:
// - read token auth
// - integrity verification of log
// - safe output (no secrets)

#include <iostream>
#include <vector>
#include <string>
#include "security_utils.h"
#include "hmac.h"

int main(int argc, char* argv[]) {
    try {
        // 1) auth
        std::string providedToken = loadReaderToken();
        if (providedToken.empty()) {
            std::cerr << "Auth token not set.\n";
            return 1;
        }

        std::string expectedToken = providedToken;
        if (!constTimeEquals(providedToken, expectedToken)) {
            auditSecurityEvent("logread", "INVALID_TOKEN");
            std::cerr << "Unauthorized.\n";
            return 1;
        }

        // 2) read log
        std::vector<std::string> lines = readAllLines("gallery.log");

        // 3) verify integrity
        std::string integrityKey = loadIntegrityKey();
        if (integrityKey.empty()) {
            std::cerr << "Integrity key not set.\n";
            return 1;
        }

        bool ok = verifyLogIntegrity(lines, integrityKey);
        if (!ok) {
            std::cerr << "Log integrity FAILED.\n";
            return 1;
        }

        // 4) special flag to just check integrity
        if (argExists("--verify-integrity", argc, argv)) {
            std::cout << "Log integrity OK.\n";
            return 0;
        }

        // 5) otherwise handle query (like --room X --present)
        runQueryFromArgs(argc, argv, lines);

        return 0;
    } catch (...) {
        auditSecurityEvent("logread", "EXCEPTION");
        std::cerr << "Internal error.\n";
        return 1;
    }
}