// tests/security_tests.cpp
// Security-related tests for Phase 3 submission.
// This tests boundary conditions, crypto repeatability, etc.

#include <cassert>
#include <iostream>
#include "../src/security_utils.h"
#include "../src/hmac.h"

int main() {
    // 1. Boundary test for name length
    {
        std::string ok = "guard1";
        std::string tooLong(300, 'A');
        assert(isValidName(ok, 64) == true);
        assert(isValidName(tooLong, 64) == false);
    }

    // 2. Allowed actions
    {
        assert(isValidAction("enter") == true);
        assert(isValidAction("exit")  == true);
        assert(isValidAction("dance") == false);
    }

    // 3. Timestamp format
    {
        assert(isValidTimestamp("2025-10-30T12:00:00Z") == true);
        assert(isValidTimestamp("30-10-2025 12:00")     == false);
    }

    // 4. constTimeEquals
    {
        assert(constTimeEquals("abc123", "abc123") == true);
        assert(constTimeEquals("abc123", "zzz999") == false);
    }

    // 5. HMAC stability
    {
        std::string h1 = computeHMAC_SHA256("key", "data");
        std::string h2 = computeHMAC_SHA256("key", "data");
        assert(h1 == h2);
    }

    std::cout << "All security tests passed.\n";
    return 0;
}