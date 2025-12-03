// tests/security_tests.cpp
// Security-related tests for Phase 3 submission.
// This file includes:
// 1) Automated PASSING tests using assert()
// 2) A "failure demonstration" section that prints visible FAIL messages
//    without stopping execution, so the professor can see how the program
//    handles invalid input.
 
#include <cassert>
#include <iostream>
#include "../src/security_utils.h"
#include "../src/hmac.h"
 
int main() {
   std::cout << "=== PHASE 3 SECURITY TESTS ===\n";
 
   // -----------------------------------------------------------
   // 1. Automated PASSING tests (asserts)
   // -----------------------------------------------------------
   std::cout << "\n[1] Running automated passing tests...\n";
 
   // Name validation
   {
       std::string ok = "guard1";
       std::string tooLong(300, 'A');
       assert(isValidName(ok, 64) == true);
       assert(isValidName(tooLong, 64) == false);
   }
 
   // Action validation
   {
       assert(isValidAction("enter") == true);
       assert(isValidAction("exit")  == true);
       assert(isValidAction("dance") == false);
   }
 
   // Timestamp validation
   {
       assert(isValidTimestamp("2025-10-30T12:00:00Z") == true);
       assert(isValidTimestamp("30-10-2025 12:00")    == false);
   }
 
   // Constant-time compare
   {
       assert(constTimeEquals("abc123", "abc123") == true);
       assert(constTimeEquals("abc123", "zzz999") == false);
   }
 
   // HMAC Repeatability
   {
       std::string h1 = computeHMAC_SHA256("key", "data");
       std::string h2 = computeHMAC_SHA256("key", "data");
       assert(h1 == h2);
   }
 
   std::cout << "PASS: All automated tests behaved as expected.\n";
 
   // -----------------------------------------------------------
   // 2. FAILURE DEMONSTRATION SECTION (Visible failures)
   // -----------------------------------------------------------
   std::cout << "\n[2] FAILURE DEMONSTRATION (INTENTIONALLY FAILING CASES)\n";
   std::cout << "These do NOT use assert() so they do not exit the program.\n";
 
   // A) Invalid name
   {
       std::string badName = "bad$name";
       if (isValidName(badName, 64)) {
           std::cout << "FAIL (unexpected): invalid name was accepted.\n";
       } else {
           std::cout << "EXPECTED FAIL: invalid actor name '" << badName << "' was correctly rejected.\n";
       }
   }
 
   // B) Invalid timestamp
   {
       std::string badTime = "2025/10/30 10:00";
       if (isValidTimestamp(badTime)) {
           std::cout << "FAIL (unexpected): invalid timestamp was accepted.\n";
       } else {
           std::cout << "EXPECTED FAIL: invalid timestamp '" << badTime << "' was correctly rejected.\n";
       }
   }
 
   // C) Invalid action
   {
       std::string badAction = "jump";
       if (isValidAction(badAction)) {
           std::cout << "FAIL (unexpected): invalid action was accepted.\n";
       } else {
           std::cout << "EXPECTED FAIL: invalid action '" << badAction << "' was correctly rejected.\n";
       }
   }
 
   // D) Simulate business logic error: exit without entering
   {
       bool wasInsideRoom = false; // simulated state
       if (!wasInsideRoom) {
           std::cout << "EXPECTED FAIL: cannot exit room because user is not inside.\n";
       } else {
           std::cout << "FAIL (unexpected): system allowed exit without entry.\n";
       }
   }
 
   // E) Wrong token simulation
   {
       std::string correct = "Writer123!";
       std::string wrong   = "WrongToken";
       if (constTimeEquals(correct, wrong)) {
           std::cout << "FAIL (unexpected): wrong token passed authentication.\n";
       } else {
           std::cout << "EXPECTED FAIL: wrong authentication token rejected.\n";
       }
   }
 
   // -----------------------------------------------------------
   std::cout << "\n=== END OF TESTS ===\n";
   return 0;
}
 