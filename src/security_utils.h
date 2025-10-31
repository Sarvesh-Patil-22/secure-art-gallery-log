#pragma once
#include <string>
#include <vector>

// ---- authentication / secrets ----
bool constTimeEquals(const std::string &a, const std::string &b);
std::string loadWriterToken();   // expected token for logappend
std::string loadReaderToken();   // expected token for logread
std::string loadIntegrityKey();  // HMAC key for log integrity

// ---- audit logging ----
void auditSecurityEvent(const std::string &tool,
                        const std::string &eventCode);

// ---- CLI argument helpers ----
std::string getArgValue(const std::string &flag, int argc, char* argv[]);
bool argExists(const std::string &flag, int argc, char* argv[]);

// ---- validation ----
bool isValidName(const std::string &s, size_t maxLen);
bool isValidAction(const std::string &s);      // "enter" / "exit"
bool isValidTimestamp(const std::string &ts);  // very basic ISO-ish check

// ---- log helpers ----
std::string getPreviousHash(const std::string &logPath);
std::string formatLogEntry(const std::string &actor,
                           const std::string &action,
                           const std::string &room,
                           const std::string &timestamp,
                           const std::string &prevHash);
bool appendSecure(const std::string &logPath,
                  const std::string &line);

std::vector<std::string> readAllLines(const std::string &logPath);

// ---- integrity check ----
bool verifyLogIntegrity(const std::vector<std::string> &lines,
                        const std::string &key);

// ---- query logic ----
void runQueryFromArgs(int argc, char* argv[],
                      const std::vector<std::string> &lines);