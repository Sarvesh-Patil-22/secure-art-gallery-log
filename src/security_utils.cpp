// security_utils.cpp
// Security helper functions for Secure Art Gallery Log.
// This file contains the defensive coding and secure handling logic
// required by Phase 3: input validation, token handling, audit logging,
// safe file writes with locking, and integrity verification.

#include "security_utils.h"
#include "hmac.h"

#include <iostream>
#include <fstream>
#include <sstream>
#include <regex>
#include <stdexcept>
#include <vector>
#include <cstring>
#include <ctime>
#include <sys/file.h>   // flock()
#include <sys/stat.h>   // chmod
#include <fcntl.h>      // open()
#include <unistd.h>     // write(), fsync(), close()
#include <cstdlib>      // getenv

// --------------------------
// utility: current timestamp for audit log
// --------------------------
static std::string nowIso() {
    std::time_t t = std::time(nullptr);
    char buf[64];
    std::strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%SZ", std::gmtime(&t));
    return std::string(buf);
}

// --------------------------
// constant-time compare for secrets
// prevents timing attacks
// --------------------------
bool constTimeEquals(const std::string &a, const std::string &b) {
    if (a.size() != b.size()) return false;
    unsigned char diff = 0;
    for (size_t i = 0; i < a.size(); ++i) {
        diff |= (unsigned char)(a[i] ^ b[i]);
    }
    return diff == 0;
}

// --------------------------
// load secrets from environment
// IMPORTANT: do NOT hardcode secrets
// --------------------------
std::string loadWriterToken() {
    const char* v = std::getenv("ARTLOG_TOKEN_WRITE");
    if (!v) return "";
    return std::string(v);
}
std::string loadReaderToken() {
    const char* v = std::getenv("ARTLOG_TOKEN_READ");
    if (!v) return "";
    return std::string(v);
}
std::string loadIntegrityKey() {
    const char* v = std::getenv("INTEGRITY_KEY");
    if (!v) return "";
    return std::string(v);
}

// --------------------------
// audit log: append security-relevant events
// this supports repudiation/logging requirements
// --------------------------
void auditSecurityEvent(const std::string &tool,
                        const std::string &eventCode) {
    // NOTE: we keep audit.log mode 0600
    int fd = ::open("audit.log",
                    O_WRONLY | O_APPEND | O_CREAT,
                    0600);
    if (fd < 0) {
        // don't print secrets, just fail silently
        return;
    }

    // "2025-11-05T18:20Z logappend INVALID_TOKEN\n"
    std::string line = nowIso() + " " + tool + " " + eventCode + "\n";

    // lock, write, fsync, close
    if (flock(fd, LOCK_EX) == 0) {
        (void)::write(fd, line.c_str(), line.size());
        (void)::fsync(fd);
        (void)flock(fd, LOCK_UN);
    }

    ::close(fd);
}

// --------------------------
// CLI arg helpers
// --------------------------
std::string getArgValue(const std::string &flag, int argc, char* argv[]) {
    for (int i = 1; i < argc - 1; ++i) {
        if (flag == argv[i]) {
            return std::string(argv[i+1]);
        }
    }
    return "";
}

bool argExists(const std::string &flag, int argc, char* argv[]) {
    for (int i = 1; i < argc; ++i) {
        if (flag == argv[i]) return true;
    }
    return false;
}

// --------------------------
// validation helpers
// --------------------------
bool isValidName(const std::string &s, size_t maxLen) {
    if (s.empty() || s.size() > maxLen) return false;
    // only allow simple safe chars
    static const std::regex allowed("^[A-Za-z0-9_-]+$");
    return std::regex_match(s, allowed);
}

bool isValidAction(const std::string &s) {
    // gallery policy: must be "enter" or "exit"
    return (s == "enter" || s == "exit");
}

bool isValidTimestamp(const std::string &ts) {
    // very basic check: "YYYY-MM-DDTHH:MM:SSZ"
    static const std::regex iso(
        "^[0-9]{4}-[0-9]{2}-[0-9]{2}T"
        "[0-9]{2}:[0-9]{2}:[0-9]{2}Z$"
    );
    return std::regex_match(ts, iso);
}

// --------------------------
// helper: read last line from gallery.log and extract its hash
// we assume each line is a JSON-ish object like:
// {"actor":"guard1",...,"prev":"<prevhash>","hmac":"<hmac>"}
// NOTE: In a real implementation you'd parse JSON properly.
// For class, we keep it simple.
// --------------------------
static std::string extractHashFromLine(const std::string &line) {
    // We will treat "hmac":"...." as final field.
    // We'll just grab the value after "hmac":" and before the next quote.
    std::size_t pos = line.find("\"hmac\":\"");
    if (pos == std::string::npos) return "";
    pos += 8; // skip "hmac":" (7 chars + 1 for quote)
    std::size_t end = line.find("\"", pos);
    if (end == std::string::npos) return "";
    return line.substr(pos, end-pos);
}

std::string getPreviousHash(const std::string &logPath) {
    std::ifstream in(logPath);
    if (!in.is_open()) {
        // no file yet, so "genesis"
        return "GENESIS";
    }
    std::string lastLine;
    std::string line;
    while (std::getline(in, line)) {
        if (!line.empty()) lastLine = line;
    }
    in.close();

    if (lastLine.empty()) {
        return "GENESIS";
    }
    // hmac of last line becomes prevHash for next line
    return extractHashFromLine(lastLine);
}

// --------------------------
// build the entry without "hmac", so we can MAC it
// --------------------------
std::string formatLogEntry(const std::string &actor,
                           const std::string &action,
                           const std::string &room,
                           const std::string &timestamp,
                           const std::string &prevHash) {
    std::ostringstream oss;
    oss << "{"
        << "\"actor\":\""     << actor     << "\","
        << "\"action\":\""    << action    << "\","
        << "\"room\":\""      << room      << "\","
        << "\"time\":\""      << timestamp << "\","
        << "\"prev\":\""      << prevHash  << "\"";
    // NOTE: we intentionally do NOT write hmac yet.
    return oss.str();
}

// --------------------------
// secure append with lock + fsync
// --------------------------
bool appendSecure(const std::string &logPath,
                  const std::string &line) {
    int fd = ::open(logPath.c_str(),
                    O_WRONLY | O_APPEND | O_CREAT,
                    0600);
    if (fd < 0) {
        return false;
    }

    // lock file during write to reduce race conditions
    if (flock(fd, LOCK_EX) != 0) {
        ::close(fd);
        return false;
    }

    ssize_t w = ::write(fd, line.c_str(), line.size());
    bool ok = (w == (ssize_t)line.size());

    // flush to disk to protect availability
    ::fsync(fd);

    flock(fd, LOCK_UN);
    ::close(fd);

    return ok;
}

// --------------------------
// read file fully into memory (used by logread)
// --------------------------
std::vector<std::string> readAllLines(const std::string &logPath) {
    std::vector<std::string> out;
    std::ifstream in(logPath);
    if (!in.is_open()) {
        return out; // empty log is allowed
    }
    std::string line;
    while (std::getline(in, line)) {
        if (!line.empty()) {
            out.push_back(line);
        }
    }
    in.close();
    return out;
}

// --------------------------
// verify HMAC chain
// 1. each line must parse
// 2. recompute HMAC of the line-without-hmac and compare
// 3. check "prev" links to previous line's hmac
// --------------------------
static std::string extractField(const std::string &line,
                                const std::string &fieldName) {
    // super light parser: finds "fieldName":"value"
    std::string needle = "\"" + fieldName + "\":\"";
    std::size_t pos = line.find(needle);
    if (pos == std::string::npos) return "";
    pos += needle.size();
    std::size_t end = line.find("\"", pos);
    if (end == std::string::npos) return "";
    return line.substr(pos, end-pos);
}

bool verifyLogIntegrity(const std::vector<std::string> &lines,
                        const std::string &key) {
    std::string prevHashExpected = "GENESIS";

    for (const std::string &line : lines) {
        // pull hmac
        std::string hmacStored = extractField(line, "hmac");
        if (hmacStored.empty()) {
            return false;
        }

        // pull prev
        std::string prevField = extractField(line, "prev");
        if (prevField.empty()) {
            return false;
        }

        // verify chain link
        if (prevField != prevHashExpected) {
            return false;
        }

        // reconstruct line-without-hmac the same way formatLogEntry() did
        // We know formatLogEntry() ends before adding ,\"hmac\"...
        // We'll rebuild that prefix here using the fields from the line:
        std::string actor     = extractField(line, "actor");
        std::string action    = extractField(line, "action");
        std::string room      = extractField(line, "room");
        std::string time      = extractField(line, "time");
        std::string prev      = extractField(line, "prev");

        std::string reconstructed = formatLogEntry(actor, action, room, time, prev);

        // recompute HMAC
        std::string hmacCheck = computeHMAC_SHA256(key, reconstructed);

        if (!constTimeEquals(hmacStored, hmacCheck)) {
            return false;
        }

        // next line must reference this line's hmac
        prevHashExpected = hmacStored;
    }

    return true;
}

// --------------------------
// basic query logic for demonstration
// This is not full production logic —
// it's just to show we can answer queries securely.
// --------------------------
void runQueryFromArgs(int argc, char* argv[],
                      const std::vector<std::string> &lines) {
    // Example usage:
    //   ./logread --room GalleryA --present
    // We’ll answer: who is currently "in" that room (enter without matching exit).

    if (!argExists("--room", argc, argv) ||
        !argExists("--present", argc, argv)) {
        std::cout << "No query or unsupported query.\n";
        return;
    }

    std::string roomFilter = getArgValue("--room", argc, argv);

    // track state: who is IN the room
    // naive approach: map person -> in/out
    std::map<std::string, bool> inRoom;

    for (const std::string &line : lines) {
        std::string actor  = extractField(line, "actor");
        std::string action = extractField(line, "action");
        std::string room   = extractField(line, "room");

        if (room == roomFilter) {
            if (action == "enter") {
                inRoom[actor] = true;
            } else if (action == "exit") {
                inRoom[actor] = false;
            }
        }
    }

    std::cout << "Present in " << roomFilter << ":\n";
    for (auto &p : inRoom) {
        if (p.second == true) {
            std::cout << " - " << p.first << "\n";
        }
    }
}