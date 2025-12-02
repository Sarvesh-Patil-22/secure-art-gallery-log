# Secure Art Gallery Log
Secure, tamper-evident log for tracking the state of an art gallery: guests and employees entering/leaving, and who is present in each room.

## Team Name
Group 6

## Team Members
Sarvesh Patil

Jay Eichmuller

## Project Overview
This project implements a secure logging system for tracking the state of an art gallery, including guests and employees entering and leaving rooms. It consists of two C++ programs:
- **logappend** – appends new information to the log file
- **logread** – reads and queries the log to display the state

## Phase 1: Requirements Assignment
The requirements document is located at:
`docs/requirements_document.pdf`

## Overview
This repository implements a small secure logging system in C++ suitable for a secure programming course. The two command-line tools are:
- `logappend` — append a new log entry (requires writer token and integrity key)
- `logread` — read/query the log and verify integrity (requires reader token and integrity key)

The project focuses on the following security goals:
- Integrity of log entries (tamper detection)
- Safe parsing and input validation
- Safe append operations (file locking, atomic writes)
- Audit logging of suspicious or error events


---

## Security Features
- **HMAC-SHA256 (OpenSSL):**
  - Each log entry contains a chained HMAC field computed with `INTEGRITY_KEY`.
  - The `prev` field in each entry references the previous entry's HMAC, forming a tamper-evident chain.
- **Constant-time secret comparisons:**
  - `constTimeEquals()` is used to compare tokens, mitigating timing attacks.
- **Input validation and bounds checking:**
  - `isValidName()` enforces a safe alphabet (alphanumeric, `-`, `_`) and maximum length for actor/room names.
  - `isValidTimestamp()` validates ISO 8601-like timestamps via regex.
  - `isValidAction()` restricts actions to `enter` or `exit` only.
- **File locking:**
  - `flock()` is used to acquire exclusive locks for `logappend` writes and when appending to `audit.log`.
- **Atomic write/flush:**
  - `write()` followed by `fsync()` ensures data is flushed to storage before releasing the lock.
- **Audit logging:**
  - `audit.log` tracks events like invalid tokens, bad inputs, write failures, and exceptions, supporting non-repudiation and incident response.

---

## Usage / Examples

### 1. Append a log entry

```bash
# Set writer token and integrity key (required for logappend)
export ARTLOG_TOKEN_WRITE=writer1
export INTEGRITY_KEY=secret_key

# Add an event (from src directory)
./logappend --actor guard1 --action enter --room GalleryA --time 2025-10-30T12:00:00Z
```
This adds a line to `gallery.log` with fields: `actor`, `action`, `room`, `time`, `prev`, and `hmac`.

If the token or input is invalid, `logappend` exits with error code 1 and `audit.log` records a security event (e.g., `INVALID_TOKEN` or `INVALID_INPUT`).

### 2. Verify log integrity and query

```bash
# Set reader token and integrity key (required for logread)
export ARTLOG_TOKEN_READ=reader1
export INTEGRITY_KEY=secret_key

# Verify integrity only (exit 0 on OK, 1 on failure)
./logread --verify-integrity

# Query who is present in a room
./logread --room GalleryA --present
```

If the log has been tampered with, `logread` will report integrity failure and log the event in `audit.log`.

### 3. Run security tests

The project includes `security_tests`. To run:

```bash
./security_tests
```

---

## Project Structure

- `src/logappend.cpp` — Secure append tool: input validation, HMAC chaining, atomic writes, audit logging
- `src/logread.cpp` — Secure read/query tool: validates HMAC chain, answers queries, logs suspicious events
- `src/security_utils.cpp`, `src/security_utils.h` — Security helpers: token loading, constant-time compare, validation, file ops, audit logging, integrity verification
- `src/hmac.cpp`, `src/hmac.h` — HMAC-SHA256 computation using OpenSSL
- `tests/security_tests.cpp` — Security and boundary tests
- `gallery.log` — Main log file (created at runtime)
- `audit.log` — Audit log for security-relevant events (created at runtime)


