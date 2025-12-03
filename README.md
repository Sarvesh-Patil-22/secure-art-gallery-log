# Secure Art Gallery Log
Secure, tamper-evident log for tracking the state of an art gallery: guests and employees entering/leaving, and who is present in each room.
 
## Team Name
Group 6
 
## Team Members
Sarvesh Patil
 
Jay Eichmuller
 
## Project Overview
The Secure Art Gallery Log is a C++ command-line system that securely records entry and exit events for individuals inside different rooms of an art gallery. The project emphasizes secure programming practices, including authentication, cryptographic integrity, input validation, file safety, and defensive memory management. The system includes two programs:
1) logappend – appends validated log entries,
2) logread – verifies integrity and answers queries.
 
## Security Features
1. Input Validation and Bounds Checking
  - Actor and room names validated with regex and length limits (max 64).
  - Timestamps must follow ISO format YYYY-MM-DDTHH:MM:SSZ.
  - Only two actions allowed: enter, exit.
  - Invalid input is rejected and logged in audit.log.
 
2. Authentication and Authorization
  - Secrets stored only in environment variables:
      ARTLOG_TOKEN_WRITE, ARTLOG_TOKEN_READ, INTEGRITY_KEY
  - Write token required for logappend; read token required for logread.
  - Constant-time comparison used for token validation.
 
3. Cryptographic Integrity – HMAC-SHA256
  - Every log entry includes an HMAC and the previous entry’s HMAC.
  - Creates a tamper-evident chain similar to a blockchain.
  - Any modification makes logread --verify-integrity fail.
 
4. Secure File Handling
  - flock(LOCK_EX) prevents concurrent writes.
  - fsync() ensures safe disk flush.
  - Files written with permission 0600 to protect from other users.
 
5. Defensive Programming and Memory Safety
  - No unsafe C functions (no strcpy, gets, sprintf).
  - Only std::string, std::vector, and validated input used.
  - All exceptions handled and logged to audit.log.
 
6. Audit Logging
  - All invalid tokens, invalid input, and write failures recorded in audit.log.
 
## Build Instructions
cd src  
make  
 
This generates:
- logappend  
- logread  
- security_tests  
 
## Usage Examples
Append an entry:
./logappend --actor guard1 --action enter --room GalleryA --time 2025-10-30T12:00:00Z
 
Verify integrity:
./logread --verify-integrity
 
Query who is present:
./logread --room GalleryA --present
 
## Tampering Demonstration
nano gallery.log  
(change any value)  
./logread --verify-integrity  
Expected: "Log integrity FAILED"
 
## Security Testing
Run security tests:
cd src  
./security_tests  
 
Covers:
- Name, timestamp, and action validation
- HMAC correctness
- Constant-time comparison
- Tampering detection
 
## Summary
This project implements a fully validated, authenticated, tamper-evident logging system using secure C++ coding techniques, HMAC-SHA256 integrity protection, strict input validation, secure file handling, and a comprehensive security test suite.
 
 
 
 
 
 
 
 
# commands :
export ARTLOG_TOKEN_WRITE="Writer123!"
export ARTLOG_TOKEN_READ="Reader123!"
export INTEGRITY_KEY="SuperSecretKey!!!"
 
Entery
./logappend --actor guard2 --action enter --room GalleryA --time 2025-10-30T12:05:00Z
 
Exit
./logappend --actor guard1 --action exit --room GalleryA --time 2025-10-30T12:10:00Z
 
Who is present :
./logread --room GalleryA --present
 
 
Adding visitor to storage room
./logappend --actor visitorA --action enter --room Storage --time 2025-10-30T12:20:00Z
 
Who is present In store room
./logread --room Storage --present
 
 
Entry :
./logappend --actor guard1 --action enter --room GalleryA --time 2025-10-30T10:00:00Z
./logappend --actor visitor1 --action enter --room GalleryB --time 2025-10-30T10:05:00Z
./logappend --actor employee1 --action enter --room GalleryC --time 2025-10-30T10:10:00Z
 
Log:
./logread --room GalleryA --present
./logread --room GalleryB --present
./logread --room GalleryC --present
 
Print raw log :
cat gallery.log
 
 
Test:
./security_tests
 