# Day 11 – Signed Authentication Tokens (Purple Team Exercise)

This system implements authentication with:

- Password hashing (SHA-256)
- IP-based brute force detection
- Security event logging
- HMAC-signed session tokens
- Token integrity verification

## Red Perspective

A naive Base64 token would allow identity tampering.
Encoding does not provide integrity or trust.

## Blue Perspective

Implemented HMAC (SHA-256) signing to protect token integrity.
Tampering invalidates signature and blocks access.

## Security Concepts Applied

- Message Authentication Codes (HMAC)
- Broken Authentication mitigation
- Brute force detection
- Event logging
- Session integrity enforcement

## Takeaway

Trust must never depend on client-controlled data.
Integrity must be cryptographically enforced.