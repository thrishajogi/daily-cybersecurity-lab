# Day 15 – Purple-Team Capstone (Phase 1)

## Objective

Design a secure internal API system with role-based access control and privilege escalation detection.

---

## System Features

- HMAC-signed authentication tokens
- Token expiration enforcement
- Role-based document filtering
- Ownership validation
- Privilege escalation detection alerts

---

## Red Scenario

A normal user attempts to access documents owned by another user.

This represents horizontal privilege escalation.

---

## Blue Defense

- Token validation
- Role-based enforcement
- Ownership verification
- Alert generation upon unauthorized access

---

## Security Concepts Applied

- RBAC
- Horizontal privilege escalation
- Integrity validation
- Expiring sessions
- Security event logging

---

## Takeaway

Authentication alone is not enough.
Authorization logic must enforce strict ownership boundaries.
Monitoring unauthorized attempts is critical.