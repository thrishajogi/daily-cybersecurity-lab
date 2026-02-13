# Day 12 – IDOR and Role-Based Access Control (RBAC)

## Objective

Simulate an insecure direct object reference vulnerability and fix it using proper authorization checks.

---

## Red Phase

The endpoint:

/profile/<user_id>

Allowed access to user data without validating identity.

This enabled horizontal privilege escalation.

---

## Blue Phase

Implemented:

- Token validation before access
- User identity verification
- Admin override logic
- Unauthorized access logging

---

## Security Principles Applied

- Never trust direct object references
- Authorization must be enforced server-side
- Authentication ≠ Authorization
- Log suspicious access attempts

---

## Key Learning

Access control vulnerabilities are logic flaws, not injection flaws.
They are subtle and frequently found in real production systems.