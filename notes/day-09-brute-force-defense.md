## Day 09 – Brute Force Attack and Rate Limiting

Brute force attacks try multiple passwords until a correct one is found.

### Why brute force works:
- Unlimited login attempts
- No delay or lockout
- Predictable passwords

---

### Attack Simulation:
A Python script was used to repeatedly attempt login with different passwords.

---

### Defense Implemented:
- Limited login attempts
- Temporary account lock
- Reset counter on successful login

---

### Key Learning:
Authentication systems must include rate limiting and lockout mechanisms to prevent brute-force attacks.