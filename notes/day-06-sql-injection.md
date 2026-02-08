## Day 06 – SQL Injection (SQLi)

SQL Injection is a web vulnerability where attackers manipulate SQL queries using malicious input.

### Why SQL Injection is dangerous:
- Authentication bypass
- Data leakage
- Database modification or deletion

### Vulnerable Behavior:
Building SQL queries using string concatenation.

Example:
SELECT * FROM users WHERE username = 'user' AND password = 'pass'

Attack Payload:
' OR '1'='1

This makes the query always true.

---

### Fixed Behavior:
- Use parameterized queries
- Sanitize user input
- Do not trust client-side input

---

### Key Learning:
SQL Injection happens due to improper input handling and unsafe query construction.