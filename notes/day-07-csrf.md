## Day 07 – Cross Site Request Forgery (CSRF)

CSRF is an attack where a logged-in user's browser is tricked into performing an unwanted action.

### Why CSRF happens:
- Browser automatically sends cookies
- Server trusts authenticated requests
- No verification of request origin

### Example attacks:
- Money transfer
- Password change
- Email change

---

### Vulnerable Behavior:
Actions performed without verifying request authenticity.

---

### Prevention Techniques:
- CSRF tokens
- SameSite cookie attribute
- Checking request origin
- User confirmation

---

### Key Learning:
CSRF exploits trust between browser and server, not input fields.