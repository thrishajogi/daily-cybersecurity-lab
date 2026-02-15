# Day 14 – Race Condition and Concurrency Exploitation

## Objective

Simulate a race condition in a financial transaction endpoint and implement a locking-based defense.

---

## Red Team Phase

The withdrawal endpoint:

1. Checked wallet balance.
2. Introduced artificial delay.
3. Deducted funds.

Two concurrent requests exploited the time gap between check and update.

Result:
Double withdrawal allowed.

---

## Vulnerability Type

Race Condition
Time-of-check to time-of-use (TOCTOU)

---

## Blue Team Fix

Used thread-level locking:

with wallet_lock:

Ensures atomic transaction execution.

Prevents concurrent state modification.

---

## Real-World Relevance

Race conditions occur in:

- Banking systems
- E-commerce checkout flows
- Cryptocurrency transfers
- Inventory systems

Improper synchronization can lead to financial loss.

---

## Key Takeaways

Security vulnerabilities are not always injection-based.
Timing and concurrency flaws can be equally dangerous.
Atomic operations are critical in financial systems.