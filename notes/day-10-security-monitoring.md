# Day 10 – Authentication Monitoring & Intrusion Detection

## Overview

This implementation extends a basic authentication system into a monitored security component.

Instead of only validating credentials, the system now:

- Tracks failed login attempts per IP
- Temporarily blocks abusive IPs
- Generates security alerts
- Logs authentication activity to a structured file
- Exposes a monitoring endpoint for alert visibility

This simulates foundational concepts used in real-world security monitoring systems.

---

## Security Architecture Enhancements

### 1. IP-Based Failure Tracking

Failed login attempts are tracked per source IP address.

Why this matters:
- Detects brute-force attempts
- Prevents automated password guessing
- Enables adaptive blocking strategies

---

### 2. Rate Limiting and Temporary Blocking

If failed attempts exceed a defined threshold:

- The IP is temporarily blocked
- Further login attempts are denied
- A security event is triggered

This mirrors behavior seen in:
- Banking systems
- Enterprise authentication gateways
- Identity providers

---

### 3. Security Event Logging

All relevant authentication events are written to a log file:

- Successful logins
- Failed logins
- Brute force detection alerts

Logs are structured as JSON entries to simulate machine-readable logging formats used in SIEM systems.

Example event:

{
  "type": "brute_force_detected",
  "ip": "127.0.0.1",
  "timestamp": 1712345678
}

---

### 4. Alert Monitoring Endpoint

A dedicated endpoint exposes detected alerts.

Purpose:
- Simulates SOC dashboard data source
- Allows visibility into detected suspicious behavior
- Separates authentication logic from monitoring logic

---

## Defensive Security Principles Applied

- Fail securely
- Limit attack surface
- Detect abuse patterns
- Separate detection from prevention
- Maintain audit logs for forensic visibility

---

## Real-World Relevance

This mini-system models core ideas behind:

- Intrusion Detection Systems (IDS)
- Security Information and Event Management (SIEM)
- Identity and Access Management (IAM)
- Authentication abuse detection pipelines

While simplified, the architecture reflects real production design patterns.

---

## Key Takeaways

- Authentication security is not only about password validation.
- Monitoring and logging are as critical as prevention.
- Attack detection requires state tracking.
- Defensive engineering requires visibility into abnormal patterns.