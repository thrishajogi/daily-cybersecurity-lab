# Day 15
 – Live Role Verification (Authorization Hardening)

## Problem

Tokens previously stored role inside the token.

If user role changed after token issuance,
privilege escalation persisted.

## Vulnerability Type

Stale privilege trust
Improper authorization caching

## Solution

Role validation moved to server-side database lookup.
Authorization decisions now use live role data.

## Key Principle

Tokens prove identity.
Authorization must revalidate server state.

## Takeaway

Never trust static authorization claims in tokens.
Always enforce authorization against current server-side data.