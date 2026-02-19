# Day 17 – Permission Matrix Authorization Engine

## Objective

Replace inline role checks with a centralized permission policy engine.

## Improvements

- Role-to-permission mapping
- Centralized permission function
- Live role validation from database
- Reduced authorization logic duplication

## Why This Matters

Hardcoded role checks do not scale.
Centralized policy engines improve security maintainability.

## Security Concept

Authentication verifies identity.
Authorization enforces capability.

Policy engines reduce inconsistent access control logic.