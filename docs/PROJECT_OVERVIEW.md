# Project Overview

## Title

**Development of a Security Subsystem for a Financial Web Platform Based on Zero Trust Principles**

---

## Author Context

This project is developed as a bachelor thesis in Cybersecurity. The primary deliverable is a working implementation of a security subsystem, supported by architecture documentation, threat modeling, and explicit security testing. The written thesis will be grounded in the implemented system rather than theoretical description alone.

---

## Problem Statement

Traditional perimeter-based security models assume that everything inside a network boundary can be trusted. This assumption has proven inadequate in modern threat environments where insider threats, stolen credentials, compromised sessions, and API abuse are common attack vectors — especially in financial systems where the consequences of unauthorized access are direct and measurable.

Zero Trust is a security model that rejects implicit trust entirely. Every request, regardless of source, must be authenticated, authorized, and continuously validated. Access decisions incorporate not only identity but also context: device, session state, recent authentication events, and resource ownership.

Financial web platforms are a realistic and high-value target for demonstrating Zero Trust principles because they combine:
- Sensitive personal data (PII, financial records)
- High-value operations (money transfers, account access)
- Regulatory requirements around access control and audit
- A broad attack surface (public-facing API, user authentication, session management)

---

## Academic Relevance

### Why this project qualifies as a bachelor thesis in Cybersecurity

This project is academically relevant for the following reasons:

1. **Applied security engineering** — It requires selecting, designing, and implementing multiple layered security mechanisms, not merely describing them. Each mechanism is justified against a threat model and mapped to a security requirement.

2. **Zero Trust as a research subject** — Zero Trust is a current and evolving security paradigm adopted by major frameworks (NIST SP 800-207, CISA Zero Trust Maturity Model). Implementing it in a concrete system demonstrates understanding beyond theoretical familiarity.

3. **Threat modeling** — The project includes a structured STRIDE threat model with attacker assumptions, abuse cases, and explicit control mappings. This is a standard professional practice and an expected skill for a cybersecurity graduate.

4. **Security testing** — The test suite targets specific security properties: failed login handling, MFA flows, token rotation, token revocation, RBAC enforcement, ownership isolation, rate limiting, and step-up authentication. This demonstrates the ability to verify security guarantees programmatically.

5. **Design decisions** — Each major architectural decision is documented as an ADR, including tradeoffs between alternatives. This demonstrates engineering judgment, not just implementation.

### Why the financial domain is used as the context

The financial platform is intentionally a **vehicle** for demonstrating security controls, not the primary research subject. Financial systems are chosen because:

- They have a well-understood security threat landscape (OWASP ASVS, PCI DSS, open banking threats)
- They naturally require strong authentication, fine-grained authorization, sensitive operation protection, and comprehensive audit trails
- They provide realistic justification for every security mechanism without requiring complex business logic
- The financial context makes it immediately clear to reviewers *why* each control exists and what it protects

The business logic (accounts, balances, transfers) is deliberately minimal and serves only to provide a realistic context for the security subsystem. The system is not intended as a production-ready financial application.

---

## Project Goals

### Primary goals

1. Design and implement a security subsystem demonstrating Zero Trust principles in a web platform context.
2. Implement strong authentication including MFA (TOTP), JWT-based token management with rotation and revocation, and session lifecycle management.
3. Implement contextual authorization: role-based access control combined with resource ownership checks and session validity verification.
4. Implement step-up authentication for sensitive operations.
5. Implement comprehensive audit logging and security event detection.
6. Validate the security subsystem through targeted security tests covering specific attack scenarios.

### Secondary goals

1. Produce architecture and threat model documentation suitable for thesis writing.
2. Demonstrate that security mechanisms are directly traceable to identified threats and security requirements.
3. Provide a minimal but functional frontend to demonstrate the full security flow end-to-end.

---

## Scope Boundaries

### In scope

- User registration, authentication, MFA, session management
- JWT access token and refresh token lifecycle
- Role-based access control (user, auditor, admin)
- Resource ownership enforcement
- Step-up authentication for high-value transfers
- Password reset and credential recovery
- Rate limiting and account lockout
- Audit logging for all security-relevant actions
- Security event detection and storage
- Admin API for user management and security monitoring
- Targeted security test suite

### Out of scope

- Production deployment infrastructure (TLS certificates, cloud hosting)
- Complex financial business logic (multi-currency exchange, interest calculation, scheduled payments)
- Mobile clients
- Real email delivery (demo mode logs tokens to console)
- Machine learning-based anomaly detection
- Regulatory compliance certification (PCI DSS, GDPR compliance assessment)
- Concurrent session limits (post-MVP)
- Frontend beyond a minimal demo UI

---

## Key Terminology

| Term | Definition |
|------|-----------|
| **Zero Trust** | Security model: never trust, always verify. Every access request is authenticated and authorized regardless of network location. |
| **MFA** | Multi-Factor Authentication. Requires a second factor beyond password, here implemented as TOTP. |
| **TOTP** | Time-based One-Time Password. A 6-digit code valid for 30 seconds, generated from a shared secret (RFC 6238). |
| **JWT** | JSON Web Token. A signed, self-contained token used to carry identity and claims between client and server. |
| **Access token** | Short-lived JWT (15 min) proving current authentication. Used in every API request. |
| **Refresh token** | Long-lived opaque token (7 days) used to obtain new access tokens without re-login. Stored hashed. |
| **Step-up authentication** | Additional MFA verification required for high-value operations beyond standard login. Issues a short-lived step-up token. |
| **RBAC** | Role-Based Access Control. Permissions are assigned to roles (user, auditor, admin), not individuals. |
| **Audit log** | Immutable, append-only record of all security-relevant actions with actor, action, result, timestamp, and context. |
| **Security event** | A detected anomaly or policy violation (brute force, token reuse, step-up bypass attempt) stored for monitoring. |
| **STRIDE** | Threat modeling methodology: Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, Elevation of Privilege. |
| **Trust boundary** | A boundary between components where trust assumptions change and verification is required. |
