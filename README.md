# GDPR Compliance Checker

A Python tool that performs a basic GDPR compliance check on any website — checking HTTPS enforcement, cookie consent, privacy policy presence, contact information, and data subject rights.

Built by [Olamide Mohammed](https://www.linkedin.com/in/olamidelatifatm) — Founder, TrustGrid Technology Limited.

---

## What It Checks

| Check | Description |
|-------|-------------|
| HTTPS | Verifies the site uses HTTPS encryption |
| Cookie Consent | Detects cookie consent banners and GDPR notices |
| Privacy Policy | Checks for privacy policy link |
| Contact Page | Verifies contact information is accessible |
| Data Subject Rights | Scans privacy policy for rights mentions |
| Tracking Detection | Detects Google Analytics and common trackers |
| Privacy Email | Looks for dedicated privacy contact email |

---

## Installation

```bash
pip install requests beautifulsoup4
```

---

## Usage

```bash
python gdpr_checker.py --url https://example.com
```

---

## Sample Output
