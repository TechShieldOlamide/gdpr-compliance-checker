#!/usr/bin/env python3
"""
GDPR Compliance Checker
TrustGrid Technology Limited
https://trustgridhq.com

A basic GDPR compliance checker that scans any website for common
compliance indicators including HTTPS, cookie consent, privacy policy,
data subject rights, and tracking detection.

Usage: python gdpr_checker.py --url https://example.com
"""

import requests
import argparse
import sys
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse


# ── CONFIGURATION ──
TIMEOUT = 10
HEADERS = {
    "User-Agent": "Mozilla/5.0 (compatible; TrustGrid-GDPR-Checker/1.0)"
}

COOKIE_CONSENT_KEYWORDS = [
    "cookie consent", "cookie policy", "we use cookies",
    "gdpr", "accept cookies", "cookie notice",
    "cookiebot", "cookieyes", "onetrust", "cookiebanner",
    "cookie-consent", "cookie_consent", "gdpr-cookie",
    "privacy consent", "consent banner"
]

PRIVACY_POLICY_KEYWORDS = [
    "privacy policy", "privacy notice", "data protection",
    "data privacy", "privacy statement"
]

DATA_RIGHTS_KEYWORDS = [
    "right to access", "right of access", "right to erasure",
    "right to be forgotten", "right to rectification",
    "right to object", "data subject rights", "your rights",
    "right to portability", "withdraw consent"
]

TRACKER_PATTERNS = {
    "Google Analytics": ["google-analytics.com", "googletagmanager.com", "gtag(", "ga("],
    "Facebook Pixel": ["facebook.net/en_US/fbevents", "fbq("],
    "HubSpot": ["hs-scripts.com", "hubspot"],
    "Hotjar": ["hotjar.com", "hj("],
    "Mixpanel": ["mixpanel.com"],
    "Segment": ["segment.com/analytics"],
}

CONSENT_TOOL_PATTERNS = [
    "cookiebot", "onetrust", "cookieyes", "trustarc",
    "usercentrics", "quantcast", "iubenda", "cookiepro"
]


def print_header():
    print("\n" + "="*50)
    print("  GDPR COMPLIANCE CHECKER")
    print("  TrustGrid Technology Limited")
    print("  trustgridhq.com")
    print("="*50)


def check_https(url):
    parsed = urlparse(url)
    if parsed.scheme == "https":
        return True, "HTTPS enforced"
    else:
        return False, "HTTPS not enforced — data transmitted insecurely"


def fetch_page(url):
    try:
        response = requests.get(url, headers=HEADERS, timeout=TIMEOUT)
        soup = BeautifulSoup(response.text, "html.parser")
        return response, soup
    except requests.exceptions.SSLError:
        print(f"  [!] SSL certificate error on {url}")
        return None, None
    except requests.exceptions.ConnectionError:
        print(f"  [!] Could not connect to {url}")
        return None, None
    except requests.exceptions.Timeout:
        print(f"  [!] Request timed out for {url}")
        return None, None
    except Exception as e:
        print(f"  [!] Error fetching {url}: {e}")
        return None, None


def check_cookie_consent(soup, page_text):
    page_lower = page_text.lower()
    for keyword in COOKIE_CONSENT_KEYWORDS:
        if keyword.lower() in page_lower:
            return True, "Cookie consent mechanism detected"
    for pattern in CONSENT_TOOL_PATTERNS:
        if pattern.lower() in page_lower:
            return True, f"Consent management tool detected ({pattern})"
    return False, "No cookie consent banner detected"


def check_privacy_policy(soup, base_url):
    links = soup.find_all("a", href=True)
    for link in links:
        link_text = link.get_text().lower()
        href = link.get("href", "").lower()
        for keyword in PRIVACY_POLICY_KEYWORDS:
            if keyword.lower() in link_text or keyword.lower() in href:
                return True, f"Privacy policy link found"
    return False, "No privacy policy link detected"


def check_contact_page(soup, base_url):
    contact_keywords = ["contact", "contact us", "get in touch", "support", "help"]
    links = soup.find_all("a", href=True)
    for link in links:
        link_text = link.get_text().lower()
        href = link.get("href", "").lower()
        for keyword in contact_keywords:
            if keyword in link_text or "contact" in href:
                return True, "Contact page found"
    return False, "No contact page detected"


def check_data_subject_rights(privacy_url):
    if not privacy_url:
        return False, "Could not check — no privacy policy URL found"
    response, soup = fetch_page(privacy_url)
    if not soup:
        return False, "Could not access privacy policy page"
    page_text = soup.get_text().lower()
    found_rights = []
    for keyword in DATA_RIGHTS_KEYWORDS:
        if keyword.lower() in page_text:
            found_rights.append(keyword)
    if len(found_rights) >= 2:
        return True, f"Data subject rights mentioned ({len(found_rights)} rights found)"
    elif len(found_rights) == 1:
        return False, f"Only 1 data subject right mentioned — incomplete rights section"
    else:
        return False, "No data subject rights section detected in privacy policy"


def check_trackers(page_text):
    found_trackers = []
    has_consent = any(pattern in page_text.lower() for pattern in CONSENT_TOOL_PATTERNS)
    for tracker_name, patterns in TRACKER_PATTERNS.items():
        for pattern in patterns:
            if pattern.lower() in page_text.lower():
                found_trackers.append(tracker_name)
                break
    if not found_trackers:
        return True, "No common trackers detected"
    elif has_consent:
        return True, f"Trackers detected ({', '.join(found_trackers)}) with consent management"
    else:
        return False, f"Trackers detected without consent management: {', '.join(found_trackers)}"


def check_privacy_email(page_text):
    import re
    privacy_email_pattern = r'privacy@[\w\.-]+|dpo@[\w\.-]+|dataprotection@[\w\.-]+'
    matches = re.findall(privacy_email_pattern, page_text.lower())
    if matches:
        return True, f"Privacy contact email found ({matches[0]})"
    return False, "No dedicated privacy contact email found"


def find_privacy_policy_url(soup, base_url):
    links = soup.find_all("a", href=True)
    for link in links:
        link_text = link.get_text().lower()
        href = link.get("href", "")
        for keyword in PRIVACY_POLICY_KEYWORDS:
            if keyword.lower() in link_text or keyword.lower() in href.lower():
                if href.startswith("http"):
                    return href
                else:
                    return urljoin(base_url, href)
    return None


def generate_recommendations(results):
    recommendations = []
    checks = {item["name"]: item["passed"] for item in results}

    if not checks.get("HTTPS"):
        recommendations.append("Install an SSL certificate and enforce HTTPS (critical — required by GDPR Article 32)")
    if not checks.get("Cookie Consent"):
        recommendations.append("Implement a cookie consent banner (required by GDPR Article 7 and ePrivacy Directive)")
    if not checks.get("Privacy Policy"):
        recommendations.append("Add a clearly visible privacy policy link (required by GDPR Article 13/14)")
    if not checks.get("Contact Page"):
        recommendations.append("Add a contact page with clear contact information")
    if not checks.get("Data Subject Rights"):
        recommendations.append("Add a data subject rights section to your privacy policy (GDPR Articles 15-22)")
    if not checks.get("Tracker Check"):
        recommendations.append("Implement consent management before loading trackers (GDPR Article 6 — lawful basis)")
    if not checks.get("Privacy Email"):
        recommendations.append("Add a privacy@ or dpo@ email address for data subject requests")

    return recommendations


def calculate_risk(score, total):
    percentage = (score / total) * 100
    if percentage >= 85:
        return "LOW", percentage
    elif percentage >= 60:
        return "MEDIUM", percentage
    else:
        return "HIGH", percentage


def run_check(url):
    # Ensure URL has scheme
    if not url.startswith("http"):
        url = "https://" + url

    print_header()
    print(f"\nChecking: {url}\n")

    results = []

    # 1. HTTPS Check
    passed, message = check_https(url)
    results.append({"name": "HTTPS", "passed": passed, "message": message})

    # Fetch the page
    response, soup = fetch_page(url)
    if not soup:
        print("  [!] Could not fetch the page. Please check the URL and try again.")
        sys.exit(1)

    page_text = response.text

    # 2. Cookie Consent
    passed, message = check_cookie_consent(soup, page_text)
    results.append({"name": "Cookie Consent", "passed": passed, "message": message})

    # 3. Privacy Policy
    passed, message = check_privacy_policy(soup, url)
    results.append({"name": "Privacy Policy", "passed": passed, "message": message})

    # 4. Contact Page
    passed, message = check_contact_page(soup, url)
    results.append({"name": "Contact Page", "passed": passed, "message": message})

    # 5. Data Subject Rights (checks privacy policy page)
    privacy_url = find_privacy_policy_url(soup, url)
    passed, message = check_data_subject_rights(privacy_url)
    results.append({"name": "Data Subject Rights", "passed": passed, "message": message})

    # 6. Tracker Detection
    passed, message = check_trackers(page_text)
    results.append({"name": "Tracker Check", "passed": passed, "message": message})

    # 7. Privacy Email
    passed, message = check_privacy_email(page_text)
    results.append({"name": "Privacy Email", "passed": passed, "message": message})

    # ── PRINT RESULTS ──
    print("-" * 50)
    score = 0
    for item in results:
        icon = "[✓]" if item["passed"] else "[✗]"
        print(f"  {icon} {item['name']}: {item['message']}")
        if item["passed"]:
            score += 1

    total = len(results)
    risk_level, percentage = calculate_risk(score, total)
    recommendations = generate_recommendations(results)

    print("\n" + "=" * 50)
    print(f"  COMPLIANCE SCORE: {score}/{total} ({percentage:.0f}%)")
    print(f"  RISK LEVEL: {risk_level}")
    print("=" * 50)

    if recommendations:
        print("\n  RECOMMENDATIONS:")
        for i, rec in enumerate(recommendations, 1):
            print(f"  {i}. {rec}")

    print("\n" + "=" * 50)
    print("  For a full GDPR compliance audit:")
    print("  https://trustgridhq.com")
    print("=" * 50 + "\n")

    return score, total, risk_level, recommendations


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="GDPR Compliance Checker by TrustGrid Technology"
    )
    parser.add_argument(
        "--url",
        required=True,
        help="Website URL to check (e.g. https://example.com)"
    )
    args = parser.parse_args()
    run_check(args.url)
