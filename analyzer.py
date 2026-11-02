
#!/usr/bin/env python3
"""A passive checker for common HTTP security headers."""

import argparse
import json
import sys
from datetime import datetime, timezone
from http.cookies import SimpleCookie
from urllib.parse import urlparse

import requests

SECURITY_HEADERS = {
    "Strict-Transport-Security": "HTTP Strict Transport Security (HSTS)",
    "Content-Security-Policy": "Content Security Policy (CSP)",
    "X-Content-Type-Options": "MIME-sniffing protection",
    "X-Frame-Options": "Clickjacking protection",
    "Referrer-Policy": "Referrer policy",
    "Permissions-Policy": "Browser feature permissions",
}


def normalize_url(value):
    """Normalize and validate an HTTP(S) URL."""
    value = value.strip()

    if not value:
        raise ValueError("URL cannot be empty.")

    if "://" not in value:
        value = "https://" + value

    parsed = urlparse(value)

    if parsed.scheme.lower() not in ("http", "https") or not parsed.hostname:
        raise ValueError("Enter a valid HTTP or HTTPS URL.")

    if parsed.username or parsed.password:
        raise ValueError("URLs containing embedded credentials are not supported.")

    return value


def get_cookie_attributes(response):
    """Read cookie flags from Set-Cookie headers."""
    raw_headers = getattr(response.raw, "headers", None)

    if raw_headers is not None and hasattr(raw_headers, "getlist"):
        set_cookie_headers = raw_headers.getlist("Set-Cookie")
    else:
        value = response.headers.get("Set-Cookie")
        set_cookie_headers = [value] if value else []

    results = []

    for cookie_header in set_cookie_headers:
        parsed_cookie = SimpleCookie()

        try:
            parsed_cookie.load(cookie_header)
        except Exception:
            continue

        for morsel in parsed_cookie.values():
            results.append({
                "name": morsel.key,
                "secure": bool(morsel["secure"]),
                "httponly": bool(morsel["httponly"]),
                "samesite": morsel["samesite"] or None,
            })

    return results


def analyze_website(url, timeout):
    """Send one GET request and inspect its response."""
    response = requests.get(
        url,
        timeout=timeout,
        allow_redirects=True,
        headers={
            "User-Agent": "WebSecurityHeaderAnalyzer/1.0"
        },
    )

    headers = response.headers
    header_results = {}
    missing_headers = []

    for header, description in SECURITY_HEADERS.items():
        value = headers.get(header)
        present = bool(value and value.strip())

        header_results[header] = {
            "description": description,
            "present": present,
            "value": value,
        }

        if not present:
            missing_headers.append(header)

    return {
        "target": url,
        "final_url": response.url,
        "status_code": response.status_code,
        "https": urlparse(response.url).scheme.lower() == "https",
        "checked_at": datetime.now(timezone.utc).isoformat(),
        "headers": header_results,
        "missing_headers": missing_headers,
        "cookies": get_cookie_attributes(response),
        "risk_summary": {
            "missing_recommended_headers_count": len(missing_headers),
            "note": "A missing header is not automatically a vulnerability.",
        },
    }


def print_report(report):
    print("\nWEB SECURITY HEADER ANALYZER")
    print("=" * 40)

    print("Target:     ", report["target"])
    print("Final URL:  ", report["final_url"])
    print("HTTP status:", report["status_code"])
    print("HTTPS:      ", "YES" if report["https"] else "NO")

    print("\nSECURITY HEADERS")
    print("-" * 40)

    for header, details in report["headers"].items():
        status = "PRESENT" if details["present"] else "MISSING"

        print(f"[{status}] {header}")

        if details["present"]:
            print(f"        Value: {details['value']}")

    print("\nCOOKIE SECURITY")
    print("-" * 40)

    if not report["cookies"]:
        print("No readable Set-Cookie headers were observed.")
    else:
        for index, cookie in enumerate(report["cookies"], start=1):
            print(
                f"Cookie {index} ({cookie['name']}): "
                f"Secure={cookie['secure']}, "
                f"HttpOnly={cookie['httponly']}, "
                f"SameSite={cookie['samesite'] or 'Not set'}"
            )

    missing_count = report["risk_summary"][
        "missing_recommended_headers_count"
    ]

    print("\nSUMMARY")
    print("-" * 40)
    print(f"Missing recommended headers: {missing_count}")
    print("This is a basic configuration check, not a complete security audit.")
    print("A missing header does not by itself prove a vulnerability.")
    print("=" * 40)


def main():
    parser = argparse.ArgumentParser(
        description="Passively check common HTTP security headers for one URL."
    )

    parser.add_argument(
        "url",
        help="Target URL (only assess systems you own or are authorized to test)",
    )

    parser.add_argument(
        "--timeout",
        type=int,
        default=10,
        help="Request timeout in seconds (default: 10; allowed: 1-60)",
    )

    parser.add_argument(
        "--json",
        dest="json_path",
        help="Optional path for saving a JSON report",
    )

    args = parser.parse_args()

    if not 1 <= args.timeout <= 60:
        parser.error("--timeout must be between 1 and 60 seconds")

    try:
        url = normalize_url(args.url)

        report = analyze_website(url, args.timeout)

        print_report(report)

        if args.json_path:
            with open(args.json_path, "w", encoding="utf-8") as output_file:
                json.dump(
                    report,
                    output_file,
                    indent=4,
                    ensure_ascii=False
                )

            print(f"\nJSON report saved to: {args.json_path}")

    except (ValueError, requests.RequestException, OSError) as error:
        print(f"\nError: {error}", file=sys.stderr)
        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
