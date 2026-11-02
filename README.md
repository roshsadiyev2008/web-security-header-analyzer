
# Web Security Header Analyzer

A Python-based tool for analyzing common HTTP security headers and basic website security configurations.

## Overview

Web Security Header Analyzer is a lightweight command-line tool developed with Python.

It sends an HTTP GET request to a user-provided website and examines the server response. The tool identifies missing security headers, checks HTTPS usage, and analyzes basic cookie security attributes.

This project is designed for educational purposes and helps users understand common web security configurations.

## Features

- Checks common HTTP security headers.
- Detects missing recommended security headers.
- Checks HTTPS usage.
- Analyzes cookie security attributes.
- Displays HTTP response status codes.
- Follows HTTP redirects.
- Generates readable terminal reports.
- Exports analysis results in JSON format.

## Security Headers Analyzed

| HTTP Header | Purpose |
|---|---|
| Strict-Transport-Security | Helps enforce secure HTTPS connections |
| Content-Security-Policy | Helps protect against content injection |
| X-Content-Type-Options | Prevents MIME-type sniffing |
| X-Frame-Options | Helps protect against clickjacking |
| Referrer-Policy | Controls referrer information |
| Permissions-Policy | Controls access to browser features |

## Cookie Security Checks

The tool checks the following cookie attributes:

- **Secure:** Restricts cookie transmission to secure connections.
- **HttpOnly:** Prevents JavaScript access to the cookie.
- **SameSite:** Controls cross-site cookie behavior.

## Requirements

- Python 3.9 or newer
- Requests library

## Installation

Clone the repository:

```bash
git clone https://github.com/roshsadiyev2008/web-security-header-analyzer.git
```

Navigate to the project directory:

```bash
cd web-security-header-analyzer
```

Install the required dependency:

```bash
pip install -r requirements.txt
```

## Usage

Run the analyzer:

```bash
python analyzer.py https://example.com
```

Set a custom request timeout:

```bash
python analyzer.py https://example.com --timeout 15
```

Save the analysis results as a JSON file:

```bash
python analyzer.py https://example.com --json report.json
```

## Example Output

```text
WEB SECURITY HEADER ANALYZER
========================================

Target:      https://example.com
HTTP status: 200
HTTPS:       YES

SECURITY HEADERS
----------------------------------------

[PRESENT] Strict-Transport-Security
[MISSING] Content-Security-Policy
[PRESENT] X-Content-Type-Options
[PRESENT] X-Frame-Options
[PRESENT] Referrer-Policy
[MISSING] Permissions-Policy

SUMMARY
----------------------------------------

Missing recommended headers: 2

This is a basic configuration check,
not a complete security audit.
```

*Note: This is an illustrative example. Actual results depend on the website's response.*

## How It Works

1. The user provides a website URL.
2. The tool sends an HTTP GET request.
3. HTTP redirects are followed automatically.
4. The final server response headers are analyzed.
5. Cookie security attributes are inspected.
6. The results are displayed in the terminal.
7. Results can optionally be exported to JSON.

## Project Structure

```text
web-security-header-analyzer/
│
├── analyzer.py
├── requirements.txt
└── README.md
```

## Limitations

- This tool performs basic HTTP security configuration checks.
- Missing headers do not automatically indicate vulnerabilities.
- It does not perform vulnerability exploitation.
- It does not crawl websites or enumerate directories.
- It does not evaluate the quality of security policies.
- Cookie analysis is limited to cookies visible in the HTTP response.
- It is not a replacement for a complete security assessment.

## Educational Purpose

This project was developed as part of a personal cybersecurity learning journey.

It provides practical experience with Python, HTTP requests, web security headers, and basic security analysis.

## Disclaimer

This tool is intended for educational purposes and authorized security assessments only.

Only analyze websites that you own or have explicit permission to assess.
