"""Synthetic demo documents. All data below is fake / publicly known test data."""
DEMO_DOCS = {
    "HR onboarding form": """EMPLOYEE ONBOARDING FORM
Name: Rahul Verma
Date of Birth: 14/08/1996
Email: rahul.verma@example.com
Mobile: +91 98765 43210
Aadhaar: 2345 6789 0123
PAN: ABCDE1234F
Passport No: K1234567
Bank: HDFC Bank, A/C No: 50100234567890, IFSC: HDFC0001234
UPI: rahul96@okhdfcbank
Joining date: 01 December 2026. Department: Engineering.""",

    "Customer support chat": """[10:02] Agent: Thanks for contacting us. Can you confirm the card used?
[10:03] Customer: Sure, it's 4111 1111 1111 1111, expiry 09/28.
[10:04] Customer: You can reach me at priya.nair@example.org or 91234 56780.
[10:05] Agent: Your refund order #88231 will be processed in 3 days.
[10:06] Customer: Thanks! Also my UPI is priya@ybl in case card fails.""",

    "Engineering incident note": """INCIDENT 2026-11-02: Staging outage
Root cause: expired credentials in deploy config.
db_host = 10.24.1.15
password: Sup3rS3cret!
AWS key found in repo: AKIAIOSFODNN7EXAMPLE
Contact on-call: devops@example.com
Action: rotate secrets and enable secret scanning.""",

    "Clean document (no PII)": """Quarterly planning notes
We will focus on improving onboarding speed and reducing page load time.
The design review is scheduled for next Tuesday. Order #1042 shipped.""",
}
