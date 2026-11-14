# Sensite: Sensitive Information Detection in Documents (CB-02)

Scans documents for PII, financial data and credentials, scores the risk, redacts the output,
and records each scan on a SHA-256 hash-chained audit ledger.

## Run locally
    pip install -r requirements.txt
    streamlit run app.py

## Detects
Credit/debit cards (Luhn-validated), Aadhaar, PAN, passport, bank account, IFSC, UPI, email, phone, DOB, passwords, API keys, IP addresses.

## Deploy
Push to GitHub, then create an app at share.streamlit.io pointing at `app.py`.
