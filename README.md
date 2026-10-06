# API Key Detector 🔍
made in l0v3 bY kArmasec

A Python template to scan websites for exposed API keys, tokens, and secrets in HTML, JavaScript, JSON, and other resources.

## Features
- Detects generic API keys and tokens
- Checks common cloud patterns like AWS, Google, Stripe, GitHub, Slack
- Scans JS, JSON, and linked pages
- Optional recursive scanning on same-domain links
- Saves results as JSON or CSV

## Install
```bash
git clone https://github.com/karmabuild49/api-key-detector.git
cd api-key-detector
pip install -r requirements.txt
```

## Run
```bash
python api_key_detector.py https://example.com
python api_key_detector.py https://example.com --recursive
python api_key_detector.py https://example.com --output json
```

## Important
Have fun

made in l0v3 bY kArmasec
