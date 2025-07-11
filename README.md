﻿# Cybersecurity-Threat-Detection---URL-Masking-Analysis
# 🔗 Advanced URL Masking Detector


A comprehensive security tool to detect and analyze masked URLs with industry-leading 1,483 shortener database.

## 🌟 Features

- **Multi-layer recursive analysis** (5 levels deep)
- **Massive shortener database** (1,483 known services)
- **Advanced detection**:
  - 🚩 URL shorteners (bit.ly, t.co, etc.)
  - 🔄 Redirect parameters (`?url=`, `u=`, `redirect=` etc.)
  - 🕵️ Homograph/Punycode attacks (e.g., `аррӏе.com`)
  - 🔢 IP address masking (`http://192.168.1.1/login`)
  - 📛 Username spoofing (`trusted.com@evil.com/paypal`)
  - 🔐 Encoded URLs (Base64, URL-encoded)
  - 📦 Data URIs (`data:text/html;base64,...`)

## 📦 Installation

### Prerequisites
- Python 3.8+
- pip package manager

### Quick Setup
```bash
git clone https://github.com/Sanjay-Program/Cybersecurity-Threat-Detection---URL-Masking-Analysis.git
cd Cybersecurity-Threat-Detection---URL-Masking-Analysis
pip install -r requirements.txt
```
### Run 
```bash
py mlm.py
```
