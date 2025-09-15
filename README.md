# 🛡️ Mini WAF — Portfolio Project

A lightweight **Web Application Firewall (WAF)** built with **FastAPI**.  
It sits as a **reverse proxy** in front of a deliberately vulnerable demo app, inspecting all requests for malicious patterns such as **XSS, SQL Injection, Path Traversal, and Command Injection**.

---

## 🎥 Project Showcase
![Demo GIF](/media.MINIWAFSNAPSHOTS.gif)  
*Replace `demo.gif` with a screen recording of your WAF blocking attacks.*

---

## 🚀 Features
- **Reverse Proxy**: All traffic passes through the WAF before reaching the backend.  
- **Configurable Rules**: Detection patterns written in `rules.yaml` (easy to extend).  
- **Regex-based Detection**:
  - Cross-Site Scripting (XSS): `<script>`, `onerror=`, `javascript:`  
  - SQL Injection: `UNION SELECT`, `OR 1=1`, `SLEEP(...)`  
  - Path Traversal: `../`, `%2e%2e/`  
  - Command Injection: `; ls`, `&& cat /etc/passwd`  
- **IP Access Control**: Allowlist & blocklist support.  
- **Rate Limiting**: Prevents brute-force attempts per IP.  
- **Protected Paths**: Example — `/admin` only accessible from allowlisted IPs.  
- **Logging**: Blocked and suspicious requests are written to `waf.log`.

---

## ⚡ Setup

### 1. Install dependencies
```bash
python -m venv .venv
.venv\Scripts\activate   # on Windows
pip install -r requirements.txt
