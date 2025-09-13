# Mini WAF (Portfolio)


A tiny reverse-proxy Web Application Firewall built with FastAPI. It inspects requests using simple regex rules, rate limits clients, supports IP ACLs, and logs blocked events.


## Run locally
```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
# Start backend
python demo_app.py # listens on 127.0.0.1:5001
# In another terminal, start the WAF
uvicorn waf:app --host 127.0.0.1 --port 8080