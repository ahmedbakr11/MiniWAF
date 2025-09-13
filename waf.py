import re
import json
import time
import yaml
import httpx
from collections import defaultdict, deque
from typing import dect, Any, List, Deque
from fastapi import FastAPI, Request, Response
from fastapi.responses import JSONResponse, PlainTextResponse

UPSTREAM = "http://127.0.0.1:5001"
LOG_FILE = "waf.log"
RULES_FILE = "rules.yaml"

app = FastAPI("MiniWAF")

###Load Rules###
with open(RULES_FILE, "r", encoding="utf-8") as f:
    cfg=yaml.safe_load(f)

ip_allowlist = set(cfg.get("ip_allowlist", []))
ip_blocklist = set(cfg.get("ip_blocklist", []))
rate_cfg = cfg.get("rate_limit", {"requests": 30, "window_seconds": 60})
rules_cfg = cfg.get("rules", [])
protected_paths = cfg.get("protected_paths", [])

compiled_rules: List[Dict[str, Any]] = []
for r in rules_cfg:
    compiled = [re.compile(p) for p in r.get("patterns", [])]
    compiled_rules.append({
    "id": r.get("id"),
    "desc": r.get("description", ""),
    "target": set(r.get("target", [])),
    "action": r.get("action", "block"),
    "patterns": compiled,
})

###Rate Limiting###
WINDOW = int(rate_cfg.get("window_seconds", 60))
LIMIT = int(rate_cfg.get("requests", 30))
requests_by_ip: Dict[str, Deque[float]] = defaultdict(deque)


def allow_by_rate(ip: str) -> bool:
    now = time.time()
    dq = requests_by_ip[ip]
    # Remove old timestamps
    # Remove old timestamps
    while dq and now - dq[0] > WINDOW:
        dq.popleft()
        if len(dq) >= LIMIT:
            return False
        dq.append(now)
        return True


###Helpers###
def log_event(event: Dict[str, Any]):
    event["ts"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(json.dumps(event, ensure_ascii=False) + "\n")


async def get_body_text(req: Request) -> str:
    try:
        body = await req.body()
        if not body:
            return ""
        # Try to keep small bodies only to avoid heavy scanning
        if len(body) > 100_000:
            return body[:100_000].decode("utf-8", errors="ignore")
        return body.decode("utf-8", errors="ignore")
    except Exception:
        return ""


###WAF LOGIC###
async def inspect_request(req: Request, body_text: str) -> Dict[str, Any]:
    client_ip = req.client.host if req.client else "unknown"
    path = req.url.path
    query_str = req.url.query

    if client_ip in ip_blocklist:       # Blocklisted IP
        return {"block": True, "reason": "ip_blocklist", "rule_id": "IP-BLOCK"}



    for p in protected_paths:           # Protected paths
        if re.search(p.get("path_regex", "^$"), path):
            if p.get("allowlist_only") and client_ip not in ip_allowlist:
                return {"block": True, "reason": "protected_path", "rule_id": "ACL-ADMIN"}


    if not allow_by_rate(client_ip):    # Rate limit
        return {"block": True, "reason": "rate_limited", "rule_id": "RATE-LIMIT"}



    header_blob = "\n".join([f"{k}: {v}" for k, v in req.headers.items()])  # Inspect headers (sample subset)


    # Apply regex rules
    targets = {
    "path": path,
    "query": query_str,
    "headers": header_blob,
    "body": body_text,
    }
    for rule in compiled_rules:
        for tgt in rule["target"]:
            buf = targets.get(tgt, "")
            for pat in rule["patterns"]:
                if pat.search(buf or ""):
                    return {
                            "block": True,
                            "reason": rule["desc"],
                            "rule_id": rule["id"],
                            "where": tgt,
                            "match": pat.pattern,
                            }


    return {"block": False}


###REVERSE PROXY###


@app.api_route("/{full_path:path}", methods=["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"])
async def proxy(full_path: str, request: Request):
    body_text = await get_body_text(request)
    verdict = await inspect_request(request, body_text)


    client_ip = request.client.host if request.client else "unknown"


    if verdict.get("block"):
        log_event({
        "event": "blocked",
        "rule_id": verdict.get("rule_id"),
        "ip": client_ip,
        "method": request.method,
        "path": "/" + full_path,
        "where": verdict.get("where"),
        "reason": verdict.get("reason"),
        "match": verdict.get("match"),
        })
        return JSONResponse({
        "message": "Request blocked by Mini WAF",
        "rule": verdict.get("rule_id"),
        "reason": verdict.get("reason"),
        }, status_code=403)


    # Forward to upstream
    url = f"{UPSTREAM}/{full_path}"
    if request.url.query:
        url += f"?{request.url.query}"


    headers = dict(request.headers)
    headers.pop("host", None)               # Remove hop-by-hop headers if present (simple subset)


    async with httpx.AsyncClient(follow_redirects=True, timeout=10.0) as client:
        resp = await client.request(request.method, url, content=await request.body(), headers=headers)


   
    if resp.status_code >= 400:              # Log passed request (optional: sample only errors)
        log_event({
        "event": "upstream_error",
        "status": resp.status_code,
        "ip": client_ip,
        "method": request.method,
        "path": "/" + full_path,
        })


    return Response(content=resp.content, status_code=resp.status_code, headers=dict(resp.headers))


###HEALTH CHECK###
@app.get("/__waf_health")
def health():
    return {"ok": True}