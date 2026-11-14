#!/usr/bin/env python3
"""GUN007 Wildcard agent: deterministic, read-only crypto transaction safety explainer."""
from __future__ import annotations
import argparse
import hashlib
import hmac
import json
import os
import sys
import time
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse

R="\033[0m"; BOLD="\033[1m"; DIM="\033[2m"; RED="\033[91m"; GREEN="\033[92m"; YELLOW="\033[93m"; BLUE="\033[94m"; MAGENTA="\033[95m"; CYAN="\033[96m"; WHITE="\033[97m"
MAX_BODY=65536


def banner():
    print(f"{CYAN}  ██████╗ ██╗   ██╗███╗   ██╗ ██████╗  ██████╗  ███████╗{R}")
    print(f"{CYAN} ██╔════╝ ██║   ██║████╗  ██║██╔═████╗██╔═████╗ ╚══███╔╝{R}")
    print(f"{CYAN} ██║  ███╗██║   ██║██╔██╗ ██║██║██╔██║██║██╔██║   ███╔╝ {R}")
    print(f"{CYAN} ██║   ██║██║   ██║██║╚██╗██║████╔╝██║████╔╝██║  ███╔╝  {R}")
    print(f"{CYAN} ╚██████╔╝╚██████╔╝██║ ╚████║╚██████╔╝╚██████╔╝ ███████╗{R}")
    print(f"{CYAN}  ╚═════╝  ╚═════╝ ╚═╝  ╚═══╝ ╚═════╝  ╚═════╝  ╚══════╝{R}")
    print(f"{YELLOW}  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━{R}")
    print(f"  {BOLD}{WHITE}Wildcard Guard v1.0{R} │ {DIM}Read-only safety triage · no signing · no funds{R}")
    print(f"{YELLOW}  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━{R}")


def header(text):
    print(f"\n{BOLD}{CYAN}╔{'═'*58}╗\n║  {text:<56}║\n╚{'═'*58}╝{R}")


def assess(payload: object) -> dict:
    """Return a deterministic warning assessment; never declares a transaction safe."""
    if not isinstance(payload, dict):
        raise ValueError("request body must be a JSON object")
    findings=[]
    def flag(key, label, severity="warning"):
        val=payload.get(key)
        if val is True or val == "true" or val == 1:
            findings.append({"code": key.upper(), "severity": "critical" if severity=="critical" else "warning", "detail": label})
        elif val is False or val == "false" or val == 0:
            findings.append({"code": key.upper(), "severity": "info", "detail": f"No signal reported: {label.lower()}"})
        else:
            findings.append({"code": key.upper(), "severity": "unknown", "detail": f"Unknown / not provided: {label.lower()}"})
    flag("simulation_failed", "transaction simulation failed", "critical")
    flag("unlimited_approval", "unlimited token approval requested", "critical")
    flag("unverified_contract", "contract source is unverified")
    flag("owner_can_mint", "owner has mint authority")
    flag("owner_can_pause", "owner can pause transfers")
    flag("owner_can_blacklist", "owner can blacklist addresses")
    flag("proxy_admin_present", "upgradeable proxy admin is present")
    flag("recipient_is_new", "recipient is not in the supplied trusted list")
    address=payload.get("contract_address")
    if address is not None and (not isinstance(address,str) or len(address) not in (42,44) or not address.startswith("0x")):
        findings.append({"code":"INVALID_ADDRESS_FORMAT","severity":"warning","detail":"Contract address does not look like a 20-byte hex address; not checked on chain."})
    chain=payload.get("chain")
    if chain is None:
        findings.append({"code":"CHAIN_UNKNOWN","severity":"unknown","detail":"No chain specified; no RPC or contract state was queried."})
    checks={"provided_indicators":len([f for f in findings if f['severity']!='unknown']),"unknown_indicators":len([f for f in findings if f['severity']=='unknown']),"onchain_queries":0,"transaction_submitted":False,"wallet_connected":False}
    return {"agent":"GUN007 Wildcard Guard","version":"1.0.0","disclaimer":"Read-only heuristic triage, not an audit. Unknown means not checked; this agent never signs or submits transactions.","decision":"CAUTION" if any(f['severity'] in ('critical','warning','unknown') for f in findings) else "NO_FLAGS_IN_PROVIDED_INPUT","contract_address":address,"chain":chain,"findings":findings,"checks":checks}


class Handler(BaseHTTPRequestHandler):
    server_version="GUN007WildcardGuard/1.0"
    def _send(self,status,obj,extra=None):
        raw=json.dumps(obj,separators=(",",":"),ensure_ascii=False).encode()
        self.send_response(status); self.send_header("Content-Type","application/json; charset=utf-8"); self.send_header("Content-Length",str(len(raw))); self.send_header("X-Content-Type-Options","nosniff"); self.send_header("Cache-Control","no-store")
        for k,v in (extra or {}).items(): self.send_header(k,v)
        self.end_headers(); self.wfile.write(raw)
    def do_GET(self):
        path=urlparse(self.path).path
        if path=="/health": return self._send(200,{"status":"ok","agent":"GUN007 Wildcard Guard","version":"1.0.0"})
        if path=="/": return self._send(200,{"name":"GUN007 Wildcard Guard","track":"Wildcard","description":"Read-only deterministic wallet and contract safety triage.","endpoint":"/agent","safety":"Never connects a wallet, signs, or broadcasts transactions."})
        return self._send(404,{"error":"not_found"})
    def do_POST(self):
        if urlparse(self.path).path!="/agent": return self._send(404,{"error":"not_found"})
        try: n=int(self.headers.get("Content-Length","-1"))
        except ValueError: return self._send(400,{"error":"invalid_content_length"})
        if n<0 or n>MAX_BODY: return self._send(413,{"error":"body_size_limit","max_bytes":MAX_BODY})
        raw=self.rfile.read(n)
        if len(raw)!=n: return self._send(400,{"error":"incomplete_body"})
        secret=os.environ.get("AGENT_GAMES_HMAC_SECRET","")
        supplied=self.headers.get("x-agent-games-signature","")
        if secret:
            expected=hmac.new(secret.encode(),raw,hashlib.sha256).hexdigest()
            if supplied.startswith("sha256="): supplied=supplied[7:]
            if not hmac.compare_digest(expected,supplied): return self._send(401,{"error":"invalid_signature"})
        try: payload=json.loads(raw)
        except (json.JSONDecodeError,UnicodeDecodeError): return self._send(400,{"error":"invalid_json"})
        try: result=assess(payload)
        except ValueError as e: return self._send(400,{"error":str(e)})
        out=json.dumps(result,separators=(",",":"),ensure_ascii=False).encode()
        hdr={}
        if secret: hdr["x-agent-games-signature"]=hmac.new(secret.encode(),out,hashlib.sha256).hexdigest()
        self._send(200,result,hdr)
    def log_message(self,fmt,*args):
        code=args[1] if len(args)>1 else "?"
        color=GREEN if str(code).startswith("2") else YELLOW if str(code).startswith("4") else RED
        print(f"  {color}[{code}]{R} {self.command} {urlparse(self.path).path}",flush=True)


def main():
    parser=argparse.ArgumentParser(description="GUN007 Wildcard Guard HTTP service")
    parser.add_argument("--host",default="127.0.0.1")
    parser.add_argument("--port",type=int,default=int(os.environ.get("PORT","8787")))
    args=parser.parse_args()
    if args.port<1 or args.port>65535: parser.error("port must be 1..65535")
    banner(); header("STARTUP / READ-ONLY MODE")
    print(f"  [i] Endpoint : http://{args.host}:{args.port}/agent")
    print(f"  [i] Health   : http://{args.host}:{args.port}/health")
    print(f"  [i] HMAC     : {'enabled' if os.environ.get('AGENT_GAMES_HMAC_SECRET') else 'optional / disabled'}")
    print(f"  [!] Chain RPC: not configured; output explicitly identifies unknown fields")
    print(f"  [!] Wallet   : never connected; no transactions can be signed or sent")
    server=ThreadingHTTPServer((args.host,args.port),Handler)
    try:
        print(f"  {GREEN}[OK]{R} Listening; Ctrl-C to stop",flush=True)
        server.serve_forever()
    except KeyboardInterrupt: print(f"\n  {YELLOW}[i]{R} Shutdown requested")
    finally: server.server_close()

if __name__=="__main__": main()
