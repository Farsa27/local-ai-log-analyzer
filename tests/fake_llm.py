"""TEST STUB ONLY - mimics llama-server's API so the pipeline can be tested without a model.
It is never used by the real app. Run: python tests/fake_llm.py  (port 8080)"""
import json, re
from http.server import BaseHTTPRequestHandler, HTTPServer

class H(BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def _send(self, obj):
        b = json.dumps(obj).encode(); self.send_response(200)
        self.send_header("Content-Type", "application/json"); self.end_headers(); self.wfile.write(b)
    def do_GET(self):
        self._send({"status": "ok"} if self.path == "/health" else {"model_path": "fake-test-model.gguf"})
    def do_POST(self):
        body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        if self.path == "/tokenize":
            return self._send({"tokens": list(range(max(1, len(body["content"]) // 4)))})
        if self.path == "/apply-template":
            return self._send({"prompt": "\n".join(m["content"] for m in body["messages"])})
        p = body["prompt"]
        if "<LOG>" not in p:
            return self._send({"content": '{"summary":"test summary","chains":[]}', "tokens_predicted": 10})
        evs = {}
        for n, line in re.findall(r"L(\d+): (.*)", p.split("<LOG>\n")[-1]):
            ip = (re.findall(r"\d+\.\d+\.\d+\.\d+", line) or ["unknown"])[0]
            t = "failed_login" if ("Failed password" in line or "invalid_password" in line) else "successful_login" if ("Accepted password" in line or "auth_result=success" in line) else \
                "sql_injection" if "UNION" in line or "OR 1=1" in line else None
            if t: evs.setdefault((ip, t), []).append(int(n))
        out = [{"type": t, "source": ip, "lines": l, "severity": "Medium", "reason": f"{t} seen"} for (ip, t), l in evs.items()]
        s = json.dumps({"events": out})
        if len(out) > 2: s = s[:-15]  # simulate a truncated reply
        self._send({"content": s, "tokens_predicted": len(s) // 4})

HTTPServer(("127.0.0.1", 8080), H).serve_forever()
