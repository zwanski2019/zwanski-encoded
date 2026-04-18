import streamlit as st
import urllib.request
import urllib.parse
import urllib.error
import json
import re
import time

# ─── Page Config ──────────────────────────────────────────────────────────────
st.set_page_config(
    page_title="Zwanski Security Scanner",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

st.markdown("""
<style>
    @import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;700&family=Syne:wght@700;800&display=swap');
    html, body, [class*="css"] { font-family: 'JetBrains Mono', monospace; }
    h1, h2, h3 { font-family: 'Syne', sans-serif !important; }
    .stApp { background: #0a0e17; color: #c9d1d9; }
    .badge-vuln { background:#ff4b4b22;color:#ff4b4b;border:1px solid #ff4b4b55;padding:2px 10px;border-radius:4px;font-size:.75rem; }
    .badge-safe { background:#00c85322;color:#00c853;border:1px solid #00c85355;padding:2px 10px;border-radius:4px;font-size:.75rem; }
    .mono-block { background:#111827;color:#00ff9f;padding:10px 14px;border-radius:6px;font-family:monospace;font-size:.82rem;border-left:3px solid #00ff9f44;word-break:break-all; }
    .stButton > button { background:#1a2233;color:#c9d1d9;border:1px solid #30363d;border-radius:6px;transition:all .2s; }
    .stButton > button:hover { border-color:#00ff9f;color:#00ff9f; }
    .stProgress > div > div { background:linear-gradient(90deg,#00ff9f,#2979ff); }
    .metric-card { background:#111827;border:1px solid #1e2a3a;border-radius:8px;padding:16px;text-align:center; }
    .metric-card .value { font-size:2rem;font-weight:800;font-family:'Syne',sans-serif; }
    .metric-card .label { color:#8b949e;font-size:.8rem;margin-top:4px; }
</style>
""", unsafe_allow_html=True)


# ─── urllib-only HTTP (Pyodide/Streamlit Cloud safe) ──────────────────────────
class Response:
    def __init__(self, status_code: int, text: str, headers: dict):
        self.status_code = status_code
        self.text = text
        self.headers = {k.lower(): v for k, v in headers.items()}
        self.content = text.encode("utf-8", errors="replace")


def http_get(url: str, timeout: int = 10) -> Response | None:
    try:
        req = urllib.request.Request(
            url, headers={"User-Agent": "Mozilla/5.0 (compatible; SecurityAuditBot/1.0)"}
        )
        with urllib.request.urlopen(req, timeout=timeout) as r:
            text = r.read().decode("utf-8", errors="replace")
            return Response(r.status, text, dict(r.headers))
    except urllib.error.HTTPError as e:
        try:
            text = e.read().decode("utf-8", errors="replace")
        except Exception:
            text = ""
        return Response(e.code, text, dict(e.headers) if e.headers else {})
    except Exception:
        return None


# ─── Scanner ──────────────────────────────────────────────────────────────────
class SecurityScanner:
    def __init__(self, base_url: str, timeout: int = 10, rate_limit: float = 0.3):
        self.base_url   = base_url.rstrip("/")
        self.timeout    = timeout
        self.rate_limit = rate_limit

    @staticmethod
    def encode_payload(payload: str, level: int = 1) -> str:
        encoded = urllib.parse.quote(payload, safe="")
        for _ in range(level - 1):
            encoded = encoded.replace("%", "%25")
        return encoded

    def _all_encodings(self, value: str) -> list:
        return [
            {"original": value, "encoded": self.encode_payload(value, lvl), "level": lvl}
            for lvl in (1, 2, 3)
        ]

    PAYLOADS = {
        "sqli":          ["' OR '1'='1", "1' UNION SELECT NULL--", "1 AND 1=1--", "' OR 1=1#"],
        "xss":           ["<script>alert('XSS')</script>", "<img src=x onerror=alert(1)>", "\"><svg onload=alert(1)>"],
        "lfi":           ["../../etc/passwd", "....//....//etc/passwd", "php://filter/convert.base64-encode/resource=index"],
        "rce":           ["; id", "| whoami", "$(id)"],
        "open_redirect": ["//evil.com", "https://evil.com"],
    }

    HIDDEN_PATHS = [
        ".env", ".git/config", ".htaccess", "web.config",
        "wp-config.php", "config.php", "config.yml", "settings.py",
        "db.php", "database.php", "backup.sql", "dump.sql", "db.sql",
        "backup.zip", "www.zip",
        "admin", "admin/login", "administrator", "wp-admin", "panel",
        "phpinfo.php", "info.php", "test.php", "debug.php",
        "error.log", "access.log",
        "api/v1", "api/users", "api/admin",
        "graphql", "swagger", "swagger-ui.html", "openapi.json",
        "actuator", "actuator/env", "metrics", "health",
    ]

    SQL_ERRORS     = ["sql syntax","mysql error","ora-","postgresql error","sqlite",
                      "microsoft sql","odbc driver","unclosed quotation","syntax error"]
    LFI_INDICATORS = ["root:x:","daemon:","/bin/bash","uid=","gid=","[boot loader]"]
    DB_PATTERNS    = ["dbname=","mysql_connect","mysqli_connect","pdo","connectionstring","jdbc:"]

    def _analyse(self, resp: Response) -> tuple:
        ev      = []
        content = resp.text.lower()
        for e in self.SQL_ERRORS:
            if e in content: ev.append(f"SQL error: `{e}`")
        for i in self.LFI_INDICATORS:
            if i in content: ev.append(f"LFI indicator: `{i}`")
        for p in self.DB_PATTERNS:
            if p in content: ev.append(f"DB pattern: `{p}`")
        if "<?php" in resp.text or "<?=" in resp.text:
            ev.append("PHP source code exposed")
        for hdr in ("x-powered-by","x-aspnet-version","x-generator","server"):
            if hdr in resp.headers:
                ev.append(f"Header disclosure → {hdr}: {resp.headers[hdr]}")
        return bool(ev), ev

    def _get(self, url: str) -> Response | None:
        resp = http_get(url, self.timeout)
        time.sleep(self.rate_limit)
        return resp

    def scan_hidden_files(self, progress_cb=None) -> list:
        found = []
        total = len(self.HIDDEN_PATHS)
        for i, path in enumerate(self.HIDDEN_PATHS):
            url  = f"{self.base_url}/{path}"
            resp = self._get(url)
            if resp is not None and resp.status_code in (200, 403):
                vuln, ev = self._analyse(resp)
                found.append({
                    "path": path, "url": url, "status": resp.status_code,
                    "vulnerable": vuln, "evidence": ev, "size": len(resp.content),
                })
            if progress_cb: progress_cb((i + 1) / total)
        return found

    def scan_parameter_injection(self, param: str, progress_cb=None) -> list:
        results = []
        pairs   = [(cat, p) for cat, plist in self.PAYLOADS.items() for p in plist]
        total   = len(pairs) * 3
        idx     = 0
        for cat, payload in pairs:
            for enc in self._all_encodings(payload):
                url  = f"{self.base_url}?{param}={enc['encoded']}"
                resp = self._get(url)
                if resp is None:
                    idx += 1; continue
                vuln, ev = self._analyse(resp)
                if cat == "xss" and payload.lower() in resp.text.lower():
                    vuln = True; ev.append("XSS payload reflected verbatim")
                if cat == "lfi" and any(i in resp.text for i in self.LFI_INDICATORS):
                    vuln = True
                if cat == "rce" and any(x in resp.text for x in ("uid=","gid=")):
                    vuln = True; ev.append("Possible RCE output")
                if vuln:
                    results.append({
                        "category": cat, "payload": payload,
                        "encoded": enc["encoded"], "level": enc["level"],
                        "status": resp.status_code, "evidence": ev,
                    })
                idx += 1
                if progress_cb: progress_cb(idx / total)
        return results

    def scan_endpoints(self, progress_cb=None) -> list:
        endpoints = [
            "/api/users","/api/admin","/api/data","/api/config",
            "/v1/users","/v2/auth","/v1/admin",
            "/graphql","/rest/v1","/swagger-ui.html","/openapi.json",
            "/.git/config","/.env","/admin/config","/admin/db",
            "/actuator","/actuator/env","/actuator/health",
            "/metrics","/health","/status",
        ]
        results = []
        for i, ep in enumerate(endpoints):
            url  = f"{self.base_url}{ep}"
            resp = self._get(url)
            if resp is not None and resp.status_code in (200, 403, 500):
                vuln, ev = self._analyse(resp)
                results.append({
                    "endpoint": ep, "url": url, "method": "GET",
                    "status": resp.status_code, "vulnerable": vuln, "evidence": ev,
                })
            if progress_cb: progress_cb((i + 1) / len(endpoints))
        return results

    def scan_encoding_reflection(self, progress_cb=None) -> list:
        patterns = [
            "%2523test", "%2523data", "%23%23test",
            "%25%32%33test", "%252e%252e%252f",
        ]
        results = []
        for i, pat in enumerate(patterns):
            url  = f"{self.base_url}?q={pat}"
            resp = self._get(url)
            if resp is not None:
                results.append({
                    "pattern": pat, "url": url, "status": resp.status_code,
                    "reflected": pat in resp.text,
                    "encoded_sequences": re.findall(r"%[0-9A-Fa-f]{2}", resp.text)[:10],
                })
            if progress_cb: progress_cb((i + 1) / len(patterns))
        return results


# ─── Session State Defaults ───────────────────────────────────────────────────
for _k in ("scan_done","hidden_files","injections","endpoints","encoding"):
    if _k not in st.session_state:
        st.session_state[_k] = [] if _k != "scan_done" else False


# ─── Sidebar ──────────────────────────────────────────────────────────────────
st.markdown("## 🛡️ Zwanski Security Scanner")
st.markdown(
    "Authorized web application security auditing — `%2523` double-encoding & beyond.\n\n"
    "> ⚠️ **Use only on systems you own or have explicit written permission to test.**"
)
st.divider()

with st.sidebar:
    st.markdown("### ⚙️ Configuration")
    target_url  = st.text_input("Target URL", placeholder="https://example.com")
    scan_types  = st.multiselect(
        "Scan Modules",
        ["Hidden Files","Parameter Injection","Endpoint Discovery","Encoding Reflection"],
        default=["Hidden Files","Endpoint Discovery"],
    )
    test_param  = st.text_input("Injection parameter", value="id")
    timeout_val = st.slider("Request timeout (s)", 3, 30, 10)
    rate_val    = st.slider("Rate limit (s)", 0.1, 2.0, 0.3, 0.1)
    st.divider()
    start_btn = st.button("🚀 Run Scan", type="primary", use_container_width=True)
    clear_btn = st.button("🧹 Clear Results", use_container_width=True)

if clear_btn:
    for _k in ("scan_done","hidden_files","injections","endpoints","encoding"):
        st.session_state[_k] = [] if _k != "scan_done" else False
    st.rerun()

# ─── Run Scan ─────────────────────────────────────────────────────────────────
if start_btn:
    if not target_url:
        st.error("Enter a target URL first.")
    else:
        scanner = SecurityScanner(target_url, timeout=timeout_val, rate_limit=rate_val)
        prog    = st.progress(0.0)
        msg     = st.empty()
        n       = len(scan_types) or 1
        base    = 0.0

        if "Hidden Files" in scan_types:
            msg.info("📁 Scanning hidden files…")
            st.session_state["hidden_files"] = scanner.scan_hidden_files(
                lambda p: prog.progress(min(base + p / n, 1.0)))
            base += 1 / n

        if "Parameter Injection" in scan_types:
            msg.info("💉 Testing parameter injection…")
            st.session_state["injections"] = scanner.scan_parameter_injection(
                test_param, lambda p: prog.progress(min(base + p / n, 1.0)))
            base += 1 / n

        if "Endpoint Discovery" in scan_types:
            msg.info("🔗 Discovering endpoints…")
            st.session_state["endpoints"] = scanner.scan_endpoints(
                lambda p: prog.progress(min(base + p / n, 1.0)))
            base += 1 / n

        if "Encoding Reflection" in scan_types:
            msg.info("🔄 Testing encoding reflection…")
            st.session_state["encoding"] = scanner.scan_encoding_reflection(
                lambda p: prog.progress(min(base + p / n, 1.0)))

        prog.progress(1.0)
        msg.success("✅ Scan complete!")
        st.session_state["scan_done"] = True
        time.sleep(0.6)
        prog.empty(); msg.empty()

# ─── Results ──────────────────────────────────────────────────────────────────
if st.session_state["scan_done"]:
    hf  = st.session_state["hidden_files"]
    inj = st.session_state["injections"]
    ep  = st.session_state["endpoints"]
    enc = st.session_state["encoding"]

    total_vulns = (
        sum(1 for x in hf if x.get("vulnerable")) +
        len(inj) +
        sum(1 for x in ep if x.get("vulnerable"))
    )

    c1, c2, c3, c4 = st.columns(4)
    for col, val, label, color in [
        (c1, total_vulns, "Total Findings",  "#ff4b4b"),
        (c2, len(hf),     "Hidden Files Hit", "#ffa726"),
        (c3, len(inj),    "Injections",       "#ff4b4b"),
        (c4, len(ep),     "Endpoints Found",  "#2979ff"),
    ]:
        with col:
            st.markdown(
                f'<div class="metric-card">'
                f'<div class="value" style="color:{color}">{val}</div>'
                f'<div class="label">{label}</div></div>',
                unsafe_allow_html=True,
            )
    st.divider()

    tab_hf, tab_inj, tab_ep, tab_enc, tab_rpt = st.tabs([
        "📁 Hidden Files","💉 Injections","🔗 Endpoints","🔄 Encoding","📄 Report",
    ])

    with tab_hf:
        st.subheader("Hidden Files & Directories")
        if not hf:
            st.info("No accessible hidden files found.")
        for item in hf:
            icon = "⚠️" if item["vulnerable"] else "📄"
            with st.expander(f"{icon} /{item['path']}  —  {item['status']}  ({item['size']} B)"):
                st.markdown(f'<div class="mono-block">{item["url"]}</div>', unsafe_allow_html=True)
                for e in item["evidence"]: st.markdown(f"- {e}")

    with tab_inj:
        st.subheader("Parameter Injection Findings")
        if not inj:
            st.success("No injection vectors detected.")
        for item in inj:
            with st.expander(f"⚠️ {item['category'].upper()}  •  Level {item['level']}  •  {item['status']}"):
                st.markdown(f"**Payload:** `{item['payload']}`")
                st.markdown(f'<div class="mono-block">{item["encoded"]}</div>', unsafe_allow_html=True)
                for e in item["evidence"]: st.markdown(f"- {e}")

    with tab_ep:
        st.subheader("Endpoint Discovery")
        if not ep:
            st.info("No interesting endpoints found.")
        for item in ep:
            icon = "⚠️" if item["vulnerable"] else "🔗"
            with st.expander(f"{icon} {item['endpoint']}  [{item['status']}]"):
                st.markdown(f'<div class="mono-block">{item["url"]}</div>', unsafe_allow_html=True)
                for e in item["evidence"]: st.markdown(f"- {e}")

    with tab_enc:
        st.subheader("Encoding Reflection")
        if not enc:
            st.info("No encoding data.")
        for item in enc:
            icon = "⚠️" if item.get("reflected") else "🔍"
            with st.expander(f"{icon} `{item['pattern']}`  —  {item['status']}"):
                st.markdown(f'<div class="mono-block">{item["url"]}</div>', unsafe_allow_html=True)
                if item.get("reflected"):
                    st.warning("Pattern reflected in response body!")
                if item.get("encoded_sequences"):
                    st.code(" ".join(item["encoded_sequences"]))

    with tab_rpt:
        st.subheader("JSON Report")
        report = {
            "target": target_url if target_url else "unknown",
            "scan_time": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "summary": {
                "total_findings": total_vulns,
                "hidden_files": len(hf),
                "injections": len(inj),
                "endpoints": len(ep),
            },
            "hidden_files": hf, "injections": inj,
            "endpoints": ep, "encoding_reflection": enc,
        }
        st.download_button(
            "📥 Download JSON Report",
            data=json.dumps(report, indent=2),
            file_name=f"scan_{int(time.time())}.json",
            mime="application/json",
        )
        st.json(report)

else:
    st.markdown("""
    <div style="text-align:center;padding:60px 0;color:#8b949e;">
        <div style="font-size:3rem">🛡️</div>
        <p style="font-family:'Syne',sans-serif;font-size:1.2rem;margin-top:16px">
            Configure a target in the sidebar and click <strong>Run Scan</strong>
        </p>
        <p style="font-size:.85rem;margin-top:8px">
            Authorized targets only — testphp.vulnweb.com · demo.testfire.net
        </p>
    </div>
    """, unsafe_allow_html=True)
