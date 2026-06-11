#!/usr/bin/env python3
"""auth_hunter.py - Exam-Grade Login Brute Forcer.

Single-file, stdlib only, threaded, polite. Built for authorized web
pentesting labs / CTFs. Replaces Hydra for simple HTTP login forms when
you need speed under exam pressure.

Not a DoS tool: hard-capped at 20 threads with a per-thread delay.
"""

import argparse
import gzip
import hashlib
import html
import http.client
import os
import queue
import re
import socket
import ssl
import sys
import threading
import time
import urllib.parse
import zlib


# ============================================================
#  ANSI COLORS
# ============================================================
if os.name == 'nt':
    try:
        os.system('')
    except Exception:
        pass

for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding='utf-8', errors='replace')
    except Exception:
        pass


class C:
    R = '\033[0m'
    BOLD = '\033[1m'
    DIM = '\033[2m'
    GREEN = '\033[32m'
    YELLOW = '\033[33m'
    RED = '\033[31m'
    CYAN = '\033[36m'
    MAG = '\033[35m'
    BLUE = '\033[34m'
    GREY = '\033[90m'


def disable_colors():
    for k in list(vars(C).keys()):
        if not k.startswith('_'):
            setattr(C, k, '')


BANNER_TMPL = """{c}
╔══════════════════════════════════════════════════════╗
║         Auth Hunter - Exam-Grade Brute Forcer        ║
║   Threaded | Burp-aware | Combo lists | Auto-detect  ║
║          stdlib only · no DoS · polite               ║
╚══════════════════════════════════════════════════════╝{r}"""


def banner():
    return BANNER_TMPL.format(c=C.CYAN, r=C.R)


# ============================================================
#  ARGPARSE - the help text IS the manual. Read once, never re-read.
# ============================================================
def build_parser():
    epilog = (
        f"\n{C.BOLD}USAGE SCENARIOS{C.R}  (read once before the exam)\n"
        f"\n{C.CYAN}-- A. Single user, password list (most common) --{C.R}\n"
        f"  You know the username (or trying 'admin') and want to brute-force the password.\n"
        f"    {C.GREEN}python auth_hunter.py \\\n"
        f"        -u \"https://site/login.php\" \\\n"
        f"        -l admin -P rockyou.txt \\\n"
        f"        --fail \"Invalid\" --insecure{C.R}\n"
        f"\n{C.CYAN}-- B. User list × password list (cartesian) --{C.R}\n"
        f"    {C.GREEN}python auth_hunter.py -u URL -L users.txt -P pass.txt --fail \"Invalid\"{C.R}\n"
        f"\n{C.CYAN}-- C. Combo list (user:pass per line) --{C.R}\n"
        f"    {C.GREEN}python auth_hunter.py -u URL --combo combos.txt --fail \"Invalid\"{C.R}\n"
        f"\n{C.CYAN}-- D. Burp-captured request --{C.R}\n"
        f"  Save the request, mark the user/pass fields with {C.YELLOW}§USER§{C.R} and {C.YELLOW}§PASS§{C.R}.\n"
        f"  Headers, cookies, CSRF tokens, method, body — all reused verbatim.\n"
        f"    {C.GREEN}python auth_hunter.py --request login.txt \\\n"
        f"        -l admin -P rockyou.txt --fail \"Invalid\"{C.R}\n"
        f"\n{C.CYAN}-- E. No wordlist - use built-in common credentials --{C.R}\n"
        f"  Tries ~15 default user/pass combos (admin:admin, root:root, etc).\n"
        f"    {C.GREEN}python auth_hunter.py -u URL --common-only --fail \"Invalid\"{C.R}\n"
        f"\n{C.BOLD}DETECTION{C.R}  (pick ONE - if none given, auto-baseline kicks in)\n"
        f"  {C.GREEN}--fail \"WORD\"{C.R}       response contains this -> failed login\n"
        f"                       (most reliable: most apps say 'Invalid' / 'incorrect')\n"
        f"  {C.GREEN}--success \"WORD\"{C.R}    response contains this -> WINNER\n"
        f"                       (use when the success page has a clear marker)\n"
        f"  {C.GREEN}--success-status N{C.R}   HTTP status code on success (e.g. 302 redirect)\n"
        f"  {C.GREEN}--fail-status N{C.R}      HTTP status code on failure (e.g. 401)\n"
        f"  {C.DIM}(if none of these, the tool sends one bogus baseline request, then\n"
        f"   flags any later response whose status or length differs significantly){C.R}\n"
        f"\n{C.BOLD}COOKIE SAFETY{C.R}\n"
        f"  Tool echoes parsed cookies before the first request. Press ENTER to start,\n"
        f"  Ctrl-C to abort. {C.DIM}(-y skips the prompt){C.R}\n"
        f"\n{C.BOLD}POLITENESS{C.R}\n"
        f"  Default 8 threads, 0.1s per-thread delay. Hard-capped at 20.\n"
        f"  Authentication endpoints rate-limit aggressively — keep delay >= 0.05.\n"
        f"\n{C.BOLD}EXIT CODES{C.R}\n"
        f"  0  at least one hit      1  zero hits      2  argument / network error\n"
    )

    p = argparse.ArgumentParser(
        prog='auth_hunter.py',
        formatter_class=argparse.RawTextHelpFormatter,
        description=(
            banner()
            + f"\n  {C.BOLD}Exam-grade login brute forcer.{C.R}"
            + f"\n  Built to replace Hydra for simple HTTP forms in exam conditions."
        ),
        epilog=epilog,
        add_help=False,
    )

    g_tgt = p.add_argument_group(f'{C.BOLD}TARGET{C.R}  (use -u OR --request)')
    g_tgt.add_argument(
        '-u', '--url', metavar='URL',
        help='Login endpoint URL.\n'
             '  example:  -u "https://site/login.php"\n'
             'Pair with --user-param / --pass-param if the form fields are not\n'
             'named "username" and "password".',
    )
    g_tgt.add_argument(
        '--request', metavar='FILE',
        help='Path to a Burp-style raw HTTP request file.\n'
             'Put §USER§ and §PASS§ where the credentials go.\n'
             '  example:  --request login.txt\n'
             'Method, URL, headers, cookies, CSRF tokens are reused verbatim.',
    )

    g_cr = p.add_argument_group(f'{C.BOLD}CREDENTIALS{C.R}')
    g_cr.add_argument(
        '-l', '--user', metavar='USER',
        help='Single username to try with every password.\n'
             '  example:  -l admin',
    )
    g_cr.add_argument(
        '-L', '--user-file', metavar='FILE',
        help='Username wordlist (one per line).\n'
             '  example:  -L users.txt',
    )
    g_cr.add_argument(
        '-p', '--pass', dest='pwd', metavar='PASS',
        help='Single password (spray a known password across users).\n'
             '  example:  -p Summer2024!',
    )
    g_cr.add_argument(
        '-P', '--pass-file', dest='pwd_file', metavar='FILE',
        help='Password wordlist (one per line).\n'
             '  example:  -P rockyou.txt',
    )
    g_cr.add_argument(
        '--combo', metavar='FILE',
        help='Combo list: each line "user:pass" (one attempt per line).\n'
             '  example:  --combo creds.txt\n'
             'When used, ignores -l/-L/-p/-P.',
    )
    g_cr.add_argument(
        '--user-param', metavar='NAME', default='username',
        help='Form field name for username. Default: username.\n'
             '  example:  --user-param email',
    )
    g_cr.add_argument(
        '--pass-param', metavar='NAME', default='password',
        help='Form field name for password. Default: password.\n'
             '  example:  --pass-param pwd',
    )
    g_cr.add_argument(
        '--no-common', action='store_true',
        help='Skip the built-in common credentials list (admin:admin, root:root, etc).\n'
             'Default: try common creds FIRST if no explicit creds given.',
    )
    g_cr.add_argument(
        '--common-only', action='store_true',
        help='Try ONLY the built-in common-creds list. Fastest probe.',
    )

    g_det = p.add_argument_group(f'{C.BOLD}DETECTION{C.R}  (pick one or rely on auto-baseline)')
    g_det.add_argument(
        '--fail', dest='fail_grep', metavar='WORD',
        help='Case-insensitive keyword that appears in FAILED logins.\n'
             '  example:  --fail "Invalid credentials"\n'
             'Hit = response does NOT contain this word. Most reliable detection.',
    )
    g_det.add_argument(
        '--success', dest='success_grep', metavar='WORD',
        help='Case-insensitive keyword that appears on SUCCESS.\n'
             '  example:  --success "Welcome"\n'
             'Hit = response DOES contain this word.',
    )
    g_det.add_argument(
        '--success-status', type=int, metavar='N',
        help='HTTP status code that indicates success.\n'
             '  example:  --success-status 302   (redirect after login)',
    )
    g_det.add_argument(
        '--fail-status', type=int, metavar='N',
        help='HTTP status code that indicates failure.\n'
             '  example:  --fail-status 401',
    )
    g_det.add_argument(
        '--length-tolerance', type=int, default=50, metavar='N',
        help='Auto-baseline mode: how many bytes the response length can\n'
             'differ from baseline before flagging as a hit. Default 50.',
    )
    g_det.add_argument(
        '--no-auto-keywords', action='store_true',
        help='Skip the built-in success-keyword scanner.\n'
             'Default: scans every response for words like "congratulations",\n'
             '"successfully", "welcome", "logout", "dashboard", "flag{", etc.\n'
             'Also rules out hits when failure words ("invalid credentials",\n'
             '"login failed", ...) are present.',
    )
    g_det.add_argument(
        '--all', dest='find_all', action='store_true',
        help='Test EVERY combo instead of stopping at first hit.\n'
             'Default: stop the moment any credential pair succeeds.',
    )

    g_net = p.add_argument_group(f'{C.BOLD}NETWORK & SESSION{C.R}')
    g_net.add_argument(
        '-X', '--method', default='POST', choices=['GET', 'POST'],
        help='HTTP method. Default: POST.',
    )
    g_net.add_argument(
        '--cookie', metavar='STR',
        help='Cookie header sent with every request.\n'
             '  example:  --cookie "PHPSESSID=abc; csrf=xyz"',
    )
    g_net.add_argument(
        '--header', metavar='K:V', action='append', default=[],
        help='Extra HTTP header. Repeatable.\n'
             '  example:  --header "X-Forwarded-For: 127.0.0.1"',
    )
    g_net.add_argument(
        '--extra-param', metavar='K=V', action='append', default=[],
        help='Extra form parameter sent with every request. Repeatable.\n'
             '  example:  --extra-param csrf_token=abc --extra-param submit=Login',
    )
    g_net.add_argument(
        '-t', '--threads', type=int, default=8,
        help='Worker threads. Default 8. Hard-capped at 20 (auth endpoints\n'
             'rate-limit fast — too many parallel attempts get you blocked).',
    )
    g_net.add_argument(
        '-d', '--delay', type=float, default=0.1,
        help='Per-thread sleep between requests (seconds). Default 0.1.\n'
             'Raise to 0.5+ for fragile servers / strict WAFs.',
    )
    g_net.add_argument(
        '--timeout', type=float, default=10.0,
        help='Per-request timeout in seconds. Default 10.',
    )
    g_net.add_argument(
        '--insecure', action='store_true',
        help='Skip TLS certificate verification (lab use only).',
    )

    g_out = p.add_argument_group(f'{C.BOLD}OUTPUT{C.R}')
    g_out.add_argument(
        '-o', '--output', metavar='FILE',
        help='Append hits to this file (user:pass + status + length).\n'
             '  example:  -o cracked.txt',
    )
    g_out.add_argument(
        '-v', '--verbose', action='store_true',
        help='Show every attempt (success, failure, errors).',
    )
    g_out.add_argument(
        '--limit', type=int, metavar='N',
        help='Only test the first N combos. Use for a smoke-test.',
    )
    g_out.add_argument(
        '--no-color', action='store_true',
        help='Disable ANSI colors.',
    )
    g_out.add_argument(
        '-y', '--yes', action='store_true',
        help='Skip the cookie-confirmation prompt.',
    )

    g_misc = p.add_argument_group(f'{C.BOLD}MISC{C.R}')
    g_misc.add_argument(
        '-h', '--help', action='help',
        help='Show this help and exit.',
    )
    g_misc.add_argument(
        '--cheatsheet', action='store_true',
        help='Print a one-screen cheat-sheet of the scenarios and exit.',
    )

    return p


# ============================================================
#  COMMON CREDENTIALS  (tried first when no creds given)
# ============================================================
COMMON_USERS = [
    'admin', 'administrator', 'root', 'user', 'test', 'guest',
    'demo', 'aladdin', 'jasmine',
]
COMMON_PASSWORDS = [
    'admin', 'password', 'admin123', '123456', 'root', 'toor',
    'password123', 'Password1', 'changeme', 'test', 'guest',
    'demo', 'letmein', 'qwerty', '12345', 'aladdin', 'jasmine',
    'open sesame', 'opensesame', 'agrabah',
]


def common_combos():
    """Yield (user, pass) pairs. Same-string matches first (admin/admin),
    then known user × known pass cartesian."""
    pairs = []
    seen = set()
    for u in COMMON_USERS:
        if u in COMMON_PASSWORDS and (u, u) not in seen:
            pairs.append((u, u))
            seen.add((u, u))
    for u in COMMON_USERS:
        for p in COMMON_PASSWORDS:
            if (u, p) not in seen:
                pairs.append((u, p))
                seen.add((u, p))
    return pairs


# ============================================================
#  BURP REQUEST FILE PARSER
# ============================================================
USER_MARKERS = ('§USER§', 'FUZZUSER')
PASS_MARKERS = ('§PASS§', 'FUZZPASS')


class ParsedRequest:
    __slots__ = ('method', 'url', 'headers', 'body', 'has_user', 'has_pass')

    def __init__(self, method, url, headers, body, has_user, has_pass):
        self.method = method
        self.url = url
        self.headers = headers
        self.body = body
        self.has_user = has_user
        self.has_pass = has_pass


def _guess_scheme(host):
    return 'http' if host.endswith(':80') else 'https'


def parse_burp_request(path):
    with open(path, 'rb') as f:
        raw = f.read().decode('utf-8', errors='replace')
    raw = raw.replace('\r\n', '\n').replace('\r', '\n')
    if '\n\n' in raw:
        head, body = raw.split('\n\n', 1)
    else:
        head, body = raw, ''
    lines = head.split('\n')
    if not lines or not lines[0].strip():
        raise ValueError('empty request file')
    parts = lines[0].split()
    if len(parts) < 2:
        raise ValueError(f'bad request line: {lines[0]!r}')
    method = parts[0].upper()
    path_q = parts[1]
    headers = {}
    host = None
    for ln in lines[1:]:
        if ':' not in ln:
            continue
        k, _, v = ln.partition(':')
        k = k.strip()
        v = v.strip()
        if not k:
            continue
        headers[k] = v
        if k.lower() == 'host':
            host = v
    if host is None:
        raise ValueError('Host: header missing from request file')
    scheme = _guess_scheme(host)
    url = f'{scheme}://{host}{path_q}'
    header_blob = '\n'.join(f'{k}: {v}' for k, v in headers.items())
    blob = url + '\n' + header_blob + '\n' + body
    has_user = any(m in blob for m in USER_MARKERS)
    has_pass = any(m in blob for m in PASS_MARKERS)
    return ParsedRequest(method, url, headers, body.rstrip('\n'),
                         has_user, has_pass)


def _sub(text, markers, value):
    out = text
    for m in markers:
        out = out.replace(m, value)
    return out


def substitute_creds_url_body(text, user, pwd):
    """URL-encode and substitute markers for URL/body context."""
    u = urllib.parse.quote(user, safe='')
    p = urllib.parse.quote(pwd, safe='')
    return _sub(_sub(text, USER_MARKERS, u), PASS_MARKERS, p)


def substitute_creds_header(text, user, pwd):
    """Substitute markers for header context (no URL encoding, strip CR/LF)."""
    su = (user.replace('\r', '').replace('\n', ''))
    sp = (pwd.replace('\r', '').replace('\n', ''))
    return _sub(_sub(text, USER_MARKERS, su), PASS_MARKERS, sp)


# ============================================================
#  HTTP CLIENT  (thread-local keep-alive — huge speedup)
# ============================================================
DEFAULT_UA = 'Mozilla/5.0 (Auth-Hunter/1.0)'
_tls = threading.local()


def _get_conn(scheme, host, port, timeout, insecure):
    key = (scheme, host, port)
    if getattr(_tls, 'key', None) != key or getattr(_tls, 'conn', None) is None:
        _reset_conn()
        if scheme == 'https':
            ctx = (ssl._create_unverified_context()
                   if insecure else ssl.create_default_context())
            conn = http.client.HTTPSConnection(host, port, timeout=timeout, context=ctx)
        else:
            conn = http.client.HTTPConnection(host, port, timeout=timeout)
        _tls.conn = conn
        _tls.key = key
    return _tls.conn


def _reset_conn():
    c = getattr(_tls, 'conn', None)
    if c is not None:
        try:
            c.close()
        except Exception:
            pass
    _tls.conn = None
    _tls.key = None


def send(method, url, headers, body, timeout, insecure=False,
         follow_redirects=False):
    """Send one HTTP request. Returns (status, body_text, location_header, err)."""
    parsed = urllib.parse.urlparse(url)
    if not parsed.hostname:
        return 0, '', '', f'bad url: {url!r}'
    host = parsed.hostname
    port = parsed.port or (443 if parsed.scheme == 'https' else 80)
    path = parsed.path or '/'
    if parsed.query:
        path += '?' + parsed.query

    h = dict(headers)
    h.setdefault('User-Agent', DEFAULT_UA)
    h.setdefault('Accept', '*/*')
    h.setdefault('Connection', 'keep-alive')
    h.setdefault('Host', host)
    ae = h.get('Accept-Encoding')
    if ae and 'br' in ae.lower():
        h['Accept-Encoding'] = 'gzip, deflate'

    body_bytes = None
    if body and method == 'POST':
        body_bytes = body.encode('utf-8')
        h.setdefault('Content-Type', 'application/x-www-form-urlencoded')
        h['Content-Length'] = str(len(body_bytes))

    for attempt in (1, 2):
        try:
            conn = _get_conn(parsed.scheme, host, port, timeout, insecure)
            conn.request(method, path, body=body_bytes, headers=h)
            resp = conn.getresponse()
            raw = resp.read()
            enc = (resp.getheader('Content-Encoding') or '').lower().strip()
            try:
                if enc == 'gzip':
                    raw = gzip.decompress(raw)
                elif enc == 'deflate':
                    try:
                        raw = zlib.decompress(raw)
                    except zlib.error:
                        raw = zlib.decompress(raw, -zlib.MAX_WBITS)
            except Exception:
                pass
            try:
                text = raw.decode('utf-8', errors='replace')
            except Exception:
                text = ''
            location = resp.getheader('Location') or ''
            return resp.status, text, location, None
        except ssl.SSLError as e:
            return 0, '', '', f'SSL: {e} (try --insecure)'
        except (http.client.HTTPException, ConnectionError,
                socket.error, OSError) as e:
            _reset_conn()
            if attempt == 2:
                return 0, '', '', f'{type(e).__name__}: {e}'
        except Exception as e:
            _reset_conn()
            return 0, '', '', f'{type(e).__name__}: {e}'

    return 0, '', '', 'unknown error'


# ============================================================
#  DETECTION
# ============================================================
class Baseline:
    def __init__(self, status, length, fingerprint):
        self.status = status
        self.length = length
        self.fingerprint = fingerprint


def fingerprint(text):
    return hashlib.md5(text[:2000].encode('utf-8', errors='ignore')).hexdigest()


# High-confidence success indicators scanned automatically when no explicit
# --success / --fail / status detection is given. Case-insensitive substring.
AUTO_SUCCESS_KEYWORDS = [
    'congratulations', 'congrats', 'challenge solved',
    'successfully logged in', 'successfully authenticated',
    'login successful', 'welcome back', 'welcome,',
    'you are logged in', 'you have logged in',
    'authentication successful', 'access granted',
    'logout', 'sign out', 'log out',  # success pages usually expose a logout link
    'dashboard', 'control panel', 'admin panel',
    'flag{', 'ctf{', 'key:', 'your key',
]

# Failure indicators — used to RULE OUT hits when scanning for keywords.
# A response containing any of these is almost certainly NOT a success even
# if it accidentally includes "welcome" elsewhere on the page.
AUTO_FAIL_KEYWORDS = [
    'invalid credentials', 'invalid username', 'invalid password',
    'incorrect password', 'incorrect username',
    'login failed', 'authentication failed', 'wrong password',
    'bad credentials', 'access denied', 'login error',
    'try again', 'username or password',
]


def _scan_keywords(text):
    """Return (hit_keyword_or_None, fail_keyword_or_None) case-insensitive."""
    low = text.lower()
    fail_hit = next((k for k in AUTO_FAIL_KEYWORDS if k in low), None)
    if fail_hit:
        return None, fail_hit
    success_hit = next((k for k in AUTO_SUCCESS_KEYWORDS if k in low), None)
    return success_hit, None


def classify(status, text, location, args, baseline):
    """Return (is_hit, reason_str). Priority: explicit flags > auto-keywords > baseline."""
    # 1. Explicit user-supplied detection (highest priority)
    if args.success_grep:
        if args.success_grep.lower() in text.lower():
            return True, f'success-grep "{args.success_grep}" matched'
        return False, ''
    if args.fail_grep:
        if args.fail_grep.lower() not in text.lower():
            return True, f'fail-grep "{args.fail_grep}" NOT in response'
        return False, ''
    if args.success_status is not None:
        if status == args.success_status:
            return True, f'status {status} == success-status'
        return False, ''
    if args.fail_status is not None:
        if status != args.fail_status:
            return True, f'status {status} != fail-status {args.fail_status}'
        return False, ''

    # 2. Auto-keyword scan (smart default)
    if not args.no_auto_keywords:
        success_kw, fail_kw = _scan_keywords(text)
        if success_kw:
            return True, f'auto-keyword "{success_kw}" found in response'
        # If we see a fail keyword, it's definitely not a hit — short-circuit
        # the baseline check (which could flag noise like dynamic CSRF tokens).
        if fail_kw:
            return False, ''

    # 3. Auto-baseline fallback
    if baseline is not None:
        if status != baseline.status:
            return True, f'status differs ({baseline.status} -> {status})'
        diff = abs(len(text) - baseline.length)
        if diff > args.length_tolerance:
            return True, f'response length differs by {diff} bytes (>{args.length_tolerance})'
        if fingerprint(text) != baseline.fingerprint:
            return True, 'response body fingerprint differs from baseline'
        return False, ''

    return False, 'no detection method configured'


# ============================================================
#  PROGRESS / RESULTS
# ============================================================
class Progress:
    def __init__(self, total):
        self.total = total
        self.done = 0
        self.lock = threading.Lock()
        self.start = time.time()

    def tick(self):
        with self.lock:
            self.done += 1
            self._draw()

    def _draw(self):
        if self.total == 0:
            return
        pct = self.done / self.total
        w = 30
        filled = int(w * pct)
        bar = '#' * filled + '.' * (w - filled)
        elapsed = time.time() - self.start
        rate = self.done / elapsed if elapsed > 0 else 0
        sys.stdout.write(
            f'\r{C.CYAN}[{bar}]{C.R} {self.done}/{self.total} '
            f'({pct * 100:5.1f}%)  {rate:5.1f}/s   '
        )
        sys.stdout.flush()

    def clear(self):
        sys.stdout.write('\r' + ' ' * 80 + '\r')
        sys.stdout.flush()


class Hunt:
    def __init__(self, args):
        self.args = args
        self.hits = []
        self.fails = 0
        self.errors = 0
        self.ssl_warned = False
        self.first_hit_time = None
        self.stop_event = threading.Event()
        self.print_lock = threading.Lock()
        self.list_lock = threading.Lock()
        self.out_fp = None
        if args.output:
            self.out_fp = open(args.output, 'a', encoding='utf-8')
            self.out_fp.write(
                f'\n# auth_hunter run {time.strftime("%Y-%m-%d %H:%M:%S")}\n'
            )

    def close(self):
        if self.out_fp:
            self.out_fp.close()

    def _line(self, msg):
        sys.stdout.write('\r' + ' ' * 80 + '\r')
        print(msg)
        sys.stdout.flush()

    def emit_hit(self, idx, user, pwd, status, length, reason, elapsed):
        with self.list_lock:
            self.hits.append((idx, user, pwd, status, length, reason))
            if self.first_hit_time is None:
                self.first_hit_time = elapsed
        with self.print_lock:
            self._line(f'  {C.GREEN}{C.BOLD}[+ CRACKED]{C.R} #{idx}  '
                       f'{C.DIM}({elapsed:.2f}s){C.R}')
            self._line(f'      {C.BOLD}{C.GREEN}{user} : {pwd}{C.R}')
            self._line(f'      {C.DIM}status={status}  length={length}  '
                       f'why={reason}{C.R}')
        if self.out_fp:
            self.out_fp.write(
                f'#{idx} | {user}:{pwd} | status={status} | len={length} | {reason}\n'
            )
            self.out_fp.flush()
        if not self.args.find_all:
            self.stop_event.set()

    def emit_fail(self, idx, user, pwd, status):
        with self.list_lock:
            self.fails += 1
        if self.args.verbose:
            with self.print_lock:
                self._line(f'  {C.RED}[x fail]{C.R} #{idx} | '
                           f'{user}:{pwd}  status={status}')

    def emit_error(self, idx, user, pwd, err):
        with self.list_lock:
            self.errors += 1
        if ('SSL' in err or 'cert' in err.lower()) and not self.ssl_warned:
            with self.print_lock:
                if not self.ssl_warned:
                    self.ssl_warned = True
                    self._line('')
                    self._line(f'  {C.RED}{C.BOLD}[!] TLS certificate verification failed.{C.R}')
                    self._line(f'  {C.RED}    {err}{C.R}')
                    self._line(f'  {C.YELLOW}    Add {C.BOLD}--insecure{C.R}{C.YELLOW} '
                               f'and re-run.{C.R}')
                    self._line('')
                    self.stop_event.set()
            return
        if self.args.verbose:
            with self.print_lock:
                self._line(f'  {C.MAG}[! err]{C.R} #{idx} | '
                           f'{user}:{pwd}  {err}')


# ============================================================
#  REQUEST BUILDING
# ============================================================
def build_request(template, user, pwd):
    """Return (method, url, headers, body)."""
    mode = template[0]
    if mode == 'req-mode':
        pr = template[1]
        url = substitute_creds_url_body(pr.url, user, pwd)
        body = substitute_creds_url_body(pr.body, user, pwd)
        headers = {k: substitute_creds_header(v, user, pwd)
                   for k, v in pr.headers.items()}
        if pr.method == 'POST':
            headers.pop('Content-Length', None)
            headers.setdefault('Content-Type', 'application/x-www-form-urlencoded')
        return pr.method, url, headers, body

    # url-mode
    _, base_url, user_param, pass_param, extras, base_headers, method = template
    pairs = list(extras) + [(user_param, user), (pass_param, pwd)]
    encoded = urllib.parse.urlencode(pairs)
    if method == 'GET':
        sep = '&' if '?' in base_url else '?'
        return method, base_url + sep + encoded, dict(base_headers), ''
    headers = dict(base_headers)
    headers.setdefault('Content-Type', 'application/x-www-form-urlencoded')
    return method, base_url, headers, encoded


def parse_extras(args_list):
    out = []
    for kv in args_list:
        if '=' not in kv:
            raise ValueError(f'bad --extra-param: {kv!r} (expected K=V)')
        k, _, v = kv.partition('=')
        out.append((k, v))
    return out


def parse_headers(args_list):
    out = {}
    for hv in args_list:
        if ':' not in hv:
            raise ValueError(f'bad --header: {hv!r} (expected K:V)')
        k, _, v = hv.partition(':')
        out[k.strip()] = v.strip()
    return out


def build_base_headers(args):
    headers = {'User-Agent': DEFAULT_UA, 'Accept': '*/*'}
    if args.cookie:
        headers['Cookie'] = args.cookie
    headers.update(parse_headers(args.header))
    return headers


# ============================================================
#  WORKER
# ============================================================
def worker(q, hunt, request_template, baseline, progress, t0):
    args = hunt.args
    while not hunt.stop_event.is_set():
        try:
            idx, user, pwd = q.get_nowait()
        except queue.Empty:
            break
        try:
            if args.verbose:
                with hunt.print_lock:
                    sys.stdout.write('\r' + ' ' * 80 + '\r')
                    print(f'  {C.GREY}[>] #{idx:>5} trying: {user} : {pwd}{C.R}')
            method, url, headers, body = build_request(request_template, user, pwd)
            status, text, location, err = send(
                method, url, headers, body, args.timeout, args.insecure,
            )
            if err is not None:
                hunt.emit_error(idx, user, pwd, err)
            else:
                is_hit, reason = classify(status, text, location, args, baseline)
                if is_hit:
                    hunt.emit_hit(idx, user, pwd, status, len(text),
                                  reason, time.time() - t0)
                else:
                    hunt.emit_fail(idx, user, pwd, status)
        finally:
            progress.tick()
            if args.delay > 0 and not hunt.stop_event.is_set():
                time.sleep(args.delay)
    _reset_conn()


# ============================================================
#  COOKIE SAFETY
# ============================================================
def cookie_safety_check(args):
    if not args.cookie:
        return
    print(f'\n{C.BOLD}-- Cookie safety check --{C.R}')
    parts = [p.strip() for p in args.cookie.split(';') if p.strip()]
    for p in parts:
        if '=' in p:
            k, _, v = p.partition('=')
            redacted = v[:6] + '...' + v[-4:] if len(v) > 12 else v
            print(f'  {C.CYAN}{k.strip()}{C.R} = {redacted}')
    print(f'{C.DIM}These cookies will be sent VERBATIM with every request.{C.R}')
    if args.yes:
        print(f'{C.DIM}--yes given - skipping confirmation.{C.R}\n')
        return
    try:
        input(f'{C.BOLD}Press ENTER to start, Ctrl-C to abort:{C.R} ')
    except (KeyboardInterrupt, EOFError):
        print(f'\n{C.YELLOW}[!] Aborted before any request was sent.{C.R}')
        sys.exit(0)


# ============================================================
#  CHEAT-SHEET
# ============================================================
def cheatsheet():
    return (
        f"\n{C.BOLD}auth_hunter.py - One-Screen Cheat Sheet{C.R}\n"
        f"\n{C.CYAN}1. Single user, password list{C.R}\n"
        f"   python auth_hunter.py -u URL -l admin -P passwords.txt --fail \"Invalid\"\n"
        f"\n{C.CYAN}2. User list × password list{C.R}\n"
        f"   python auth_hunter.py -u URL -L users.txt -P passwords.txt --fail \"Invalid\"\n"
        f"\n{C.CYAN}3. Combo list (user:pass per line){C.R}\n"
        f"   python auth_hunter.py -u URL --combo creds.txt --fail \"Invalid\"\n"
        f"\n{C.CYAN}4. Burp request (§USER§ §PASS§ markers){C.R}\n"
        f"   python auth_hunter.py --request login.txt -l admin -P pass.txt --fail \"Invalid\"\n"
        f"\n{C.CYAN}5. Built-in common creds only (fastest probe){C.R}\n"
        f"   python auth_hunter.py -u URL --common-only --fail \"Invalid\"\n"
        f"\n{C.BOLD}DETECTION FLAGS{C.R}  (pick one)\n"
        f"   --fail \"Invalid\"        response contains this -> failure (most reliable)\n"
        f"   --success \"Welcome\"     response contains this -> winner\n"
        f"   --success-status 302    HTTP code on success (e.g. redirect)\n"
        f"   --fail-status 401\n"
        f"   {C.DIM}(none -> auto-baseline by length/fingerprint){C.R}\n"
        f"\n{C.BOLD}USEFUL{C.R}\n"
        f"   --user-param email    if form field isn't named 'username'\n"
        f"   --pass-param pwd      if form field isn't named 'password'\n"
        f"   --extra-param csrf=X  csrf tokens, hidden inputs, submit names\n"
        f"   --cookie \"...\"        session cookies (echoed before run)\n"
        f"   -t 8 -d 0.1           polite defaults (cap 20 threads)\n"
        f"   -o cracked.txt        save hits for the writeup\n"
        f"   --all                 don't stop at first hit\n"
    )


# ============================================================
#  MAIN
# ============================================================
def main():
    parser = build_parser()
    args = parser.parse_args()

    if args.no_color:
        disable_colors()

    if args.cheatsheet:
        print(cheatsheet())
        return 0

    if not args.url and not args.request:
        print(banner())
        parser.print_help()
        print(f'\n{C.RED}[!] Need either -u URL or --request FILE.{C.R}')
        return 2

    print(banner())

    # Safety caps
    if args.threads < 1:
        args.threads = 1
    if args.threads > 20:
        print(f'{C.YELLOW}[!] --threads {args.threads} capped to 20 (auth-endpoint polite max).{C.R}')
        args.threads = 20
    if args.delay < 0:
        args.delay = 0

    # ---- Build credential pairs ----
    try:
        pairs = build_credential_pairs(args)
    except ValueError as e:
        print(f'{C.RED}[!] {e}{C.R}')
        return 2

    if args.limit:
        pairs = pairs[:args.limit]
    if not pairs:
        print(f'{C.RED}[!] No credentials to try. Pass -l/-L/-p/-P/--combo or skip --no-common.{C.R}')
        return 2

    # ---- Build request template ----
    try:
        extras = parse_extras(args.extra_param)
        extra_headers = parse_headers(args.header)
    except ValueError as e:
        print(f'{C.RED}[!] {e}{C.R}')
        return 2

    if args.request:
        try:
            pr = parse_burp_request(args.request)
        except (OSError, ValueError) as e:
            print(f'{C.RED}[!] --request parse error: {e}{C.R}')
            return 2
        if not (pr.has_user and pr.has_pass):
            print(f'{C.RED}[!] --request file missing markers.{C.R}')
            print(f'    Add §USER§ where the username goes, §PASS§ where the password goes.')
            print(f'    (FUZZUSER / FUZZPASS also accepted.)')
            return 2
        if args.cookie:
            pr.headers['Cookie'] = args.cookie
        for k, v in extra_headers.items():
            pr.headers[k] = v
        pr.headers.setdefault('User-Agent', DEFAULT_UA)
        template = ('req-mode', pr)
        target_desc = f'{pr.method} {pr.url}  (from {args.request})'
    else:
        base_headers = build_base_headers(args)
        template = ('url-mode', args.url, args.user_param, args.pass_param,
                    extras, base_headers, args.method)
        target_desc = (f'{args.method} {args.url}  '
                       f'fields {args.user_param}/{args.pass_param}')

    # ---- Run header ----
    n_common = sum(1 for u, p in pairs if u in COMMON_USERS and p in COMMON_PASSWORDS)
    n_other = len(pairs) - n_common
    stop_mode = 'all (no early stop)' if args.find_all else 'first-hit'
    tls_mode = f'{C.YELLOW}insecure{C.R}' if args.insecure else 'verify-tls'
    det_mode = detection_mode_str(args)
    print(f'{C.BOLD}Target  :{C.R} {target_desc}')
    print(f'{C.BOLD}Combos  :{C.R} {len(pairs)} (common={n_common}, other={n_other})   '
          f'{C.BOLD}Threads:{C.R} {args.threads}   '
          f'{C.BOLD}Delay  :{C.R} {args.delay}s')
    print(f'{C.BOLD}Detect  :{C.R} {det_mode}')
    print(f'{C.BOLD}Mode    :{C.R} stop={stop_mode}   tls={tls_mode}   keep-alive=on')

    cookie_safety_check(args)

    # ---- Auto-baseline if no explicit detection ----
    baseline = None
    if not (args.success_grep or args.fail_grep
            or args.success_status is not None or args.fail_status is not None):
        baseline = run_baseline(args, template)
        if baseline is None:
            return 2

    # ---- Enqueue + run ----
    q = queue.Queue()
    for i, (u, p) in enumerate(pairs, 1):
        q.put((i, u, p))

    progress = Progress(len(pairs))
    hunt = Hunt(args)

    threads = []
    t0 = time.time()
    for _ in range(args.threads):
        t = threading.Thread(
            target=worker, args=(q, hunt, template, baseline, progress, t0),
            daemon=True,
        )
        t.start()
        threads.append(t)
    try:
        for t in threads:
            t.join()
    except KeyboardInterrupt:
        hunt.stop_event.set()
        progress.clear()
        print(f'\n{C.YELLOW}[!] Ctrl-C - stopping. Partial results below.{C.R}\n')

    elapsed = time.time() - t0
    progress.clear()
    hunt.close()

    # ---- Summary ----
    rate = progress.done / elapsed if elapsed > 0 else 0
    print(f'\n{C.BOLD}=========== SUMMARY ==========={C.R}')
    print(f'  Total tried  : {progress.done} / {len(pairs)}   '
          f'{C.DIM}({rate:.1f} req/s){C.R}')
    print(f'  {C.GREEN}[+] Cracked   : {len(hunt.hits)}{C.R}')
    print(f'  {C.RED}[x] Failed    : {hunt.fails}{C.R}')
    print(f'  {C.MAG}[!] Errors    : {hunt.errors}{C.R}')
    print(f'  Time elapsed  : {elapsed:.2f}s')
    if hunt.stop_event.is_set() and hunt.hits and not args.find_all:
        print(f'  {C.DIM}(stopped early on first hit — pass --all to keep going){C.R}')

    if hunt.hits:
        print(f'\n  {C.BOLD}{C.GREEN}CRACKED CREDENTIALS{C.R}')
        for idx, u, p, st, ln, why in hunt.hits:
            print(f'    #{idx} | {C.BOLD}{u} : {p}{C.R} | status={st} len={ln}')
            print(f'         {C.DIM}{why}{C.R}')
        if args.output:
            print(f'\n  Saved to {C.CYAN}{args.output}{C.R}')
        return 0

    print(f'\n  {C.YELLOW}No credentials cracked.{C.R}')
    print(f'  Check: detection mode, cookie/session, account lockout, CSRF token freshness.')
    return 1


# ============================================================
#  CREDENTIAL ASSEMBLY
# ============================================================
def load_lines(path):
    with open(path, 'r', encoding='utf-8', errors='replace') as f:
        return [ln.rstrip('\n')
                for ln in f
                if ln.strip() and not ln.lstrip().startswith('#')]


def build_credential_pairs(args):
    """Return ordered list of (user, pass) tuples. Common combos first."""
    pairs = []
    seen = set()

    def add(u, p):
        if (u, p) not in seen:
            seen.add((u, p))
            pairs.append((u, p))

    # 1. Combo file always wins (one attempt per line, no cartesian)
    if args.combo:
        try:
            for ln in load_lines(args.combo):
                if ':' in ln:
                    u, _, p = ln.partition(':')
                    add(u, p)
                else:
                    add(ln, ln)  # treat as same-string fallback
        except OSError as e:
            raise ValueError(f'Cannot read combo file: {e}')
        if args.limit:
            pairs = pairs[:args.limit]
        return pairs

    # 2. Resolve users
    users = []
    if args.user_file:
        try:
            users = load_lines(args.user_file)
        except OSError as e:
            raise ValueError(f'Cannot read user file: {e}')
    elif args.user:
        users = [args.user]

    # 3. Resolve passwords
    passwords = []
    if args.pwd_file:
        try:
            passwords = load_lines(args.pwd_file)
        except OSError as e:
            raise ValueError(f'Cannot read password file: {e}')
    elif args.pwd:
        passwords = [args.pwd]

    # 4. Common-only short-circuit
    if args.common_only:
        for u, p in common_combos():
            add(u, p)
        return pairs

    # 5. If no explicit creds and not --no-common, use defaults
    if not users and not passwords and not args.no_common:
        for u, p in common_combos():
            add(u, p)
        return pairs

    # 6. Otherwise build cartesian, but prepend common (if allowed)
    if not args.no_common:
        for u, p in common_combos():
            add(u, p)

    if not users:
        raise ValueError('No username given. Use -l USER or -L FILE.')
    if not passwords:
        raise ValueError('No password given. Use -p PASS or -P FILE.')

    for u in users:
        for p in passwords:
            add(u, p)

    return pairs


# ============================================================
#  BASELINE  (auto-detection mode)
# ============================================================
def run_baseline(args, template):
    bogus_user = '__authhunter_baseline_user__'
    bogus_pass = '__authhunter_baseline_pass__'
    print(f'\n{C.CYAN}[*] No --fail / --success given - sending one baseline request '
          f'with bogus creds to fingerprint failure response...{C.R}')
    method, url, headers, body = build_request(template, bogus_user, bogus_pass)
    status, text, _, err = send(method, url, headers, body, args.timeout, args.insecure)
    if err is not None:
        print(f'{C.RED}[!] Baseline request failed: {err}{C.R}')
        if 'SSL' in err:
            print(f'{C.YELLOW}    Add --insecure for self-signed lab certs.{C.R}')
        return None
    bl = Baseline(status=status, length=len(text), fingerprint=fingerprint(text))
    print(f'    baseline status={status}, length={bl.length} bytes, '
          f'fingerprint={bl.fingerprint[:12]}...')
    print(f'    Any later response whose status / length (±{args.length_tolerance}B) /')
    print(f'    body fingerprint differs from this will be flagged as a HIT.\n')
    _reset_conn()
    return bl


def detection_mode_str(args):
    if args.success_grep:
        return f'success-grep "{args.success_grep}"'
    if args.fail_grep:
        return f'fail-grep "{args.fail_grep}" (hit = word NOT in response)'
    if args.success_status is not None:
        return f'success-status={args.success_status}'
    if args.fail_status is not None:
        return f'fail-status={args.fail_status}'
    parts = []
    if not args.no_auto_keywords:
        parts.append(f'auto-keywords ({len(AUTO_SUCCESS_KEYWORDS)} words)')
    parts.append(f'auto-baseline (±{args.length_tolerance}B)')
    return ' + '.join(parts)


if __name__ == '__main__':
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit(130)
