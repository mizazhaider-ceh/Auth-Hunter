<div align="center">

# 🔓 Auth-Hunter

### Exam-grade login brute forcer. Single file. Zero dependencies.

*Built to replace Hydra for web login forms when the exam clock is running.*

<br>

![Python](https://img.shields.io/badge/Python-3.7%2B-3776AB?style=for-the-badge&logo=python&logoColor=white)
![Dependencies](https://img.shields.io/badge/Dependencies-NONE-2ECC71?style=for-the-badge)
![GUI](https://img.shields.io/badge/GUI-tkinter-9B59B6?style=for-the-badge&logo=windowsterminal&logoColor=white)
![Platform](https://img.shields.io/badge/Windows%20%7C%20Linux%20%7C%20Kali-1F6FEB?style=for-the-badge)
![License](https://img.shields.io/badge/License-MIT-F1C40F?style=for-the-badge)
![Authorized use only](https://img.shields.io/badge/Authorized%20use-ONLY-E74C3C?style=for-the-badge)

```text
╔══════════════════════════════════════════════════════╗
║         Auth Hunter - Exam-Grade Brute Forcer        ║
║   Threaded | Burp-aware | Combo lists | Auto-detect  ║
║          stdlib only · no DoS · polite               ║
╚══════════════════════════════════════════════════════╝
```

</div>

Auth-Hunter is a threaded HTTP login brute forcer built to replace Hydra for
simple web login forms under exam pressure. It is one Python file with zero
dependencies, so it runs anywhere Python 3 runs: Kali, Windows, a fresh exam
VM, a locked-down lab box. No `pip install`, no virtualenv, nothing to break
five minutes before the clock starts.

It is built for **authorized** testing only: web pentesting labs, CTFs, and
exam environments where you have permission to attack the target.

---

## 📖 Table of contents

- [💡 Why this tool exists](#-why-this-tool-exists)
- [🍪 The session cookie warning (read this first)](#-the-session-cookie-warning-read-this-first)
- [⚙️ Install and requirements](#-install-and-requirements)
- [🖥️ Graphical interface (GUI)](#-graphical-interface-gui)
- [🚀 Quick start](#-quick-start)
- [🧭 Finding the fields to attack](#-finding-the-fields-to-attack)
- [🎯 The five usage scenarios](#-the-five-usage-scenarios)
- [🔍 How detection works](#-how-detection-works)
- [🚩 Every flag, explained](#-every-flag-explained)
- [🍪 Cookies and sessions in detail](#-cookies-and-sessions-in-detail)
- [📨 Using a Burp request file](#-using-a-burp-request-file)
- [📤 Output and exit codes](#-output-and-exit-codes)
- [🛡️ Politeness and safety caps](#-politeness-and-safety-caps)
- [🩹 Troubleshooting](#-troubleshooting)
- [👤 Author](#-author)

---

## 💡 Why this tool exists

In an exam you do not have time to fight your tools. Hydra is great, but it
needs the right module, the right form-string syntax, and it gets unhappy with
CSRF tokens, cookies, and odd success conditions. When you are under a timer,
"why is Hydra not matching the failure string" is the last thing you want to
debug.

Auth-Hunter solves the few things that actually matter in a web login exam:

- **It always sends your session cookie verbatim.** Most exam logins only work
  if the request carries the exact `PHPSESSID` the server handed you. Auth-Hunter
  never strips, rotates, or regenerates it. See the warning below, it is the
  single most important thing in this README.
- **It detects success in five different ways**, and if you do not tell it how,
  it figures it out on its own with an auto-baseline.
- **It reads Burp requests directly.** Save the captured request, mark the two
  fields, and every header, cookie, and CSRF token is reused exactly as Burp
  saw it.
- **It is polite by default** so you do not lock out the account or trip the WAF
  in the first ten seconds.
- **The help text is the manual.** Run `-h` once and you never have to re-ask
  what a flag does.

---

## 🍪 The session cookie warning (read this first)

This is written in bold because students lose marks over it every single year.

> ### Treat your session cookie as sacred
>
> **Do NOT change your browser during the exam.** If you absolutely must,
> carry the session over to the new browser by hand. Switching browsers can
> silently drop your session and the exam stops responding.
>
> **Do NOT change your `sessionID` / `PHPSESSID`.** If it changes, the exam
> stops. The challenge state is tied to that one cookie value.
>
> **Treat the cookie as sacred:** never strip it, never regenerate it, never
> let a tool rotate it. Auth-Hunter is built around this rule. It sends your
> cookie exactly as you give it, on every single request, and it shows you the
> cookie it parsed before it sends anything so you can confirm it is the right
> one.

Every request Auth-Hunter sends carries the cookie you pass with `--cookie`
(or the `Cookie:` header inside your `--request` file). It is never touched.
Before the first request goes out, the tool prints the cookie it is about to
use and waits for you to press ENTER. If it looks wrong, press Ctrl-C and fix
it. Nothing has been sent yet.

---

## ⚙️ Install and requirements

- **Python 3.7 or newer.** That is the only requirement.
- No third-party packages. Everything used (`http.client`, `ssl`, `argparse`,
  `threading`) ships with Python itself.

```bash
git clone https://github.com/mizazhaider-ceh/Auth-Hunter.git
cd Auth-Hunter
python auth_hunter.py -h
```

On Windows use `python`, on most Linux boxes use `python3`. Both work.

---

## 🖥️ Graphical interface (GUI)

If you prefer clicking over typing, there is a full graphical front-end:
`auth_hunter_gui.py`. It is also pure standard library (Python's built-in
tkinter), so there is still nothing to install.

```bash
python auth_hunter_gui.py
```

Keep `auth_hunter_gui.py` in the same folder as `auth_hunter.py`. The GUI does
not re-implement anything: it builds the exact `auth_hunter.py` command from the
form you fill in and runs the real tool underneath, streaming its live output
into the window. Whatever the command line does, the GUI does identically.

What you get:

- **Every flag as a form field**, grouped into Target, Credentials, Detection,
  Network and Session, and Output, with a short hint next to each one.
- **A live output panel** with the banner, cracked credentials in green, and the
  running progress shown on the status bar at the bottom.
- **A command preview box** that shows the exact command being run, so you learn
  the command line by using the GUI. There is a Copy button to grab it.
- **A cookie safety dialog**: before the first request, the GUI lists the cookies
  it is about to send (partly redacted) and asks you to confirm, so the session
  cookie stays sacred. Internally it passes `-y` to the engine so nothing hangs
  waiting on a terminal prompt.
- **Run and Stop buttons.** Stop cleanly terminates the run.

The GUI always runs the engine with `--no-color` (so the panel text stays clean)
and `-y` (so the confirmation is handled by the dialog above). Everything else is
exactly what you selected.

---

## 🚀 Quick start

```bash
# Single known user, brute the password, stop on first hit,
# carry your exam session cookie, ignore the lab's self-signed cert.
python auth_hunter.py \
    -u "https://target/login.php" \
    -l admin \
    -P rockyou.txt \
    --fail "Invalid" \
    --cookie "PHPSESSID=your_real_session_value_here" \
    --insecure
```

Read that command top to bottom:

- `-u` is the login URL.
- `-l admin` is the username you are testing.
- `-P rockyou.txt` is the password wordlist.
- `--fail "Invalid"` tells the tool that any response containing the word
  "Invalid" is a failed login, so anything that does NOT contain it is a win.
- `--cookie "PHPSESSID=..."` carries your exam session. This is the part most
  people forget.
- `--insecure` skips TLS certificate checks, which lab servers almost always
  need because they use self-signed certificates.

---

## 🧭 Finding the fields to attack

Auth-Hunter needs the **names of the username and password fields**, and you
read them from the login form's HTML. View Source on the login page (right-click,
View Source, or press `F12`):

```html
<form method="POST" action="/login.php">
    <input name="username" type="text">         <!-- --user-param username -->
    <input name="password" type="password">     <!-- --pass-param password -->
    <input type="submit" value="Log in">
</form>
```

Read the form like a map:

| What you see in the HTML       | What it gives the tool                |
| ------------------------------ | ------------------------------------- |
| `action="/login.php"`          | the `-u` URL                          |
| `<input name="username">`      | `--user-param username` (the default) |
| `<input name="password">`      | `--pass-param password` (the default) |

The field names already default to `username` and `password`, so if the form
uses those exact names you do not need `--user-param` / `--pass-param` at all.
Set them only when the form differs, for example `<input name="email">` means
`--user-param email`. The values you actually try come from `-l` / `-L` (the
usernames) and `-p` / `-P` (the passwords).

---

## 🎯 The five usage scenarios

These are the five shapes nearly every login attack takes. Pick the one that
matches what you know.

### A. Single user, password list (most common)

You know the username, or you are guessing `admin`, and you want to brute the
password.

```bash
python auth_hunter.py -u "https://site/login.php" \
    -l admin -P rockyou.txt --fail "Invalid" --insecure
```

### B. User list times password list (cartesian)

You do not know the username either. Every user is tried against every password.

```bash
python auth_hunter.py -u URL -L users.txt -P pass.txt --fail "Invalid"
```

### C. Combo list (one `user:pass` per line)

You have a list of specific credential pairs, for example from a leak or an
earlier finding. Each line is tried once, with no cartesian expansion.

```bash
python auth_hunter.py -u URL --combo combos.txt --fail "Invalid"
```

### D. Burp-captured request

The cleanest way to handle CSRF tokens, custom headers, and odd field names.
Save the request from Burp, mark the username and password fields with `§USER§`
and `§PASS§`, and the tool replays everything else verbatim.

```bash
python auth_hunter.py --request login.txt \
    -l admin -P rockyou.txt --fail "Invalid"
```

See [Using a Burp request file](#using-a-burp-request-file) for the details.

### E. No wordlist, use the built-in common credentials

A fast first probe. Tries about fifteen classic default pairs like
`admin:admin`, `root:root`, and `root:toor`, plus a few themed entries.

```bash
python auth_hunter.py -u URL --common-only --fail "Invalid"
```

---

## 🔍 How detection works

The single hardest part of brute forcing a login is knowing when you have won.
Auth-Hunter checks for success in a strict priority order. Whatever you specify
explicitly always wins; if you specify nothing, it falls back to being smart.

**Priority order, highest first:**

1. **Explicit flags you set.** Exactly one of these, and it overrides
   everything else:
   - `--success "WORD"` &nbsp;&rarr;&nbsp; a hit is a response that **contains**
     this word (use it when the success page has a clear marker like "Welcome").
   - `--fail "WORD"` &nbsp;&rarr;&nbsp; a hit is a response that does **not**
     contain this word. This is the most reliable option, because almost every
     app says "Invalid" or "incorrect" on a failed login. Prefer this one.
   - `--success-status N` &nbsp;&rarr;&nbsp; a hit is this HTTP status code,
     for example `302` for the redirect after a successful login.
   - `--fail-status N` &nbsp;&rarr;&nbsp; a hit is any status that is **not**
     this code, for example treat everything that is not `401` as a win.

2. **Auto-keyword scan (the smart default).** If you set none of the flags
   above, every response is scanned for high-confidence success words like
   "congratulations", "successfully logged in", "welcome back", "dashboard",
   "logout", "access granted", and CTF markers like `flag{` and `ctf{`. It also
   scans for failure words like "invalid credentials" and "login failed" and
   uses them to **rule out** false positives, so a page that happens to contain
   "welcome" in a footer while also saying "invalid credentials" is correctly
   treated as a failure. Turn this off with `--no-auto-keywords`.

3. **Auto-baseline fallback.** If nothing above decided it, the tool sends one
   request with deliberately bogus credentials before the run starts, records
   that failure response's status, length, and a fingerprint of its body, then
   flags any later response that differs: a different status code, a length that
   differs by more than the tolerance (`--length-tolerance`, default 50 bytes),
   or a different body fingerprint. This is what lets the tool work even when
   you have no idea what the success page looks like.

For the mock exam specifically, the auto-keyword scan already knows
"congratulations" is the success marker, so you can often run with no detection
flag at all and it will just find the win.

---

## 🚩 Every flag, explained

### Target (use `-u` OR `--request`)

| Flag | What it does |
|------|--------------|
| `-u`, `--url URL` | The login endpoint URL. Pair with `--user-param` / `--pass-param` if the form fields are not named `username` and `password`. |
| `--request FILE` | Path to a Burp-style raw HTTP request file. Put `§USER§` and `§PASS§` where the credentials go. Method, URL, headers, cookies, and CSRF tokens are reused verbatim. |

### Credentials

| Flag | What it does |
|------|--------------|
| `-l`, `--user USER` | A single username, tried with every password. Example: `-l admin`. |
| `-L`, `--user-file FILE` | A username wordlist, one per line. |
| `-p`, `--pass PASS` | A single password, sprayed across all users. Example: `-p Summer2024!`. |
| `-P`, `--pass-file FILE` | A password wordlist, one per line. Example: `-P rockyou.txt`. |
| `--combo FILE` | A combo list where each line is `user:pass`, one attempt per line. When used, it ignores `-l/-L/-p/-P`. |
| `--user-param NAME` | The form field name for the username. Default `username`. Example: `--user-param email`. |
| `--pass-param NAME` | The form field name for the password. Default `password`. Example: `--pass-param pwd`. |
| `--no-common` | Skip the built-in common-credentials list. By default, common creds are tried FIRST when no explicit creds are given. |
| `--common-only` | Try ONLY the built-in common-creds list. The fastest probe. |

**How the credential order is built:** unless you pass `--no-common`, the
built-in common pairs are tried first (quick wins like `admin:admin`), then your
explicit users-times-passwords cartesian follows. A `--combo` file overrides all
of this and is tried exactly as written. Duplicate pairs are removed
automatically, so the common list never wastes an attempt your wordlist would
repeat.

### Detection (pick one, or rely on auto-baseline)

| Flag | What it does |
|------|--------------|
| `--success WORD` | Response contains this word means a win. Case-insensitive. |
| `--fail WORD` | Response does not contain this word means a win. Case-insensitive. Most reliable. |
| `--success-status N` | This HTTP status code means a win, for example `302`. |
| `--fail-status N` | Any status that is not this one means a win, for example `401`. |
| `--length-tolerance N` | In auto-baseline mode, how many bytes a response length may differ from the baseline before it counts as a hit. Default 50. |
| `--no-auto-keywords` | Turn off the built-in success/failure keyword scanner. |
| `--all` | Test every combo instead of stopping at the first hit. Default is to stop the moment a credential pair works. |

### Network and session

| Flag | What it does |
|------|--------------|
| `-X`, `--method {GET,POST}` | HTTP method. Default `POST`. |
| `--cookie STR` | The Cookie header sent with every request. Example: `--cookie "PHPSESSID=abc; csrf=xyz"`. This is how you carry your exam session. |
| `--header K:V` | An extra HTTP header. Repeatable. Example: `--header "X-Forwarded-For: 127.0.0.1"`. |
| `--extra-param K=V` | An extra form parameter sent with every request. Repeatable. Use it for CSRF tokens, hidden inputs, and submit-button names. Example: `--extra-param csrf_token=abc --extra-param submit=Login`. |
| `-t`, `--threads N` | Worker threads. Default 8. Hard-capped at 20, because auth endpoints rate-limit quickly and too many parallel attempts get you blocked. |
| `-d`, `--delay N` | Per-thread sleep between requests, in seconds. Default 0.1. Raise to 0.5 or more for fragile servers or strict WAFs. |
| `--timeout N` | Per-request timeout in seconds. Default 10. |
| `--insecure` | Skip TLS certificate verification. Lab use only, but lab use is nearly always, because lab certs are self-signed. |

### Output

| Flag | What it does |
|------|--------------|
| `-o`, `--output FILE` | Append hits to this file (user:pass plus status and length). Good for the writeup. |
| `-v`, `--verbose` | Show every attempt, including failures and errors. |
| `--limit N` | Only test the first N combos. Use it for a quick smoke-test before the full run. |
| `--no-color` | Disable ANSI colors, for logs or terminals that mangle them. |
| `-y`, `--yes` | Skip the cookie-confirmation prompt. Use it only once you have confirmed the cookie is correct. |

### Misc

| Flag | What it does |
|------|--------------|
| `-h`, `--help` | Show the full built-in help, which is a complete manual on its own. |
| `--cheatsheet` | Print a one-screen cheat sheet of the scenarios and exit. |

---

## 🍪 Cookies and sessions in detail

There are two ways to attach a session, and they cover every situation:

1. **`--cookie` on the command line** when you are using `-u`:

   ```bash
   python auth_hunter.py -u URL -l admin -P pass.txt \
       --fail "Invalid" --cookie "PHPSESSID=your_value"
   ```

2. **A `Cookie:` header inside your `--request` file** when you are replaying a
   Burp capture. It is reused exactly as captured. If you also pass `--cookie`
   on the command line, that value takes over the `Cookie` header in the file,
   which is handy when your captured session has expired and you want to swap in
   a fresh one without re-saving the file.

Either way, before the first request the tool prints a **cookie safety check**:
it lists each cookie name with the value partly redacted, reminds you the cookie
will be sent verbatim, and waits for ENTER. This is your last chance to confirm
you are about to attack with the correct session. Press Ctrl-C to abort with
nothing sent. Pass `-y` to skip this prompt once you trust the value.

---

## 📨 Using a Burp request file

This is the most reliable mode for any login with a CSRF token or unusual
fields. Capture the login request in Burp, copy it to a file, and replace the
username and password values with markers.

`login.txt`:

```http
POST /login.php HTTP/1.1
Host: target.lab
Cookie: PHPSESSID=your_real_session_value
Content-Type: application/x-www-form-urlencoded

username=§USER§&password=§PASS§&csrf_token=abc123&submit=Login
```

Then run:

```bash
python auth_hunter.py --request login.txt -l admin -P rockyou.txt --fail "Invalid"
```

Notes that save time:

- The markers are `§USER§` and `§PASS§`. If those characters are awkward to type,
  `FUZZUSER` and `FUZZPASS` are accepted as plain-text equivalents.
- Both markers must be present, or the tool stops and tells you which is missing.
- The scheme is guessed from the `Host` header: a host ending in `:80` is treated
  as `http`, everything else as `https`.
- The `Content-Length` header is recomputed for you on every request, so you do
  not have to keep it accurate in the file.
- Usernames and passwords are URL-encoded when substituted into the URL or body,
  and stripped of stray carriage returns when substituted into headers.

---

## 📤 Output and exit codes

A cracked credential is printed in green with the status code, response length,
and the exact reason it was flagged a win, so you can trust the result rather
than guess at it. With `-o` the same line is appended to your output file,
timestamped per run, ready for the report.

The progress bar shows attempts completed, percentage, and live request rate.
On Ctrl-C the run stops cleanly and prints whatever it found so far.

**Exit codes** (useful for scripting):

| Code | Meaning |
|------|---------|
| `0` | At least one credential cracked. |
| `1` | Zero hits. |
| `2` | Argument or network error (bad flags, unreadable wordlist, baseline request failed). |

---

## 🛡️ Politeness and safety caps

Auth-Hunter is deliberately not a denial-of-service tool.

- Threads default to **8** and are **hard-capped at 20**. Ask for more and it
  quietly clamps to 20 and tells you.
- A per-thread delay of **0.1 seconds** is on by default. Keep it at or above
  0.05 against real auth endpoints, which rate-limit aggressively.
- Connections are kept alive per thread, so you get speed from reuse rather than
  from hammering the server with a flood of new sockets.

If a target is fragile or you are seeing lockouts, drop to `-t 4 -d 0.5` and let
it run slower and safer.

---

## 🩹 Troubleshooting

**Everything reports as a hit, or nothing does.** Your detection method is off.
Prefer `--fail "Invalid"` with the exact failure word from the real page. View
the login response once in the browser, copy a word that only appears on
failure, and pass it.

**TLS certificate error.** Add `--insecure`. Lab and exam servers almost always
use self-signed certificates. The tool also detects this and reminds you.

**No credentials cracked.** Check, in this order: the detection mode, the session
cookie (is it the current one), account lockout from too many attempts, and CSRF
token freshness if the token is single-use. A stale CSRF token makes every
attempt fail regardless of the password.

**The session seems to have died mid-run.** Re-read
[the cookie warning](#the-session-cookie-warning-read-this-first). Do not switch
browsers, do not let anything regenerate the cookie. Grab a fresh `PHPSESSID`,
pass it with `--cookie`, and run again.

**It is too slow or too aggressive.** Tune `-t` (threads) and `-d` (delay).
Lower threads and higher delay are gentler; the reverse is faster but riskier.

---

## 👤 Author

Built by **Muhammad Izaz Haider**, Student of CyberSecurity at Howest, lover of
AI and offensive security.

- GitHub: [@mizazhaider-ceh](https://github.com/mizazhaider-ceh)

Made for students, by a student. If it helped you pass, pass it on.

---

### Legal and ethical use

Auth-Hunter is for **authorized** security testing only: your own systems,
explicit-permission engagements, CTFs, and exam labs where attacking the target
is the point. Brute forcing a login you do not have permission to test is
illegal in most countries. You are responsible for how you use it.

---

<div align="center">

### ⭐ If Auth-Hunter helped you, drop a star and share it with your class.

**Made with care for students, by a student.**

![Built by Muhammad Izaz Haider](https://img.shields.io/badge/Built%20by-Muhammad%20Izaz%20Haider-36C5F0?style=for-the-badge)
![AI x Offensive Security](https://img.shields.io/badge/AI%20x%20Offensive%20Security-9B59B6?style=for-the-badge)

</div>
