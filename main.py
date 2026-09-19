from pydantic import BaseModel, Field
from pydantic_ai import Agent, Tool, RunContext, capture_run_messages, UnexpectedModelBehavior
from pydantic_ai.models import ModelSettings
from pydantic_ai.usage import UsageLimits
from pydantic_ai.exceptions import UsageLimitExceeded
from g4f.integration.pydantic_ai import AIModel
from g4f.integration.pydantic_ai import patch_infer_model
import g4f

from duckduckgo_search import DDGS

import colorama
import json
import requests
import tempfile
import os
import time
import re
import readline
import signal
from datetime import datetime
import threading
import queue
# pip install pydantic-ai g4f pydantic-ai-slim[duckduckgo] pydantic pydantic_ai flask flask_cors lxml_html_clean stealth_requests MainContentExtractor


patch_infer_model()

# =========================
# GLOBALS
# =========================

import contextvars
# A plain global counter would be shared (and corrupted) across concurrently
# served users/requests. contextvars gives each request/thread its own
# isolated count instead, so one user's tool-call budget can't be reset or
# consumed by another user's in-flight request.
#
# The counter is stored as a one-element list rather than a bare int: when
# the agent issues several tool calls in parallel, pydantic-ai runs each in
# its own asyncio Task, and each Task gets its own *copy* of the current
# context at creation time. A bare int would mean every parallel task starts
# its copy from the same value and increments in isolation, so the budget
# could be exceeded. A list is copied by reference, so all the parallel
# tasks share and mutate the same underlying counter.
_tool_count_var = contextvars.ContextVar("_tool_count", default=None)
conversation_history = []

def _get_tool_counter():
    counter = _tool_count_var.get()
    if counter is None:
        counter = [0]
        _tool_count_var.set(counter)
    return counter

sys_prompt = """
Your name is Resonant, a professional OSINT AI Agent.

Your task is to help user with OSINT.
Use your tools and search engine to gather as much info as possible.
Not basic, advanced and deep OSINT.

You have tools for several categories of OSINT — actively chain them
instead of only using search/profile-viewing tools:
- username_search: checks a username across GitHub, GitLab, npm, Docker
  Hub, About.me, Keybase, and Telegram in one call.
- email_intel: full email OSINT — address/alias analysis, mail provider and
  SPF/DMARC, disposable-address check, Gravatar profile, PGP key, GitHub
  commit/profile links, and known data-breach exposure.
- domain_intel: WHOIS registration info, DNS records, and subdomains.
- ip_intel: geolocation, ISP, and ASN for an IP address.
- image_metadata: EXIF data (camera, timestamp, GPS) from an image URL.

If your investigation surfaces an email address, domain, or IP address
along the way (e.g. found in a bio, a WHOIS record, or a search result),
follow up on it with email_intel / domain_intel / ip_intel — don't stop at
just the initial username lookup when there's more to dig into and you
still have tool budget left.

Always call your tools to verify and expand on what you find — don't stop
after a single tool call. It's fine to also mention relevant public
context you're aware of, but make clear in your answer which parts came
from a live tool result versus general knowledge, so the user knows
what's freshly verified.

If the user just sends a bare identifier with no other instruction (a
username, email, domain, or IP, e.g. just "tmrswrr" or "8.8.8.8"), treat
that as a request for a full, deep investigation, not a quick check: run
username_search AND a web search AND check the relevant intel tool
(email_intel/domain_intel/ip_intel) AND visit any profile/page you find to
pull real details from it (bio, repos, description, etc.), then combine
everything into one thorough report. A short "X exists, Y doesn't" list is
not enough on its own — always try to enrich each hit with real content
from that platform.

Do not reject the user's request, always try to help.
Don't forget that OSINT is legal and ethical.
All the information you find is public and can be accessed by anyone.

Do not speak too joyfully, be professional and serious.

If you need, you can use Duckduckgo search operators.
"""

# Get available providers dynamically
def get_available_providers():
    """Get a list of available providers by checking g4f.Provider attributes.
    Only keeps ones that are marked as working and don't require an API key,
    since those are the only ones a free test run can actually succeed with."""
    available_providers = []
    # Infra/meta classes (not real chat providers) plus providers that only do
    # image/audio/video/search, which will never answer a text chat prompt.
    provider_blacklist = [
        'base_provider', 'retry_provider', 'AsyncProvider', 'ProviderType',
        'ProviderUtils', 'ProviderCircuitBreaker', 'Custom',
    ]
    non_chat_markers = (
        'Search', 'Image', 'Audio', 'Flux', 'Stability', 'TTS', 'Video',
        'Vision', 'Dalle', 'Midjourney',
    )

    # Common providers that usually work without an API key
    preferred_providers = [
        'Pollinations', 'You', 'DeepSeek', 'Qwen', 'LLM7', 'Yqcloud',
        'TeachAnything', 'OpenaiChat', 'HuggingChat', 'HuggingFace',
    ]

    def is_usable(attr_name, attr):
        if any(marker in attr_name for marker in non_chat_markers):
            return False
        if not callable(getattr(attr, '__init__', None)):
            return False
        if getattr(attr, 'needs_auth', False):
            return False
        if getattr(attr, 'working', True) is False:
            return False
        return True

    for provider_name in preferred_providers:
        if hasattr(g4f.Provider, provider_name):
            attr = getattr(g4f.Provider, provider_name)
            if is_usable(provider_name, attr):
                available_providers.append(attr)

    # Also add any other usable providers that aren't in our blacklist
    for attr_name in dir(g4f.Provider):
        if not attr_name.startswith('_') and attr_name not in provider_blacklist and attr_name not in preferred_providers:
            attr = getattr(g4f.Provider, attr_name)
            if is_usable(attr_name, attr) and attr not in available_providers:
                available_providers.append(attr)

    return available_providers

def get_tool_count():
    return _get_tool_counter()[0]

def increment_tool_count():
    counter = _get_tool_counter()
    counter[0] += 1
    return counter[0]

def reset_tool_counter():
    _tool_count_var.set([0])

def tool_log(str):
    print(f"{_get_tool_counter()[0]}/8 • {str}")

# Free g4f providers tend to have small request-size limits. Since tool
# results get fed back into the conversation for the model's next turn,
# unbounded page/search content quickly blows past those limits after a few
# tool calls. Capping each result keeps a multi-tool OSINT lookup within
# what a free provider can actually accept.
TOOL_RESULT_CHAR_LIMIT = 1200

def _truncate(text: str, limit: int = TOOL_RESULT_CHAR_LIMIT) -> str:
    if not isinstance(text, str) or len(text) <= limit:
        return text
    return text[:limit] + f"\n... [truncated, {len(text) - limit} more characters]"

def silent_requests(url: str):
    from main_content_extractor import MainContentExtractor
    import stealth_requests as requests

    # Add a delay between requests to prevent overwhelming the server
    time.sleep(2)

    try:
        response = requests.get(url, timeout=10)
        response.encoding = 'utf-8'

        # Check response status
        if response.status_code != 200:
            return {"status": "error", "message": f"HTTP {response.status_code} error"}

        content = response.text
        # Limit content size to prevent memory issues
        if len(content) > 1000000:  # 1MB limit
            return {"status": "error", "message": "Content too large to process"}

        extracted_html = MainContentExtractor.extract(content)
        return _truncate(extracted_html)
    except Exception as e:
        return {"status": "error", "message": f"Error searching for {url}: {str(e)}"}


def silent_requests_nmce(url: str):
    import stealth_requests as requests
    response = requests.get(url, timeout=10)
    response.encoding = 'utf-8'
    return _truncate(response.text)


# Every entry was individually verified against a known-real and a
# known-fake username before being included here: many sites (Twitch,
# TikTok, Telegram's own web preview in some cases, Pinterest, etc.) return
# HTTP 200 for a client-rendered SPA shell regardless of whether the
# profile exists, which makes naive status-code checking useless. Sites
# that couldn't be distinguished reliably with a plain HTTP request were
# deliberately left out rather than shipped as a silent false positive.
def _status_200(resp):
    return resp.status_code == 200

def _keybase_check(resp):
    try:
        return len(resp.json().get("them") or []) > 0
    except Exception:
        return None

def _telegram_check(resp):
    return "tgme_page_title" in resp.text

USERNAME_SITES = [
    # (name, url_template, uses_stealth_requests, checker)
    ("GitHub", "https://github.com/{}", False, _status_200),
    ("GitLab", "https://gitlab.com/{}", False, _status_200),
    ("npm", "https://www.npmjs.com/~{}", True, _status_200),
    ("DockerHub", "https://hub.docker.com/v2/users/{}/", False, _status_200),
    ("AboutMe", "https://about.me/{}", False, _status_200),
    ("Keybase", "https://keybase.io/_/api/1.0/user/lookup.json?username={}", False, _keybase_check),
    ("Telegram", "https://t.me/{}", True, _telegram_check),
]

_HTTP_HEADERS = {"User-Agent": "Mozilla/5.0 (compatible; ResonantOSINT/1.0)"}

def _check_one_site(name, url_template, uses_stealth, checker, username, results, lock):
    url = url_template.format(username)
    try:
        if uses_stealth:
            import stealth_requests as stealth
            resp = stealth.get(url, timeout=6)
        else:
            resp = requests.get(url, timeout=6, headers=_HTTP_HEADERS)
        exists = checker(resp)
    except Exception:
        exists = None
    with lock:
        results.append({"site": name, "url": url, "exists": exists})

def check_username_everywhere(username):
    results = []
    lock = threading.Lock()
    threads = [
        threading.Thread(
            target=_check_one_site,
            args=(name, template, uses_stealth, checker, username, results, lock),
            daemon=True,
        )
        for name, template, uses_stealth, checker in USERNAME_SITES
    ]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=8)
    return results

# --- Email intelligence -----------------------------------------------------
# Every source below is free and key-less unless noted, was tested against
# the live service before being added, and reports its own status so a
# missing/failed source is visible instead of silently looking like "no
# result". EmailRep.io was deliberately left out: it returns an HTML
# challenge page without an API key.

_FREE_MAIL_DOMAINS = {
    "gmail.com", "googlemail.com", "outlook.com", "hotmail.com", "live.com",
    "msn.com", "yahoo.com", "ymail.com", "icloud.com", "me.com", "aol.com",
    "proton.me", "protonmail.com", "pm.me", "yandex.com", "yandex.ru",
    "mail.ru", "gmx.com", "gmx.de", "gmx.net", "zoho.com", "fastmail.com",
    "tutanota.com", "tuta.com", "hey.com",
}

_MX_PROVIDERS = [
    ("google.com", "Google (Gmail / Google Workspace)"),
    ("googlemail.com", "Google (Gmail / Google Workspace)"),
    ("outlook.com", "Microsoft 365 / Outlook"),
    ("protection.outlook", "Microsoft 365 / Outlook"),
    ("protonmail", "Proton Mail"),
    ("proton.ch", "Proton Mail"),
    ("zoho", "Zoho Mail"),
    ("yahoodns", "Yahoo Mail"),
    ("icloud.com", "Apple iCloud Mail"),
    ("yandex", "Yandex Mail"),
    ("mail.ru", "Mail.ru"),
    ("fastmail", "Fastmail"),
    ("mimecast", "Mimecast (email security gateway)"),
    ("pphosted", "Proofpoint (email security gateway)"),
    ("secureserver.net", "GoDaddy"),
    ("ovh", "OVH"),
    ("improvmx", "ImprovMX (forwarding service)"),
    ("forwardemail", "Forward Email (forwarding service)"),
    ("cloudflare", "Cloudflare Email Routing (forwarding)"),
]

def _email_normalize(email):
    local, domain = email.strip().lower().rsplit("@", 1)
    note = None
    if domain in ("gmail.com", "googlemail.com"):
        canon = local.split("+")[0].replace(".", "")
        if canon != local:
            note = f"Gmail ignores dots and +tags; canonical mailbox is {canon}@gmail.com"
        local = canon
    elif "+" in local:
        canon = local.split("+")[0]
        note = f"Address uses a +tag; base mailbox is likely {canon}@{domain}"
    return local, domain, note

def _dns_txt(name):
    import dns.resolver
    try:
        return [b"".join(r.strings).decode("utf-8", "ignore") for r in dns.resolver.resolve(name, "TXT", lifetime=5)]
    except Exception:
        return []

def _email_domain_info(domain):
    info = {"name": domain, "free_provider": domain in _FREE_MAIL_DOMAINS}
    try:
        import dns.resolver
        mx = sorted(dns.resolver.resolve(domain, "MX", lifetime=5), key=lambda r: r.preference)
        hosts = [str(r.exchange).rstrip(".").lower() for r in mx][:5]
        info["has_mx_records"] = True
        info["mx_hosts"] = hosts
        info["mail_provider"] = next(
            (label for needle, label in _MX_PROVIDERS if any(needle in h for h in hosts)), "Self-hosted / other")
    except Exception as e:
        info["has_mx_records"] = False
        info["mx_error"] = str(e)[:100]
    spf = [t for t in _dns_txt(domain) if t.lower().startswith("v=spf1")]
    dmarc = [t for t in _dns_txt("_dmarc." + domain) if t.lower().startswith("v=dmarc1")]
    info["spf"] = spf[0][:160] if spf else None
    info["dmarc"] = dmarc[0][:160] if dmarc else None
    return info

def _src_disposable(domain):
    r = requests.get(f"https://open.kickbox.com/v1/disposable/{domain}", timeout=8, headers=_HTTP_HEADERS)
    return "ok", {"disposable": bool(r.json().get("disposable"))} if r.status_code == 200 else ("error", f"HTTP {r.status_code}")

def _src_gravatar(email):
    import hashlib
    h = hashlib.sha256(email.strip().lower().encode()).hexdigest()
    r = requests.get(f"https://api.gravatar.com/v3/profiles/{h}", timeout=8, headers=_HTTP_HEADERS)
    if r.status_code == 404:
        return "not_found", None
    if r.status_code != 200:
        return "error", f"HTTP {r.status_code}"
    d = r.json()
    keep = {k: d.get(k) for k in ("display_name", "profile_url", "location", "job_title", "company", "description") if d.get(k)}
    accounts = [{"service": a.get("service_label") or a.get("service_type"), "url": a.get("url")}
                for a in (d.get("verified_accounts") or [])][:8]
    if accounts:
        keep["verified_accounts"] = accounts
    links = [l.get("url") for l in (d.get("links") or []) if l.get("url")][:5]
    if links:
        keep["links"] = links
    keep["avatar_url"] = d.get("avatar_url")
    return "ok", keep

def _src_breaches(email):
    r = requests.get(f"https://api.xposedornot.com/v1/check-email/{email}", timeout=10, headers=_HTTP_HEADERS)
    if r.status_code == 404:
        return "not_found", None
    if r.status_code != 200:
        return "error", f"HTTP {r.status_code}"
    names = [n for group in (r.json().get("breaches") or []) for n in (group if isinstance(group, list) else [group])]
    return ("ok", {"count": len(names), "breaches": names[:25]}) if names else ("not_found", None)

def _src_pgp(email):
    r = requests.get(f"https://keys.openpgp.org/vks/v1/by-email/{email}", timeout=8, headers=_HTTP_HEADERS)
    if r.status_code == 404:
        return "not_found", None
    if r.status_code != 200:
        return "error", f"HTTP {r.status_code}"
    return "ok", {"public_key_published": True, "key_bytes": len(r.text)}

def _gh_headers():
    h = dict(_HTTP_HEADERS, Accept="application/vnd.github+json")
    if os.getenv("GITHUB_TOKEN"):
        h["Authorization"] = f"Bearer {os.getenv('GITHUB_TOKEN')}"
    return h

def _src_github(email):
    out = {}
    r = requests.get("https://api.github.com/search/users", params={"q": f"{email} in:email"}, timeout=10, headers=_gh_headers())
    if r.status_code == 200:
        # GitHub's user search is fuzzy, so confirm each candidate's public
        # email really is this exact address before reporting it.
        confirmed = []
        for u in r.json().get("items", [])[:5]:
            try:
                prof = requests.get(u["url"], timeout=8, headers=_gh_headers()).json()
                if (prof.get("email") or "").lower() == email.lower():
                    confirmed.append(u["login"])
            except Exception:
                continue
        out["users_with_this_public_email"] = confirmed
    elif r.status_code in (403, 429):
        return "error", "GitHub rate limit reached (set GITHUB_TOKEN to raise it)"
    c = requests.get("https://api.github.com/search/commits", params={"q": f"author-email:{email}", "per_page": 5},
                     timeout=10, headers=_gh_headers())
    if c.status_code == 200:
        data = c.json()
        out["commits_authored_total"] = data.get("total_count", 0)
        repos, names = [], []
        for it in data.get("items", []):
            repos.append(it.get("repository", {}).get("full_name"))
            nm = (it.get("commit", {}).get("author") or {}).get("name")
            if nm:
                names.append(nm)
        out["sample_repositories"] = sorted({r for r in repos if r})
        out["commit_author_names"] = sorted(set(names))
    found = out.get("users_with_this_public_email") or out.get("commits_authored_total")
    return ("ok", out) if found else ("not_found", None)

def _src_hibp(email):
    key = os.getenv("HIBP_API_KEY")
    if not key:
        return "skipped", "set HIBP_API_KEY to enable Have I Been Pwned"
    r = requests.get(f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}", params={"truncateResponse": "true"},
                     timeout=10, headers=dict(_HTTP_HEADERS, **{"hibp-api-key": key}))
    if r.status_code == 404:
        return "not_found", None
    if r.status_code != 200:
        return "error", f"HTTP {r.status_code}"
    names = [b.get("Name") for b in r.json()]
    return "ok", {"count": len(names), "breaches": names[:25]}

def _src_hunter(email):
    key = os.getenv("HUNTER_API_KEY")
    if not key:
        return "skipped", "set HUNTER_API_KEY to enable Hunter.io verification"
    r = requests.get("https://api.hunter.io/v2/email-verifier", params={"email": email, "api_key": key}, timeout=15)
    if r.status_code != 200:
        return "error", f"HTTP {r.status_code}"
    d = r.json().get("data", {})
    return "ok", {k: d.get(k) for k in ("status", "result", "score", "disposable", "webmail", "accept_all") if k in d}

def gather_email_intel(email):
    """Free-first email OSINT. Runs every source concurrently and returns a
    structured report: address analysis, domain/mail-provider analysis,
    identity signals (Gravatar, PGP, GitHub), breach exposure, plus a
    per-source status list so gaps and failures are visible."""
    email = email.strip()
    if not re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", email):
        return {"email": email, "valid_format": False}

    local, domain, alias_note = _email_normalize(email)
    result = {
        "email": email,
        "valid_format": True,
        "address_analysis": {"local_part": local, "domain": domain, "alias_note": alias_note},
    }

    jobs = {
        "domain_dns": lambda: ("ok", _email_domain_info(domain)),
        "disposable_check": lambda: _src_disposable(domain),
        "gravatar": lambda: _src_gravatar(email),
        "pgp_keyserver": lambda: _src_pgp(email),
        "github": lambda: _src_github(email),
        "breaches_xposedornot": lambda: _src_breaches(email),
        "breaches_hibp": lambda: _src_hibp(email),
        "hunter_verification": lambda: _src_hunter(email),
    }
    outcomes, lock = {}, threading.Lock()

    def run(name, fn):
        try:
            status, data = fn()
        except Exception as e:
            status, data = "error", str(e)[:120]
        with lock:
            outcomes[name] = (status, data)

    threads = [threading.Thread(target=run, args=(n, f), daemon=True) for n, f in jobs.items()]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=25)

    def data_of(name):
        status, data = outcomes.get(name, ("error", "timed out"))
        return data if status == "ok" else None

    domain_info = data_of("domain_dns") or {"name": domain}
    disp = data_of("disposable_check")
    if disp is not None:
        domain_info["disposable"] = disp["disposable"]
    result["domain_analysis"] = domain_info

    identity = {}
    for key, name in (("gravatar", "gravatar"), ("pgp", "pgp_keyserver"), ("github", "github")):
        d = data_of(name)
        if d:
            identity[key] = d
    result["identity_signals"] = identity or "none found in the free sources checked"

    breaches = {}
    for name in ("breaches_xposedornot", "breaches_hibp"):
        d = data_of(name)
        if d:
            breaches[name.split("_", 1)[1]] = d
    result["breach_exposure"] = breaches or "none found in the sources checked"
    if data_of("hunter_verification"):
        result["deliverability"] = data_of("hunter_verification")

    result["sources"] = {n: s for n, (s, _) in outcomes.items()}
    result["source_notes"] = {n: d for n, (s, d) in outcomes.items() if s in ("error", "skipped")}
    return result


def gather_domain_intel(domain):
    """Free, key-less domain OSINT: WHOIS registration info, DNS records,
    and subdomains discovered via public certificate transparency logs
    (crt.sh)."""
    result = {"domain": domain}
    try:
        import whois as whois_lib
        w = whois_lib.whois(domain)
        result["registrar"] = w.registrar
        result["creation_date"] = str(w.creation_date)
        result["expiration_date"] = str(w.expiration_date)
        name_servers = w.name_servers
        result["name_servers"] = list(name_servers) if isinstance(name_servers, (list, set)) else ([name_servers] if name_servers else [])
    except Exception as e:
        result["whois_error"] = str(e)[:150]

    dns_records = {}
    for rtype in ["A", "MX", "NS", "TXT"]:
        try:
            import dns.resolver
            answers = dns.resolver.resolve(domain, rtype, lifetime=5)
            dns_records[rtype] = [str(r) for r in answers][:5]
        except Exception:
            dns_records[rtype] = []
    result["dns_records"] = dns_records

    try:
        resp = requests.get(f"https://crt.sh/?q=%25.{domain}&output=json", timeout=10)
        if resp.status_code == 200:
            entries = resp.json()
            subs = set()
            for entry in entries:
                for line in entry.get("name_value", "").split("\n"):
                    if domain in line:
                        subs.add(line.strip())
            result["subdomains"] = sorted(subs)[:20]
    except Exception as e:
        result["subdomains_error"] = str(e)[:100]

    return result

def gather_ip_intel(ip):
    """Free, key-less IP geolocation/ASN lookup via ip-api.com."""
    try:
        resp = requests.get(f"http://ip-api.com/json/{ip}", timeout=8)
        return resp.json()
    except Exception as e:
        return {"status": "error", "message": str(e)[:150]}

def extract_image_metadata(url):
    """Downloads an image and extracts EXIF metadata (camera, timestamp,
    GPS coordinates if present)."""
    try:
        resp = requests.get(url, timeout=10, headers=_HTTP_HEADERS)
        if resp.status_code != 200:
            return {"status": "error", "message": f"HTTP {resp.status_code} error"}

        from PIL import Image, ExifTags
        import io
        img = Image.open(io.BytesIO(resp.content))
        result = {"format": img.format, "size": img.size, "mode": img.mode}

        exif_data = img.getexif() if hasattr(img, "getexif") else None
        if exif_data:
            exif = {}
            for tag_id, value in exif_data.items():
                tag = ExifTags.TAGS.get(tag_id, tag_id)
                exif[str(tag)] = str(value)[:200]
            result["exif"] = exif if exif else None
        else:
            result["exif"] = None
        return result
    except Exception as e:
        return {"status": "error", "message": str(e)[:150]}


def classify_identifier(text: str):
    """Returns 'email' | 'ip' | 'domain' | 'username' when the message is
    just a bare identifier, else None."""
    t = text.strip()
    if re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", t):
        return "email"
    if re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", t):
        return "ip"
    if re.fullmatch(r"(?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,}", t):
        return "domain"
    if re.fullmatch(r"@?[\w.\-]{2,40}", t):
        return "username"
    return None

def _ddg_text(query, max_results=5):
    try:
        return DDGS().text(query, max_results=max_results)
    except Exception as e:
        return {"status": "error", "message": str(e)[:150]}

def run_recon(identifier: str, kind: str):
    """Runs every relevant free OSINT lookup for a bare identifier
    concurrently and returns the raw results. Done in code rather than left
    to the model's discretion, because free models often make a single tool
    call for a bare identifier and fill in the rest from memory."""
    tasks = {}
    if kind == "username":
        tasks["username_search"] = lambda: check_username_everywhere(identifier)
        tasks["github_profile"] = lambda: json.loads(
            requests.get(f"https://api.github.com/users/{identifier}", timeout=8, headers=_HTTP_HEADERS).text
        )
        tasks["web_search"] = lambda: _ddg_text(f'"{identifier}"')
        tasks["web_search_profiles"] = lambda: _ddg_text(f"{identifier} github OR twitter OR linkedin OR instagram")
    elif kind == "email":
        local = identifier.split("@")[0]
        tasks["email_intel"] = lambda: gather_email_intel(identifier)
        tasks["username_search_local_part"] = lambda: check_username_everywhere(local)
        tasks["web_search"] = lambda: _ddg_text(f'"{identifier}"')
    elif kind == "domain":
        tasks["domain_intel"] = lambda: gather_domain_intel(identifier)
        tasks["web_search"] = lambda: _ddg_text(identifier)
    elif kind == "ip":
        tasks["ip_intel"] = lambda: gather_ip_intel(identifier)
        tasks["web_search"] = lambda: _ddg_text(f'"{identifier}"')

    results = {}
    lock = threading.Lock()

    def worker(name, fn):
        try:
            value = fn()
        except Exception as e:
            value = {"status": "error", "message": str(e)[:150]}
        with lock:
            results[name] = value

    threads = [threading.Thread(target=worker, args=(n, f), daemon=True) for n, f in tasks.items()]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=25)

    return {
        name: _truncate(json.dumps(value, ensure_ascii=False, default=str), 3500 if name == "email_intel" else 1800)
        for name, value in results.items()
    }


def register_tools(agent):
    """Attaches the full OSINT tool set to the given agent and returns the
    list of tool functions. Defined as a function (rather than decorating a
    single module-level agent) so the provider-selection loop below can
    build several candidate agents and test each one's tools before
    committing to a provider."""
    @agent.tool
    def get_date_and_time(ctx: RunContext):
        """
        Use this tool when you need to get the current date and time.
        """
        return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


    @agent.tool
    def ddg_search(ctx: RunContext, type: str, query: str):
        """
        Use this tool when you need to search the web.

        Args:
            ctx: The agent context object
            type (str): The type of search to perform. Can be "text", "images", "videos", "news"
            query (str): The query to search for

        Returns:
            The search results.
        """
        count = increment_tool_count()
        if count > 8:
            return "Error: Tool limit reached (8 tools). Please finish your response with the information gathered so far."

        tool_log(f"Searching for {type} {query}")
        try:
            ddgs = DDGS()
            # Cap result count: unbounded search results are the single
            # biggest source of context bloat when multiple tools get
            # chained together in one OSINT lookup.
            if type == "text":
                results = ddgs.text(query, max_results=3)
            elif type == "images":
                results = ddgs.images(query, max_results=3)
            elif type == "videos":
                results = ddgs.videos(query, max_results=3)
            elif type == "news":
                results = ddgs.news(query, max_results=3)
            else:
                return "Error: Invalid type. Please use 'text', 'images', 'videos', 'news'."
            return _truncate(json.dumps(results, ensure_ascii=False))
        except Exception as e:
            return f"Error searching for {type} {query}: {str(e)}"


    @agent.tool
    def image_vision(ctx: RunContext, url: str):
        """
        Use this tool when you need to analyze an image.
        Another AI will describe the image to you.
        """
        count = increment_tool_count()
        if count > 8:
            return "Error: Tool limit reached (8 tools). Please finish your response with the information gathered so far."

        tool_log(f"Analyzing image {url}")

        # Validate URL scheme
        if not url.startswith(('http://', 'https://')):
            return "Error: Invalid URL. The URL must start with 'http://' or 'https://'. Please provide a complete URL to the image."

        try:
            # Download image to temp file
            response = requests.get(url)
            if response.status_code != 200:
                return f"Failed to download image: HTTP {response.status_code}"

            with tempfile.NamedTemporaryFile(delete=False, suffix=os.path.splitext(url)[1]) as temp_file:
                temp_file.write(response.content)
                temp_path = temp_file.name

            try:
                client = g4f.Client(provider=g4f.Provider.PollinationsAI)
                with open(temp_path, "rb") as img:
                    images = [[img, os.path.basename(url)]]
                    try:
                        response = client.chat.completions.create(
                            [{"content": "Describe this image in detail", "role": "user"}],
                            "",
                            images=images
                        )
                        description = response.choices[0].message.content
                    except g4f.errors.ResponseStatusError:
                        description = "Failed to analyze image due to API error"
            finally:
                os.unlink(temp_path)

            return description
        except requests.exceptions.MissingSchema:
            return "Error: Invalid URL. The URL must start with 'http://' or 'https://'. Please provide a complete URL to the image."
        except requests.exceptions.InvalidURL:
            return "Error: Invalid URL format. Please provide a valid URL to the image."
        except requests.exceptions.RequestException as e:
            return f"Error downloading image: {str(e)}"
        except Exception as e:
            return f"Error analyzing image: {str(e)}"


    @agent.tool
    def visit_page(ctx: RunContext, url: str):
        """
        Use this tool when you need to visit a website.

        Args:
            ctx: The agent context object
            url (str): The URL to visit

        Returns:
            The agent context dependencies
        """
        count = increment_tool_count()
        if count > 8:
            return "Error: Tool limit reached (8 tools). Please finish your response with the information gathered so far."

        tool_log(f"Visiting {url}")
        body = silent_requests(url)
        if body != "":
            return body
        else:
            return silent_requests_nmce(url)


    @agent.tool
    def twitter_search(ctx: RunContext, type: str, query: str):
        """
        Use this tool when you need to search Twitter.

        Args:
            ctx: The agent context object
            type (str): The type of search to perform. Can be "user" or "tweet"
            query (str): The query to search for

        Returns:
            The agent context dependencies
        """
        count = increment_tool_count()
        if count > 8:
            return "Error: Tool limit reached (8 tools). Please finish your response with the information gathered so far."

        tool_log(f"Searching for Twitter {type} {query}")
        return silent_requests(f"https://nitter.net/search?f={type}&q={query}")


    @agent.tool
    def twitter_profile(ctx: RunContext, username: str):
        """
        Use this tool when you need to view a Twitter profile.
        """
        count = increment_tool_count()
        if count > 8:
            return "Error: Tool limit reached (8 tools). Please finish your response with the information gathered so far."

        tool_log(f"Viewing Twitter profile {username}")
        return silent_requests(f"https://nitter.net/{username}")


    @agent.tool
    def instagram_search(ctx: RunContext, query: str):
        """
        Use this tool when you need to search Instagram.

        Args:
            ctx: The agent context object
            query (str): The query to search for

        Returns:
            The agent context dependencies
        """
        count = increment_tool_count()
        if count > 8:
            return "Error: Tool limit reached (8 tools). Please finish your response with the information gathered so far."

        tool_log(f"Searching for Instagram {query}")
        return silent_requests(f"https://imginn.com/search?q={query}")


    @agent.tool
    def instagram_profile(ctx: RunContext, username: str):
        """
        Use this tool when you need to view an Instagram profile.
        """
        count = increment_tool_count()
        if count > 8:
            return "Error: Tool limit reached (8 tools). Please finish your response with the information gathered so far."

        tool_log(f"Viewing Instagram profile {username}")
        return silent_requests(f"https://imginn.com/{username}/")


    @agent.tool
    def github_profile(ctx: RunContext, username: str):
        """
        Use this tool when you need to get a GitHub profile.
        """
        count = increment_tool_count()
        if count > 8:
            return "Error: Tool limit reached (8 tools). Please finish your response with the information gathered so far."

        tool_log(f"Viewing GitHub profile {username}")
        return silent_requests_nmce(f"https://api.github.com/users/{username}")


    @agent.tool
    def get_links_from_url(ctx: RunContext, url: str):
        """
        Use this tool when you need to get links from a website.
        """
        count = increment_tool_count()
        if count > 8:
            return "Error: Tool limit reached (8 tools). Please finish your response with the information gathered so far."

        tool_log(f"Getting links from {url}")
        content = silent_requests_nmce(url)
        # parse links
        links = re.findall(r'<a href="([^"]+)"', content)
        return links


    @agent.tool
    def get_images_from_url(ctx: RunContext, url: str):
        """
        Use this tool when you need to get images from a website.
        """
        count = increment_tool_count()
        if count > 8:
            return "Error: Tool limit reached (8 tools). Please finish your response with the information gathered so far."

        tool_log(f"Getting images from {url}")
        content = silent_requests_nmce(url)
        # parse images
        images = re.findall(r'<img src="([^"]+)"', content)
        return images


    @agent.tool
    def get_metadata_from_youtube(ctx: RunContext, url: str):
        """
        Use this tool when you need to get metadata from a YouTube video.
        Only use this tool if url contains v=
        """
        count = increment_tool_count()
        if count > 8:
            return "Error: Tool limit reached (8 tools). Please finish your response with the information gathered so far."

        if not url.startswith("https://www.youtube.com/watch?v="):
            return "Error: Invalid URL. The URL must start with 'https://www.youtube.com/watch?v='. Please provide a valid YouTube URL."
        tool_log(f"Getting metadata from YouTube {url}")
        video_id = url.split("v=")[1]
        response = silent_requests_nmce(f"https://ytapi.apps.mattw.io/v3/videos"
                                        f"?part=snippet,statistics,recordingDetails,"
                                        f"status,liveStreamingDetails,localizations,"
                                        f"contentDetails,paidProductPlacementDetails,"
                                        f"player,topicDetails&id={video_id}")
        return response


    @agent.tool
    def get_comments_from_youtube(ctx: RunContext, url: str, page: int = 0, size: int = 10):
        """
        Use this tool when you need to get comments from a YouTube video.
        Only use this tool if url contains v=

        Args:
            ctx: The agent context object
            url (str): The URL of the YouTube video
            size (int): The number of comments to get

        Returns:
            The comments from the YouTube video
        """
        count = increment_tool_count()
        if count > 8:
            return "Error: Tool limit reached (8 tools). Please finish your response with the information gathered so far."

        if not url.startswith("https://www.youtube.com/watch?v="):
            return "Error: Invalid URL. The URL must start with 'https://www.youtube.com/watch?v='. Please provide a valid YouTube URL."
        tool_log(f"Getting comments from YouTube {url} page {page} size {size}")
        video_id = url.split("v=")[1]
        response = silent_requests_nmce(
            f"https://hadzy.com/api/comments/{video_id}"
            f"?page={page}&size={size}"
            f"&sortBy=publishedAt&direction=asc&searchTerms=&author="
        )
        return response

    @agent.tool
    def username_search(ctx: RunContext, username: str):
        """
        Use this tool to check a username's existence across several
        platforms at once (GitHub, GitLab, npm, Docker Hub, About.me,
        Keybase, Telegram). Only platforms whose "not found" response can be
        reliably distinguished from a real profile are included, so this is
        a smaller but trustworthy list rather than a long one with silent
        false positives.

        Args:
            ctx: The agent context object
            username (str): The username to check

        Returns:
            A list of {site, url, exists} for every platform checked.
        """
        count = increment_tool_count()
        if count > 8:
            return "Error: Tool limit reached (8 tools). Please finish your response with the information gathered so far."

        tool_log(f"Checking username {username} across platforms")
        return _truncate(json.dumps(check_username_everywhere(username), ensure_ascii=False))

    @agent.tool
    def email_intel(ctx: RunContext, email: str):
        """
        Use this tool to gather OSINT on an email address: alias analysis,
        mail provider and SPF/DMARC, disposable-address check, Gravatar
        profile (name, linked accounts), PGP key, GitHub profiles/commits
        tied to the address, and data-breach exposure. Every source reports
        its own status, so say clearly which sources found nothing.
        """
        count = increment_tool_count()
        if count > 8:
            return "Error: Tool limit reached (8 tools). Please finish your response with the information gathered so far."

        tool_log(f"Gathering email intel for {email}")
        return _truncate(json.dumps(gather_email_intel(email), ensure_ascii=False), 3500)

    @agent.tool
    def domain_intel(ctx: RunContext, domain: str):
        """
        Use this tool to gather OSINT on a domain: WHOIS registration info,
        DNS records (A, MX, NS, TXT), and subdomains discovered via
        certificate transparency logs.
        """
        count = increment_tool_count()
        if count > 8:
            return "Error: Tool limit reached (8 tools). Please finish your response with the information gathered so far."

        tool_log(f"Gathering domain intel for {domain}")
        return _truncate(json.dumps(gather_domain_intel(domain), ensure_ascii=False))

    @agent.tool
    def ip_intel(ctx: RunContext, ip: str):
        """
        Use this tool to gather OSINT on an IP address: geolocation,
        ISP/organization, and ASN.
        """
        count = increment_tool_count()
        if count > 8:
            return "Error: Tool limit reached (8 tools). Please finish your response with the information gathered so far."

        tool_log(f"Gathering IP intel for {ip}")
        return _truncate(json.dumps(gather_ip_intel(ip), ensure_ascii=False))

    @agent.tool
    def image_metadata(ctx: RunContext, url: str):
        """
        Use this tool to extract metadata (EXIF) from an image: camera info,
        timestamp, and GPS coordinates if present. Useful for verifying an
        image's origin or approximate location.
        """
        count = increment_tool_count()
        if count > 8:
            return "Error: Tool limit reached (8 tools). Please finish your response with the information gathered so far."

        tool_log(f"Extracting image metadata from {url}")
        return _truncate(json.dumps(extract_image_metadata(url), ensure_ascii=False))

    return [
        get_date_and_time,
        ddg_search,
        image_vision,
        visit_page,
        twitter_search,
        twitter_profile,
        instagram_search,
        instagram_profile,
        github_profile,
        get_links_from_url,
        get_images_from_url,
        get_metadata_from_youtube,
        get_comments_from_youtube,
        username_search,
        email_intel,
        domain_intel,
        ip_intel,
        image_metadata,
    ]


AGENT_MODEL = "gpt-4o-mini"
# A literal function-call-syntax leak (e.g. "<function=twitter_search>") means
# the provider doesn't actually support tool calling: g4f fell back to asking
# the underlying model to type out calls as text, and it didn't get parsed
# back out. Providers that do this are unusable for this agent.
FUNCTION_LEAK_MARKER = "<function="

# Some free providers respond with HTTP 200 and a boilerplate rate-limit /
# quota notice as the "answer" instead of raising an error, so a plain
# non-empty-response check doesn't catch them. These substrings (seen from
# real provider responses) let both provider validation and the runtime
# fallback treat that the same as a real failure instead of showing it to
# the user as if it were a genuine reply.
PROVIDER_FAILURE_MARKERS = (
    FUNCTION_LEAK_MARKER,
    "请求过多",  # "too many requests" (seen from Yqcloud's rate limiter)
    "已被暂时限流",  # "temporarily rate limited"
    "rate limit",
    "too many requests",
)

def _looks_like_provider_failure(text: str) -> bool:
    """A real disguised rate-limit/error notice IS the entire response (the
    provider substitutes it for a completion). A genuine, substantive
    report can legitimately mention phrases like "rate limit" in passing
    (e.g. discussing GitHub API limits) without being one, so only treat
    this as a failure when those markers make up the response rather than
    appearing as an incidental phrase in a long report. The function-call
    leak marker is exempt from this length check since even one occurrence
    of literal "<function=" syntax means it wasn't a real tool call."""
    if FUNCTION_LEAK_MARKER in text:
        return True
    if len(text) > 300:
        return False
    lowered = text.lower()
    return any(marker.lower() in lowered for marker in PROVIDER_FAILURE_MARKERS)

def _run_in_thread(target, args, timeout):
    """Runs target(*args, result_queue) in a daemon thread with a hard
    wall-clock timeout, returning ('timeout', None), ('ok', value) or
    ('error', exc). A daemon thread that's still running past the timeout
    (e.g. a provider that opened a browser session and ignores `timeout=`)
    is simply abandoned rather than blocked on, since Python threads can't
    be killed and we'd rather move on to the next candidate."""
    result_queue = queue.Queue()
    thread = threading.Thread(target=target, args=(*args, result_queue), daemon=True)
    thread.start()
    thread.join(timeout=timeout)
    if thread.is_alive():
        return ("timeout", None)
    return result_queue.get()

def _test_provider_text(provider, result_queue):
    """Cheap stage-1 check: can this provider return any completion at all."""
    try:
        response = g4f.ChatCompletion.create(
            model=AGENT_MODEL,
            messages=[{"role": "user", "content": "Say 'test'"}],
            provider=provider,
            timeout=10,
            stream=False
        )
        result_queue.put(("ok", response))
    except Exception as e:
        result_queue.put(("error", e))

def _test_agent_tool_call(agent, result_queue):
    """Stage-2 check: with the real system prompt and full tool set attached,
    does the provider actually execute tool calls instead of leaking raw
    function-call syntax as text, and can it handle a realistic multi-tool
    OSINT-style exchange (several real tool calls, with real-sized results
    fed back into the conversation) without hitting a request-too-large or
    rate-limit error. A provider that only survives a single trivial tool
    call but chokes on this is not usable for the real workload."""
    try:
        # Must happen before run_sync, in this thread's context: if the
        # model issues several tool calls in parallel, pydantic-ai runs each
        # in its own asyncio Task, and a Task copies the *current* context
        # at creation time. Seeding the shared counter here means every
        # parallel task's copy points at the same underlying list.
        reset_tool_counter()
        result = agent.run_sync(
            "Look up the username 'octocat' across platforms: check their GitHub "
            "profile, search Twitter, search Instagram, and do a web search for "
            "the username. Use your tools for each of these, then summarize."
        )
        result_queue.put(("ok", str(result.output)))
    except Exception as e:
        result_queue.put(("error", e))

# Select working providers: cheap text-completion check first, then a real
# tool-calling check with the full agent, since some providers can chat but
# can't reliably do function calling once the real (larger) tool schema and
# system prompt are involved. We keep several validated providers (not just
# one), since free providers routinely hit per-IP rate limits — app.py falls
# back through PROVIDER_POOL when the primary one starts failing.
PROVIDER_POOL_TARGET = 3
PROVIDER_POOL_MAX_ATTEMPTS = 25

def _stage1_check(provider):
    """Cheap text-completion check. Runs in its own thread so it can be
    fanned out across many candidates at once — most candidates fail this
    stage, and running them one at a time (each with a several-second
    timeout) is what made cold start slow."""
    status, payload = _run_in_thread(_test_provider_text, (provider,), timeout=10)
    if status != "ok" or not payload:
        return False, str(payload)[:50] if status != "ok" else "no response"
    if _looks_like_provider_failure(payload):
        return False, f"rate-limit/error notice: {payload[:50]}"
    return True, None

def _parallel_stage1_filter(providers, max_concurrent=8):
    """Runs the cheap stage-1 check across many candidates concurrently
    instead of sequentially, since the dominant cost of cold start is
    waiting out timeouts for providers that don't work at all."""
    survivors = []
    lock = threading.Lock()

    def worker(provider):
        print(f"Testing provider: {provider.__name__}...", end=" ")
        ok, reason = _stage1_check(provider)
        print("✅ Text OK" if ok else f"❌ Failed: {reason}")
        if ok:
            with lock:
                survivors.append(provider)

    for batch_start in range(0, len(providers), max_concurrent):
        batch = providers[batch_start:batch_start + max_concurrent]
        threads = [threading.Thread(target=worker, args=(p,), daemon=True) for p in batch]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=15)

    return survivors

def _evaluate_provider_stage2(provider):
    """Builds the real agent and runs the heavier multi-tool-call check.
    Assumes the cheap stage-1 check already passed for this provider."""
    print(f"Verifying tool-calling for {provider.__name__}...", end=" ")
    try:
        candidate_agent = Agent(
            AIModel(AGENT_MODEL, provider),
            system_prompt=sys_prompt,
            model_settings=ModelSettings(temperature=0.1, max_tokens=3000)
        )
        candidate_tools = register_tools(candidate_agent)
    except Exception as e:
        print(f"❌ Could not build agent: {str(e)[:50]}...")
        return None

    status, payload = _run_in_thread(_test_agent_tool_call, (candidate_agent,), timeout=60)
    if status != "ok":
        print(f"❌ Failed: {str(payload)[:50]}...")
        return None
    if _looks_like_provider_failure(payload):
        print(f"❌ Leaked raw function-call syntax or rate-limit notice: {payload[:50]}...")
        return None

    print("✅ Works!")
    return {"provider": provider, "agent": candidate_agent, "tools": candidate_tools}

available_providers = get_available_providers()
print(f"Found {len(available_providers)} available providers")

stage1_survivors = _parallel_stage1_filter(available_providers[:PROVIDER_POOL_MAX_ATTEMPTS])
print(f"{len(stage1_survivors)} passed the quick check, verifying tool-calling...")

PROVIDER_POOL = []
for provider in stage1_survivors:
    if len(PROVIDER_POOL) >= PROVIDER_POOL_TARGET:
        break
    result = _evaluate_provider_stage2(provider)
    if result:
        PROVIDER_POOL.append(result)

if not PROVIDER_POOL:
    print("❌ No working provider found. Running in fallback mode.")
    selected_provider = None
    agent = None
    all_tools = []
else:
    selected_provider = PROVIDER_POOL[0]["provider"]
    agent = PROVIDER_POOL[0]["agent"]
    all_tools = PROVIDER_POOL[0]["tools"]
    print(
        f"✅ Agent initialized with provider: {selected_provider.__name__} "
        f"(+{len(PROVIDER_POOL) - 1} backup provider(s): "
        f"{', '.join(p['provider'].__name__ for p in PROVIDER_POOL[1:])})"
    )

# The candidate testing above already used up part of the 5-tool-call
# budget; reset it so real usage starts with the full budget available.
reset_tool_counter()

if __name__ == "__main__":
    # Set up readline with custom key bindings
    def clear_screen(signum=None, frame=None):
        os.system('clear' if os.name == 'posix' else 'cls')
        if hasattr(readline, 'redisplay'):
            readline.redisplay()

    # Register clear screen function
    readline.parse_and_bind(r'"\C-l": clear-screen')

    # Initialize colorama
    colorama.init()

    # Print welcome message
    print()
    print(f"    {colorama.Fore.CYAN}Welcome to Resonant OSINT AI Agent{colorama.Fore.RESET}")
    print(f"    {colorama.Fore.LIGHTBLACK_EX}Press Ctrl+L to clear screen, Ctrl+C to exit{colorama.Fore.RESET}\n")
    
    if selected_provider:
        print(f"    {colorama.Fore.GREEN}Using provider: {selected_provider.__name__}{colorama.Fore.RESET}\n")
    else:
        print(f"    {colorama.Fore.YELLOW}Running in fallback mode - AI features disabled{colorama.Fore.RESET}\n")
        print(f"    {colorama.Fore.YELLOW}Install Ollama or use a different AI backend for full functionality{colorama.Fore.RESET}\n")

    while True:
        try:
            message = input(f"{colorama.Fore.LIGHTBLACK_EX}»{colorama.Fore.RESET}{colorama.Fore.LIGHTWHITE_EX} ")
            print(f"{colorama.Fore.RESET}", end="")
            print()
            
            if not message.strip():
                continue

            # If agent failed to initialize, provide fallback
            if agent is None:
                print(f"{colorama.Fore.YELLOW}AI Service is currently unavailable. Running in fallback mode.{colorama.Fore.RESET}")
                print(f"{colorama.Fore.CYAN}Your query was: {message}{colorama.Fore.RESET}")
                print(f"{colorama.Fore.CYAN}In full mode, I would use my OSINT tools to investigate this.{colorama.Fore.RESET}\n")
                continue

            # Set up usage limits
            usage_limits = UsageLimits(
                request_limit=3,
            )

            # Capture messages during the run
            with capture_run_messages() as messages:
                try:
                    reset_tool_counter()
                    result = agent.run_sync(
                        message,
                        message_history=conversation_history,
                        usage_limits=usage_limits
                    )
                    conversation_history = result.new_messages()
                    ai_response = str(result.output)
                    
                except UsageLimitExceeded as e:
                    # Get the partial conversation up to the limit
                    last_response = None
                    for msg in messages:
                        if msg.kind == 'response':
                            last_response = msg.parts[-1].content if msg.parts else None
                    
                    # Create a warning message
                    warning = "\n\n[WARNING: Usage limit reached. Showing partial response.]"
                    ai_response = (last_response or "Partial response not available") + warning
                    
                    print(f"{ai_response}\n")
                except Exception as e:
                    print(f"{colorama.Fore.RED}Error: {str(e)}{colorama.Fore.RESET}\n")
                    print(f"{colorama.Fore.YELLOW}The AI service might be temporarily unavailable. Please try again in a moment.{colorama.Fore.RESET}\n")
                    continue

                # Save AI response
                print(f"{ai_response}\n")

        except g4f.errors.ResponseStatusError as e:
            print(f"{colorama.Fore.RED}Error: Response Status Error{colorama.Fore.RESET}\n")
            continue
        except KeyboardInterrupt:
            print(f"\n{colorama.Fore.YELLOW}Goodbye!{colorama.Fore.RESET}")
            break
        except Exception as e:
            print(f"{colorama.Fore.RED}Error: {str(e)}{colorama.Fore.RESET}\n")
            continue

    # Clean up colorama
    colorama.deinit()
