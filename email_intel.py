"""Email OSINT: free-first data gathering plus a structured report.

Kept in its own module (no AI-provider imports) so an email lookup returns
immediately instead of waiting for provider discovery.

Every source is free and key-less unless noted, was tested against the live
service before being added, and reports its own status, so a missing or
failed source is visible instead of looking like "no result". Sources that
would require probing sign-up / password-reset flows, or logging in to a
third-party account, are deliberately not used.
"""
import json
import os
import re
import threading

import requests

_HTTP_HEADERS = {"User-Agent": "Mozilla/5.0 (compatible; ResonantOSINT/1.0)"}

EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")

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
    r = requests.get("https://api.xposedornot.com/v1/breach-analytics", params={"email": email},
                     timeout=15, headers=_HTTP_HEADERS)
    if r.status_code == 404:
        return "not_found", None
    if r.status_code != 200:
        return "error", f"HTTP {r.status_code}"
    d = r.json()
    details = (d.get("ExposedBreaches") or {}).get("breaches_details") or []
    if not details:
        return "not_found", None
    items = []
    for b in details:
        items.append({
            "name": b.get("breach"),
            "domain": b.get("domain"),
            "year": b.get("xposed_date"),
            "records": b.get("xposed_records"),
            "industry": b.get("industry"),
            "data_exposed": [x for x in (b.get("xposed_data") or "").split(";") if x],
            "password_risk": b.get("password_risk"),
        })
    items.sort(key=lambda x: str(x.get("year") or ""))
    return "ok", {"count": len(items), "breaches": items[:40]}

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

_PLACEHOLDER_GH_LOGINS = {"invalid-email-address"}

def _gh_profile(login):
    r = requests.get(f"https://api.github.com/users/{login}", timeout=8, headers=_gh_headers())
    if r.status_code != 200:
        return None
    p = r.json()
    return {k: p.get(k) for k in ("login", "name", "html_url", "avatar_url", "followers", "following",
                                   "public_repos", "created_at", "company", "blog", "location", "bio") if p.get(k) not in (None, "")}

def _src_github(email):
    out = {"accounts": []}
    matched = {}   # login -> how the address was linked to it

    # Users whose profile shows this exact public email. GitHub's user search
    # is fuzzy, so each candidate is confirmed against the profile itself.
    r = requests.get("https://api.github.com/search/users", params={"q": f"{email} in:email"}, timeout=10, headers=_gh_headers())
    if r.status_code in (403, 429):
        return "error", "GitHub rate limit reached (set GITHUB_TOKEN to raise it)"
    if r.status_code == 200:
        for u in r.json().get("items", [])[:5]:
            try:
                full = requests.get(u["url"], timeout=8, headers=_gh_headers()).json()
            except Exception:
                continue
            if (full.get("email") or "").lower() == email.lower():
                matched[u["login"]] = "public email on profile"

    # Accounts that authored commits with this address. GitHub links a commit
    # to an account only when the address is verified on that account.
    c = requests.get("https://api.github.com/search/commits", params={"q": f"author-email:{email}", "per_page": 10},
                     timeout=10, headers=_gh_headers())
    repos, names = [], []
    if c.status_code == 200:
        data = c.json()
        out["commits_authored_total"] = data.get("total_count", 0)
        for it in data.get("items", []):
            login = (it.get("author") or {}).get("login")
            if login and login not in _PLACEHOLDER_GH_LOGINS:
                matched.setdefault(login, "commit author (verified address)")
            repos.append((it.get("repository") or {}).get("full_name"))
            nm = (it.get("commit", {}).get("author") or {}).get("name")
            if nm:
                names.append(nm)
        out["sample_repositories"] = sorted({x for x in repos if x})[:5]
        out["commit_author_names"] = sorted(set(names))[:5]

    for login, how in list(matched.items())[:4]:
        prof = _gh_profile(login)
        if prof:
            prof["linked_by"] = how
            out["accounts"].append(prof)

    found = out["accounts"] or out.get("commits_authored_total")
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
    items = [{"name": b.get("Name")} for b in r.json()]
    return "ok", {"count": len(items), "breaches": items[:40]}

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
    result["summary"] = _summarize(result)
    return result

def _merged_breaches(result):
    """Breach entries from every enabled source, de-duplicated by name, with
    the richest record kept."""
    be = result.get("breach_exposure")
    merged = {}
    for source in (be.values() if isinstance(be, dict) else []):
        for b in (source or {}).get("breaches") or []:
            key = str(b.get("name")).lower()
            if key not in merged or len(b) > len(merged[key]):
                merged[key] = b
    return sorted(merged.values(), key=lambda x: str(x.get("year") or ""))


def _summarize(result):
    """Consolidates everything found into the headline numbers and flat
    lists (names, usernames, pictures, links, accounts, breach dates)."""
    ident = result.get("identity_signals")
    ident = ident if isinstance(ident, dict) else {}
    names, usernames, pictures, links, accounts = [], [], [], [], []

    def add(lst, value, source):
        if value and not any(x["value"] == value for x in lst):
            lst.append({"value": value, "source": source})

    grav = ident.get("gravatar") or {}
    if grav:
        add(names, grav.get("display_name"), "Gravatar")
        slug = (grav.get("profile_url") or "").rstrip("/").rsplit("/", 1)[-1]
        add(usernames, slug, "Gravatar")
        add(pictures, grav.get("avatar_url"), "Gravatar")
        add(links, grav.get("profile_url"), "Gravatar")
        for l in grav.get("links") or []:
            add(links, l, "Gravatar")
        accounts.append({"service": "Gravatar", "username": slug, "url": grav.get("profile_url")})
        for a in grav.get("verified_accounts") or []:
            add(links, a.get("url"), f"Gravatar ({a.get('service')})")
            accounts.append({"service": a.get("service"), "username": None, "url": a.get("url")})

    gh = ident.get("github") or {}
    for acc in gh.get("accounts") or []:
        add(names, acc.get("name"), "GitHub")
        add(usernames, acc.get("login"), "GitHub")
        add(pictures, acc.get("avatar_url"), "GitHub")
        add(links, acc.get("html_url"), "GitHub")
        accounts.append({"service": "GitHub", "username": acc.get("login"), "url": acc.get("html_url"), "details": acc})
    if not gh.get("accounts"):
        for nm in gh.get("commit_author_names") or []:
            add(names, nm, "GitHub commits")

    items = _merged_breaches(result)
    years = sorted(str(b.get("year")) for b in items if b.get("year"))
    return {
        "counts": {"accounts": len(accounts), "breaches": len(items), "usernames": len(usernames),
                   "pictures": len(pictures), "links": len(links)},
        "names": names, "usernames": usernames, "pictures": pictures, "links": links, "accounts": accounts,
        "breach_first_seen": years[0] if years else None,
        "breach_last_seen": years[-1] if years else None,
    }


def _md_escape(text):
    return str(text).replace("|", "\\|").replace("\n", " ").strip()


def format_email_report(data):
    """Turns gather_email_intel() output into a structured markdown report.
    Built in code from the raw results, so nothing in it can be invented."""
    email = data.get("email", "")
    if not data.get("valid_format"):
        return f"`{email}` is not a valid email address."

    summ = data.get("summary") or _summarize(data)
    c = summ["counts"]
    out = [f"## Email Intelligence: `{email}`", ""]
    out += ["| Accounts | Breaches | Usernames | Pictures | Links |", "|:--:|:--:|:--:|:--:|:--:|",
            f"| {c['accounts']} | {c['breaches']} | {c['usernames']} | {c['pictures']} | {c['links']} |", ""]

    def section(title, rows):
        if rows:
            out.extend([f"### {title}", *rows, ""])

    section("Names", [f"- **{_md_escape(n['value'])}** ({n['source']})" for n in summ["names"]])
    section("Usernames", [f"- `{_md_escape(u['value'])}` ({u['source']})" for u in summ["usernames"]])

    dates = []
    if summ["breach_first_seen"]:
        dates.append(f"- First seen in a breach: **{summ['breach_first_seen']}**")
        dates.append(f"- Last seen in a breach: **{summ['breach_last_seen']}**")
    section("Dates", dates)

    section("Links", [f"- <{l['value']}> ({l['source']})" for l in summ["links"]])
    if summ["pictures"]:
        imgs = " ".join(f'<img src="{p["value"]}" width="72" height="72" alt="{p["source"]} avatar">' for p in summ["pictures"])
        out.extend(["### Profile Pictures", imgs, ""])

    items = _merged_breaches(data)
    if items:
        out += ["### Data Breach Exposure",
                f"Found in **{len(items)}** breach(es), first appeared **{summ['breach_first_seen']}**, last appeared **{summ['breach_last_seen']}**.", "",
                "| Breach | Source | Year | Records | Data exposed | Password risk |", "|---|---|:--:|--:|---|---|"]
        for b in items:
            rec = f"{b['records']:,}" if isinstance(b.get("records"), int) else "n/a"
            out.append(f"| {_md_escape(b.get('name'))} | {_md_escape(b.get('domain') or 'n/a')} | {b.get('year') or 'n/a'} | {rec} | "
                       f"{_md_escape(', '.join(b.get('data_exposed') or []) or 'n/a')} | {_md_escape(b.get('password_risk') or 'n/a')} |")
        out.append("")
    else:
        out += ["### Data Breach Exposure", "Not found in the breach sources checked.", ""]

    rows = []
    for a in summ["accounts"]:
        d = a.get("details") or {}
        extra = ", ".join(f"{k}: {d[k]}" for k in ("followers", "following", "public_repos", "created_at") if k in d)
        who = f" `{a['username']}`" if a.get("username") else ""
        link = f" — <{a['url']}>" if a.get("url") else ""
        rows.append(f"- **{a['service']}**{who}{link}" + (f"  \n  {extra}" if extra else "")
                    + (f"  \n  linked by: {d['linked_by']}" if d.get("linked_by") else ""))
    section(f"Registered Accounts ({len(rows)} found)", rows)

    gh = (data.get("identity_signals") or {}).get("github") if isinstance(data.get("identity_signals"), dict) else None
    if gh and gh.get("commits_authored_total"):
        section("Commit Activity", [f"- {gh['commits_authored_total']:,} public commits use this address"
                                    + (f"; sample repositories: {', '.join(gh.get('sample_repositories') or [])}" if gh.get("sample_repositories") else "")])

    pgp = (data.get("identity_signals") or {}).get("pgp") if isinstance(data.get("identity_signals"), dict) else None
    if pgp:
        section("PGP", ["- A public PGP key is published for this address on keys.openpgp.org"])

    dom = data.get("domain_analysis") or {}
    infra = [f"- Domain: `{dom.get('name')}`" + (" (free mail provider)" if dom.get("free_provider") else "")]
    if dom.get("mail_provider"):
        infra.append(f"- Mail provider: {dom['mail_provider']}")
    if dom.get("mx_hosts"):
        infra.append(f"- MX: {', '.join(dom['mx_hosts'][:3])}")
    infra.append(f"- SPF: {'yes' if dom.get('spf') else 'no'}, DMARC: {'yes' if dom.get('dmarc') else 'no'}")
    if dom.get("disposable") is not None:
        infra.append(f"- Disposable address: {'**yes**' if dom['disposable'] else 'no'}")
    if data.get("address_analysis", {}).get("alias_note"):
        infra.append(f"- Alias: {data['address_analysis']['alias_note']}")
    section("Mail Infrastructure", infra)

    labels = {"ok": "found", "not_found": "nothing found", "skipped": "not enabled", "error": "error"}
    src_rows = [f"| {n} | {labels.get(s, s)} |" for n, s in sorted((data.get("sources") or {}).items())]
    out += ["### Sources Checked", "| Source | Result |", "|---|---|", *src_rows, ""]
    notes = data.get("source_notes") or {}
    if notes:
        out += ["_" + "; ".join(f"{k}: {v}" for k, v in notes.items()) + "_", ""]
    out += ["_Only public and open sources are used. Absence of a result means nothing was found in these sources, not that the address has no other accounts._"]
    return "\n".join(out)
