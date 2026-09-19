"""Public-profile username scan using the WhatsMyName project's site list.

WhatsMyName (https://github.com/WebBreacher/WhatsMyName) is maintained by
Micah Hoffman and contributors and is licensed CC BY-SA 4.0. The list is
downloaded at runtime and cached locally rather than bundled in this repo.

Each check is a plain GET of a site's public profile URL, judged by the
response code and page markers the project verified for that site. Nothing
here logs in, signs up, or triggers password-reset flows.

Excluded on purpose: adult and dating categories (sensitive, and rarely
useful for a legitimate lookup), sites that sit behind a captcha or
Cloudflare challenge (they can't be checked reliably with a plain request),
and entries that need a POST.
"""
import json
import os
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests

WMN_URL = "https://raw.githubusercontent.com/WebBreacher/WhatsMyName/main/wmn-data.json"
CACHE_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".cache", "wmn-data.json")
CACHE_TTL = 7 * 24 * 3600
EXCLUDED_CATEGORIES = {"xx NSFW xx", "dating", "archived"}
_HEADERS = {"User-Agent": "Mozilla/5.0 (compatible; ResonantOSINT/1.0)"}


def _load_sites():
    try:
        if os.path.exists(CACHE_PATH) and time.time() - os.path.getmtime(CACHE_PATH) < CACHE_TTL:
            with open(CACHE_PATH, encoding="utf-8") as f:
                data = json.load(f)
        else:
            raise FileNotFoundError
    except Exception:
        r = requests.get(WMN_URL, timeout=20, headers=_HEADERS)
        r.raise_for_status()
        data = r.json()
        try:
            os.makedirs(os.path.dirname(CACHE_PATH), exist_ok=True)
            with open(CACHE_PATH, "w", encoding="utf-8") as f:
                json.dump(data, f)
        except OSError:
            pass
    return [
        s for s in data.get("sites", [])
        if s.get("uri_check") and "{account}" in s["uri_check"]
        and not s.get("post_body")
        and not s.get("protection")
        and "search" not in s["uri_check"].lower()   # search pages aren't profiles
        and s.get("cat") not in EXCLUDED_CATEGORIES
    ]


def _matches(site, resp):
    if resp.status_code != site.get("e_code"):
        return False
    text = resp.text
    if site.get("e_string") and site["e_string"] not in text:
        return False
    if site.get("m_string") and site["m_string"] in text:
        return False
    return True


def _check(site, username):
    url = site["uri_check"].replace("{account}", username)
    try:
        resp = requests.get(url, timeout=6, headers=_HEADERS, allow_redirects=True)
        if _matches(site, resp):
            return {"site": site["name"], "category": site.get("cat", "misc"),
                    "url": site.get("uri_pretty", site["uri_check"]).replace("{account}", username)}
    except Exception:
        pass
    return None


def scan_username(username, max_seconds=25, workers=64):
    """Returns (found, stats). `found` is a list of {site, category, url}."""
    username = username.strip().lstrip("@")
    if not username or not all(c.isalnum() or c in "._-" for c in username):
        return [], {"checked": 0, "note": "username has unsupported characters"}
    sites = _load_sites()
    found, done = [], 0
    deadline = time.time() + max_seconds
    pool = ThreadPoolExecutor(max_workers=workers)
    futures = [pool.submit(_check, s, username) for s in sites]
    try:
        for fut in as_completed(futures, timeout=max_seconds):
            done += 1
            hit = fut.result()
            if hit:
                found.append(hit)
    except Exception:
        pass  # deadline reached; report what finished
    finally:
        pool.shutdown(wait=False, cancel_futures=True)
    found.sort(key=lambda x: (x["category"], x["site"].lower()))
    return found, {"checked": done, "total_sites": len(sites), "complete": done >= len(sites)}
