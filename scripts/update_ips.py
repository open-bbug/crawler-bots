# /// script
# requires-python = ">=3.12"
# dependencies = [
#     "requests>=2.32.5",
#     "urllib3>=1.26",
# ]
# ///

import html
import ipaddress
import json
import os
import re
import sys

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# Configuration
DATA_DIR = "data"
PROVIDERS_FILE = "providers/providers.txt"
KEYWORDS_FILE = "providers/record_name.txt"
ALL_IPS_FILE = os.path.join(DATA_DIR, "all_ip_whitelist.txt")
VERIFY_FILE = os.path.join(DATA_DIR, "all_verify_record_name.txt")

USER_AGENT = "Mozilla/5.0 (compatible; BotWhitelistUpdater/1.0; +https://github.com/open-bbug/crawler-bots)"
# (connect, read) timeouts in seconds; some provider pages are large
REQUEST_TIMEOUT = (10, 30)
# Exit code when at least one provider could not be updated (fallback or failed)
EXIT_PROVIDER_FAILURES = 2


def load_providers(filename):
    providers = {}
    if os.path.exists(filename):
        with open(filename, 'r') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#'):
                    parts = line.split('=', 1)
                    if len(parts) == 2:
                        providers[parts[0].strip()] = parts[1].strip()
    return providers


def load_keywords(filename):
    keywords = []
    if os.path.exists(filename):
        with open(filename, 'r') as f:
            for line in f:
                line = line.split('#', 1)[0].strip()
                if line:
                    keywords.append(line)
    return keywords


PROVIDERS = load_providers(PROVIDERS_FILE)
KEYWORDS = load_keywords(KEYWORDS_FILE)


def build_session():
    """HTTP session that retries connection errors, 429 and 5xx responses with exponential backoff."""
    retry = Retry(
        total=3,
        backoff_factor=2,  # urllib3 2.x: retry at once, then wait 4s and 8s
        status_forcelist=(429, 500, 502, 503, 504),
        allowed_methods=frozenset(["GET"]),
        respect_retry_after_header=True,
    )
    session = requests.Session()
    session.headers["User-Agent"] = USER_AGENT
    adapter = HTTPAdapter(max_retries=retry)
    session.mount("https://", adapter)
    session.mount("http://", adapter)
    return session


SESSION = build_session()


def fetch_url(url):
    """Return (text, error); error is None on success."""
    try:
        response = SESSION.get(url, timeout=REQUEST_TIMEOUT)
        response.raise_for_status()
        return response.text, None
    except Exception as e:
        print(f"Error fetching {url}: {e}")
        return None, str(e)


def parse_facebook(content):
    # Geofeed (RFC 8805) CSV: ip_prefix,country,region,city,postal_code; '#' starts a comment.
    # The prefix column holds both IPv4 and IPv6 ranges.
    if "<!DOCTYPE html>" in content or "<html" in content:
        print("Facebook returned HTML. Skipping (needs manual check or specialized scraper).")
        return []
    ips = []
    for line in content.splitlines():
        line = line.split('#', 1)[0].strip()
        if not line:
            continue
        prefix = line.split(',', 1)[0].strip()
        if validate_ip(prefix):
            ips.append(prefix)
    return list(dict.fromkeys(ips))


def parse_yandex(content):
    # https://yandex.com/ips is an HTML page listing Yandex's CIDR ranges (IPv4 and IPv6).
    # Strip the markup and collect every CIDR; require an explicit /prefix so stray numbers
    # on the page are not picked up.
    text = html.unescape(re.sub(r'<[^>]+>', ' ', content)).replace('\\/', '/')
    candidates = re.findall(r'\b\d{1,3}(?:\.\d{1,3}){3}/\d{1,2}\b', text)
    candidates += re.findall(r'(?<![\w:])[0-9a-fA-F]{1,4}(?::[0-9a-fA-F]{0,4}){1,7}/\d{1,3}\b', text)
    ips = [ip for ip in dict.fromkeys(candidates) if validate_ip(ip)]
    if not ips:
        if re.search(r'showcaptcha|smartcaptcha', content, re.I):
            print("Yandex: returned a captcha page, no CIDR ranges found.")
        else:
            print("Yandex: no CIDR ranges found in page (format may have changed).")
    return ips


def parse_amazonbot(content):
    # Amazon publishes each IP list inside an HTML page under https://developer.amazon.com/amazonbot/
    # (ip-addresses/, searchbot-ip-addresses/, live-ip-addresses/); there is no raw JSON endpoint.
    # The JSON sits in a code block and is usually HTML-escaped (&quot;), and the page also
    # contains CSS/JS braces, so we cannot simply take the text between the first '{' and last '}'.
    ips = []
    text = html.unescape(re.sub(r'<[^>]+>', '', content))

    # 1. Try every '{' as the start of a JSON object and keep the ones that hold "prefixes".
    decoder = json.JSONDecoder()
    for match in re.finditer(r'\{', text):
        try:
            data, _ = decoder.raw_decode(text, match.start())
        except ValueError:
            continue
        if isinstance(data, dict) and isinstance(data.get("prefixes"), list):
            for item in data["prefixes"]:
                if not isinstance(item, dict):
                    continue
                for key in ("ip_prefix", "ipv6_prefix", "ipv4Prefix", "ipv6Prefix"):
                    if key in item:
                        ips.append(item[key])

    # 2. Fallback: pick prefix values out of partial / non-strict JSON (e.g. trailing commas).
    if not ips:
        ips = re.findall(r'"(?:ip_prefix|ipv6_prefix|ipv4Prefix|ipv6Prefix)"\s*:\s*"([^"]+)"', text)

    # 3. Fallback: plain IP / CIDR list inside <pre> or <code> blocks.
    if not ips:
        for block in re.findall(r'<(?:pre|code)[^>]*>(.*?)</(?:pre|code)>', content, re.S | re.I):
            block = html.unescape(re.sub(r'<[^>]+>', ' ', block))
            ips.extend(re.findall(r'\b\d{1,3}(?:\.\d{1,3}){3}(?:/\d{1,2})?\b', block))

    if not ips:
        print("Amazonbot: no IP prefixes found in page (format may have changed).")

    return list(dict.fromkeys(ips))


def parse_plain_ips(content):
    # Plain text list with one IP or CIDR (IPv4 or IPv6) per line; other lines are ignored
    ips = []
    for line in content.splitlines():
        line = line.strip()
        if line and validate_ip(line):
            ips.append(line)
    return ips


def parse_prefixes(content):
    # Standard Google-style format: {"prefixes": [{"ipv4Prefix": ...}, {"ipv6Prefix": ...}]}
    data = json.loads(content)
    ips = []
    if "prefixes" in data:
        for item in data["prefixes"]:
            if "ipv4Prefix" in item:
                ips.append(item["ipv4Prefix"])
            if "ipv6Prefix" in item:
                ips.append(item["ipv6Prefix"])
    return ips


def parse_claudebot(content):
    # Anthropic publishes one list covering ClaudeBot, Claude-User and Claude-SearchBot.
    # The schema is not documented, so collect every string in the JSON that is a valid IP/CIDR.
    ips = []

    def walk(node):
        if isinstance(node, dict):
            for value in node.values():
                walk(value)
        elif isinstance(node, list):
            for value in node:
                walk(value)
        elif isinstance(node, str) and validate_ip(node):
            ips.append(node)

    walk(json.loads(content))
    return ips


PARSERS = {
    "facebook": parse_facebook,
    "google": parse_prefixes,
    "bing": parse_prefixes,
    "duckduckgo": parse_prefixes,
    "ahrefs": parse_prefixes,
    "commoncrawl": parse_prefixes,
    "telegram": parse_plain_ips,
    "yandex": parse_yandex,
    "uptimerobot": parse_plain_ips,
    "pingdom": parse_plain_ips,
    "pingdom-ipv6": parse_plain_ips,
    "openai": parse_prefixes,
    "gptbot": parse_prefixes,
    "chatgpt-user": parse_prefixes,
    "amazonbot": parse_amazonbot,
    "amzn-searchbot": parse_amazonbot,
    "amzn-user": parse_amazonbot,
    "applebot": parse_prefixes,
    "barkrowler": parse_prefixes,
    "seekport": parse_plain_ips,
    "claudebot": parse_claudebot,
    "perplexitybot": parse_prefixes,
    "perplexity-user": parse_prefixes,
    "mistralai-user": parse_prefixes,
    "mistralai-index": parse_prefixes,
    "duckassistbot": parse_prefixes,
    "google-special": parse_prefixes,
    "google-user-fetchers": parse_prefixes,
    "google-user-fetchers-google": parse_prefixes
}


def validate_ip(ip_str):
    try:
        ipaddress.ip_network(ip_str, strict=False)
        return True
    except ValueError:
        return False


def write_verify_records():
    """Publish the manually maintained rDNS keywords as data/all_verify_record_name.txt (sorted, deduplicated)."""
    records = sorted({keyword.lower() for keyword in KEYWORDS})
    with open(VERIFY_FILE, 'w') as f:
        f.write('\n'.join(records))
    print(f"Wrote {len(records)} rDNS keywords from {KEYWORDS_FILE} to {VERIFY_FILE}")


def fetch_provider(provider, url):
    """Fetch and parse one provider. Returns (valid_ips, error); error is None on success."""
    content, fetch_error = fetch_url(url)
    if fetch_error:
        return [], f"fetch failed: {fetch_error}"
    if not content:
        return [], "fetch failed: empty response"
    parser = PARSERS.get(provider)
    if not parser:
        return [], "no parser"
    try:
        ips = parser(content)
    except Exception as e:
        return [], f"parse error: {e}"
    valid_ips = [ip for ip in ips if validate_ip(ip)]
    if not valid_ips:
        return [], "no valid IPs in response"
    return valid_ips, None


def load_existing(filename):
    """Read a previously saved provider list, keeping only valid entries."""
    if not os.path.exists(filename):
        return []
    with open(filename, 'r') as f:
        return [line.strip() for line in f if line.strip() and validate_ip(line.strip())]


def annotate(level, title, message):
    # Emit a GitHub Actions annotation so problems show up on the run summary page
    if os.environ.get("GITHUB_ACTIONS") == "true":
        message = message.replace('%', '%25').replace('\r', '%0D').replace('\n', '%0A')
        print(f"::{level} title={title}::{message}")


def write_report(results, total):
    """Write a Markdown report to the Actions job summary and to UPDATE_REPORT_PATH (used as PR body)."""
    problems = [r for r in results if r["status"] != "ok"]
    lines = ["## Crawler bot IP update", ""]
    lines.append(f"- Providers: {len(results)} "
                 f"(ok: {sum(r['status'] == 'ok' for r in results)}, "
                 f"fallback: {sum(r['status'] == 'fallback' for r in results)}, "
                 f"failed: {sum(r['status'] == 'failed' for r in results)})")
    lines.append(f"- Total distinct IPs in `data/all_ip_whitelist.txt`: {total}")
    lines.append("")
    if problems:
        lines += ["### Providers not updated", "",
                  "Fallback providers kept their previous `data/<provider>.txt`, which is still included in the whitelist.", "",
                  "| Provider | Status | Reason | IPs used |",
                  "|----------|--------|--------|----------|"]
        for r in problems:
            reason = " ".join(r["error"].split()).replace("|", "\\|")
            lines.append(f"| {r['provider']} | {r['status']} | {reason} | {r['count']} |")
    else:
        lines.append("All providers were fetched successfully.")
    lines += ["", "<details><summary>All providers</summary>", "",
              "| Provider | Status | IPs |", "|----------|--------|-----|"]
    for r in results:
        lines.append(f"| {r['provider']} | {r['status']} | {r['count']} |")
    lines += ["", "</details>", ""]
    report = "\n".join(lines)

    for env_var in ("GITHUB_STEP_SUMMARY", "UPDATE_REPORT_PATH"):
        path = os.environ.get(env_var)
        if path:
            with open(path, 'a') as f:
                f.write(report)


def main():
    if not os.path.exists(DATA_DIR):
        os.makedirs(DATA_DIR)

    all_ips = set()
    results = []

    for provider, url in PROVIDERS.items():
        print(f"Processing {provider}...")
        filename = os.path.join(DATA_DIR, f"{provider}.txt")
        valid_ips, error = fetch_provider(provider, url)

        if error is None:
            with open(filename, 'w') as f:
                f.write('\n'.join(valid_ips))
            all_ips.update(valid_ips)
            print(f"  Saved {len(valid_ips)} IPs for {provider}")
            results.append({"provider": provider, "status": "ok", "error": "", "count": len(valid_ips)})
            continue

        # Fetch or parse failed: keep the previous list so the whitelist does not shrink
        existing = load_existing(filename)
        if existing:
            all_ips.update(existing)
            print(f"  {error}; using {len(existing)} IPs from existing {filename}")
            annotate("warning", f"{provider} not updated",
                     f"{error}; kept {len(existing)} IPs from previous {filename}")
            results.append({"provider": provider, "status": "fallback", "error": error, "count": len(existing)})
        else:
            print(f"  {error}; no existing data for {provider}")
            annotate("error", f"{provider} failed",
                     f"{error}; no previous data, provider missing from whitelist")
            results.append({"provider": provider, "status": "failed", "error": error, "count": 0})

    # Write all IPs
    sorted_ips = sorted(list(all_ips))
    with open(ALL_IPS_FILE, 'w') as f:
        f.write('\n'.join(sorted_ips))
    print(f"Total distinct IPs saved: {len(sorted_ips)}")

    write_verify_records()
    write_report(results, len(sorted_ips))
    return print_summary(results)


def print_summary(results):
    """Print the providers that were not updated; return the process exit code."""
    problems = [r for r in results if r["status"] != "ok"]
    print()
    print(f"Summary: {len(results) - len(problems)}/{len(results)} providers updated")
    if not problems:
        return 0
    for r in problems:
        print(f"  [{r['status']}] {r['provider']}: {r['error']} (IPs used: {r['count']})")
    return EXIT_PROVIDER_FAILURES


if __name__ == "__main__":
    sys.exit(main())
