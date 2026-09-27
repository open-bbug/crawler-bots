# /// script
# requires-python = ">=3.12"
# dependencies = [
#     "requests>=2.32.5",
# ]
# ///

import requests
import json
import html
import os
import ipaddress
import re
import random

import socket

# Configuration
# Configuration
DATA_DIR = "data"
PROVIDERS_FILE = "providers/providers.txt"
KEYWORDS_FILE = "providers/record_name.txt"
ALL_IPS_FILE = os.path.join(DATA_DIR, "all_ip_whitelist.txt")
VERIFY_FILE = os.path.join(DATA_DIR, "all_verify_record_name.txt")

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
            keywords = [line.strip() for line in f if line.strip() and not line.startswith('#')]
    return keywords

PROVIDERS = load_providers(PROVIDERS_FILE)
KEYWORDS = load_keywords(KEYWORDS_FILE)

def fetch_url(url):
    """Return (text, error); error is None on success."""
    try:
        headers = {
            'User-Agent': 'Mozilla/5.0 (compatible; BotWhitelistUpdater/1.0; +https://github.com/your-repo)'
        }
        response = requests.get(url, headers=headers, timeout=10)
        response.raise_for_status()
        return response.text, None
    except Exception as e:
        print(f"Error fetching {url}: {e}")
        return None, str(e)

def parse_facebook(content):
    # Facebook provides a format like: CSV or similar.
    # If the URL is an HTML page (likely), we might need regex if it's simple valid data embedded.
    # However, strict 'geofeed' usually implies CSV: start_ip, state, country, city, zip
    # Let's try to parse as CIDR lines if possible, or return empty if HTML.
    ips = []
    if "<!DOCTYPE html>" in content or "<html" in content:
        print("Facebook returned HTML. Skipping (needs manual check or specialized scraper).")
        return []
    
    # Heuristic: look for CIDR patterns
    cidr_pattern = r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d{1,2}'
    ips.extend(re.findall(cidr_pattern, content))
    return ips

def parse_google(content):
    data = json.loads(content)
    ips = []
    if "prefixes" in data:
        for item in data["prefixes"]:
            if "ipv4Prefix" in item:
                ips.append(item["ipv4Prefix"])
            if "ipv6Prefix" in item:
                ips.append(item["ipv6Prefix"])
    return ips

def parse_bing(content):
    data = json.loads(content)
    ips = []
    if "prefixes" in data:
        for item in data["prefixes"]:
            if "ipv4Prefix" in item:
                ips.append(item["ipv4Prefix"])
            if "ipv6Prefix" in item:
                ips.append(item["ipv6Prefix"])
    return ips

def parse_duckduckgo(content):
    data = json.loads(content)
    ips = []
    if "prefixes" in data:
        for item in data["prefixes"]:
            if "ipv4Prefix" in item:
                ips.append(item["ipv4Prefix"])
            if "ipv6Prefix" in item:
                ips.append(item["ipv6Prefix"])
    return ips

def parse_ahrefs(content):
    data = json.loads(content)
    ips = []
    if "prefixes" in data:
        for item in data["prefixes"]:
            if "ipv4Prefix" in item:
                ips.append(item["ipv4Prefix"])
            if "ipv6Prefix" in item:
                ips.append(item["ipv6Prefix"])
    return ips

def parse_commoncrawl(content):
    data = json.loads(content)
    ips = []
    if "prefixes" in data:
        # According to standard structure
        for item in data["prefixes"]:
            if "ipv4Prefix" in item:
                ips.append(item["ipv4Prefix"])
            if "ipv6Prefix" in item:
                 ips.append(item["ipv6Prefix"])
    return ips

def parse_telegram(content):
    ips = []
    for line in content.splitlines():
        line = line.strip()
        if not line: continue
        # Check if line looks like a CIDR
        if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d{1,2}$', line) or \
           re.match(r'^[a-fA-F0-9:]+/\d{1,3}$', line):
            ips.append(line)
    return ips

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

def parse_uptimerobot(content):
    ips = []
    for line in content.splitlines():
        line = line.strip()
        if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?:/\d{1,2})?$', line) or \
           re.match(r'^[a-fA-F0-9:]+(?:/\d{1,3})?$', line):
            ips.append(line)
    return ips

def parse_pingdom(content):
    # Similar to others, list of IPs
    ips = []
    for line in content.splitlines():
        line = line.strip()
        if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', line):
             ips.append(line)
    return ips

def parse_openai(content):
    data = json.loads(content)
    ips = []
    if "prefixes" in data:
        for item in data["prefixes"]:
            if "ipv4Prefix" in item:
                ips.append(item["ipv4Prefix"])
            if "ipv6Prefix" in item:
                ips.append(item["ipv6Prefix"])
    return ips

def parse_gptbot(content):
    data = json.loads(content)
    ips = []
    if "prefixes" in data:
        for item in data["prefixes"]:
            if "ipv4Prefix" in item:
                ips.append(item["ipv4Prefix"])
            if "ipv6Prefix" in item:
                ips.append(item["ipv6Prefix"])
    return ips

def parse_chatgpt_user(content):
    data = json.loads(content)
    ips = []
    if "prefixes" in data:
        for item in data["prefixes"]:
            if "ipv4Prefix" in item:
                ips.append(item["ipv4Prefix"])
            if "ipv6Prefix" in item:
                ips.append(item["ipv6Prefix"])
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

def parse_applebot(content):
    data = json.loads(content)
    ips = []
    if "prefixes" in data:
        for item in data["prefixes"]:
            if "ipv4Prefix" in item:
                ips.append(item["ipv4Prefix"])
            if "ipv6Prefix" in item:
                ips.append(item["ipv6Prefix"])
    return ips

def parse_barkrowler(content):
    data = json.loads(content)
    ips = []
    if "prefixes" in data:
        for item in data["prefixes"]:
            if "ipv4Prefix" in item:
                ips.append(item["ipv4Prefix"])
            if "ipv6Prefix" in item:
                ips.append(item["ipv6Prefix"])
    return ips

def parse_seekport(content):
    # Plain text list of IPs
    ips = []
    for line in content.splitlines():
        line = line.strip()
        if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', line):
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
    "google": parse_google,
    "bing": parse_bing,
    "duckduckgo": parse_duckduckgo,
    "ahrefs": parse_ahrefs,
    "commoncrawl": parse_commoncrawl,
    "telegram": parse_telegram,
    "yandex": parse_yandex,
    "uptimerobot": parse_uptimerobot,
    "pingdom": parse_pingdom,
    "openai": parse_openai,
    "gptbot": parse_gptbot,
    "chatgpt-user": parse_chatgpt_user,
    "amazonbot": parse_amazonbot,
    "amzn-searchbot": parse_amazonbot,
    "amzn-user": parse_amazonbot,
    "applebot": parse_applebot,
    "barkrowler": parse_barkrowler,
    "seekport": parse_seekport,
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

def verify_ip(ip_address):
    """
    Performs reverse DNS lookup on the accessing IP address.
    Reads DNS record and extracts crawler keywords (e.g., googlebot) to a whitelist.
    """
    # Keywords to look for in the hostname
    keywords = KEYWORDS
    
    try:
        # Reverse DNS lookup
        hostname, _, _ = socket.gethostbyaddr(ip_address)
        print(f"Hostname for {ip_address}: {hostname}")
        
        found_keywords = []
        for keyword in keywords:
            if keyword in hostname.lower():
                found_keywords.append(keyword)
        
        if found_keywords:
            # Ensure data directory exists
            if not os.path.exists(DATA_DIR):
                os.makedirs(DATA_DIR)

            # Read existing records
            existing_records = set()
            if os.path.exists(VERIFY_FILE):
                with open(VERIFY_FILE, 'r') as f:
                    existing_records = set(line.strip() for line in f if line.strip())
            
            # Update records
            new_records = existing_records.union(set(found_keywords))
            
            # Write back if changed
            if len(new_records) > len(existing_records):
                with open(VERIFY_FILE, 'w') as f:
                    f.write('\n'.join(sorted(list(new_records))))
                print(f"Added keywords {found_keywords} to {VERIFY_FILE}")
            else:
                print(f"Keywords {found_keywords} already in {VERIFY_FILE}")
        else:
             print(f"No crawler keywords found in hostname: {hostname}")

        return found_keywords

    except socket.herror:
        print(f"No PTR record found for {ip_address}")
        return []
    except Exception as e:
        print(f"Error verifying IP {ip_address}: {e}")
        return []

def verify_sample(provider, valid_ips):
    # Verify one random IP from the first entry to extract reverse-DNS keywords
    try:
        first_entry = valid_ips[0]
        net = ipaddress.ip_network(first_entry, strict=False)
        # Pick a random IP from the subnet (single IPs /32 or /128 have one address)
        num_addrs = net.num_addresses
        if num_addrs > 1:
            target_ip = str(net[random.randint(0, num_addrs - 1)])
        else:
            target_ip = str(net.network_address)
        print(f"  Verifying random sample IP: {target_ip} (from {first_entry})...")
        verify_ip(target_ip)
    except Exception as e:
        print(f"  Error verifying first IP for {provider}: {e}")

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
            verify_sample(provider, valid_ips)
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

    write_report(results, len(sorted_ips))

if __name__ == "__main__":
    main()
