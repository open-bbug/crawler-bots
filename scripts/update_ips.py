# /// script
# requires-python = ">=3.12"
# dependencies = [
#     "requests>=2.32.5",
# ]
# ///

import requests
import json
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
    try:
        headers = {
            'User-Agent': 'Mozilla/5.0 (compatible; BotWhitelistUpdater/1.0; +https://github.com/your-repo)'
        }
        response = requests.get(url, headers=headers, timeout=10)
        response.raise_for_status()
        return response.text
    except Exception as e:
        print(f"Error fetching {url}: {e}")
        return None

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
    # Yandex often returns HTML.
    ips = []
    if "<!DOCTYPE html>" in content or "<html" in content:
         print("Yandex returned HTML. Skipping (needs manual check or specialized scraper).")
         return []
    # If raw lines
    for line in content.splitlines():
        line = line.strip()
        if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?:/\d{1,2})?$', line):
            ips.append(line)
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
    # Amazon provides a webpage with JSON inside a code block.
    # We need to extract the JSON string.
    ips = []
    # Find the JSON content between braces, possibly spanning lines.
    # The chunk view shows it is inside a markdown code block ``` ... ```
    # Let's try to extract relevant JSON structure.
    try:
        # Find start of JSON object
        start_idx = content.find('{')
        if start_idx != -1:
            # Find the last closing brace
            end_idx = content.rfind('}')
            if end_idx != -1 and end_idx > start_idx:
                json_candidate = content[start_idx:end_idx+1]
                data = json.loads(json_candidate)
                if "prefixes" in data:
                    for item in data["prefixes"]:
                        if "ip_prefix" in item:
                            ips.append(item["ip_prefix"])
    except (json.JSONDecodeError, ValueError) as e:
        print(f"Error parsing Amazon JSON: {e}")
        
    return ips

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
    "applebot": parse_applebot,
    "barkrowler": parse_barkrowler,
    "seekport": parse_seekport
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

def main():
    if not os.path.exists(DATA_DIR):
        os.makedirs(DATA_DIR)
    
    all_ips = set()

    for provider, url in PROVIDERS.items():
        print(f"Processing {provider}...")
        content = fetch_url(url)
        if content:
            parser = PARSERS.get(provider)
            if parser:
                try:
                    ips = parser(content)
                    valid_ips = [ip for ip in ips if validate_ip(ip)]
                    
                    if valid_ips:
                        # Write individual file
                        filename = os.path.join(DATA_DIR, f"{provider}.txt")
                        with open(filename, 'w') as f:
                            f.write('\n'.join(valid_ips))
                        
                        all_ips.update(valid_ips)
                        print(f"  Saved {len(valid_ips)} IPs for {provider}")
                        
                        # Verify the first IP to extract keywords
                        try:
                            first_entry = valid_ips[0]
                            # Handle CIDR to get a single random IP address
                            net = ipaddress.ip_network(first_entry, strict=False)
                            
                            # Pick a random IP from the subnet
                            # If it's a single IP (/32 or /128), num_addresses is 1, returns index 0
                            # For larger subnets, this gives us a random host.
                            num_addrs = net.num_addresses
                            if num_addrs > 1:
                                random_index = random.randint(0, num_addrs - 1)
                                target_ip = str(net[random_index])
                            else:
                                target_ip = str(net.network_address)
                            
                            print(f"  Verifying random sample IP: {target_ip} (from {first_entry})...")
                            verify_ip(target_ip)
                        except Exception as e:
                            print(f"  Error verifying first IP for {provider}: {e}")

                    else:
                        print(f"  No valid IPs found for {provider}")
                except Exception as e:
                    print(f"  Error parsing {provider}: {e}")
            else:
                 print(f"  No parser for {provider}")
        else:
            print(f"  Failed to fetch content for {provider}")

    # Write all IPs
    sorted_ips = sorted(list(all_ips))
    with open(ALL_IPS_FILE, 'w') as f:
        f.write('\n'.join(sorted_ips))
    print(f"Total distinct IPs saved: {len(sorted_ips)}")

if __name__ == "__main__":
    main()
