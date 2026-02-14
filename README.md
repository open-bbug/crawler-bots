# Crawler Bot IP Whitelist Automation

This project automates the retrieval and maintenance of IP whitelists for major crawler bots (Google, Bing, Facebook, etc.). It fetches IP ranges from official sources and consolidates them into a single whitelist file.

## Features

- **Automated Fetching**: Scripts to fetch IP lists from multiple providers.
- **Consolidation**: Merges all IPs into a single `data/all_ip_whitelist.txt` file.
- **Scheduled Updates**: GitHub Action workflow runs every Monday to update the lists and create a Pull Request.

## Supported Providers

| Provider | Source Type | Status |
|----------|-------------|--------|
| Facebook | Geofeed/HTML | Active |
| Google | JSON | Active |
| Bing | JSON | Active |
| DuckDuckGo | JSON | Active |
| Ahrefs | JSON | Active |
| CommonCrawl | JSON | Active |
| Telegram | CIDR Text | Active |
| UptimeRobot | Text | Active |
| Pingdom | Text | Active |
| OpenAI SearchBot | JSON | Active |
| GPTBot | JSON | Active |
| ChatGPT User | JSON | Active |
| AmazonBot | JSON (HTML Embedded) | Active |
| AppleBot | JSON | Active |
| Barkrowler | JSON | Active |
| Seekport | Text | Active |
| Yandex | HTML | Skipped (HTML parsing/protection) |

## Project Structure

```
├── data/                  # Generated IP lists
│   ├── all_ip_whitelist.txt
│   └── <provider>.txt
├── providers/             # Configuration
│   ├── providers.txt      # List of provider URLs
│   └── record_name.txt    # Verification keywords
├── scripts/
│   └── update_ips.py      # Main fetcher script
├── .github/workflows/
│   └── update_ips.yml     # Weekly automation workflow
└── README.md
```

## Setup & Usage

### Prerequisites

- [uv](https://github.com/astral-sh/uv)

### Installation

1. Clone the repository.
2. Install `uv` if you haven't already:
   ```bash
   curl -LsSf https://astral.sh/uv/install.sh | sh
   ```

### Running Locally

To fetch the latest IPs and update the `data/` directory using `uv`:

```bash
uv run scripts/update_ips.py
```

This will:
1. Fetch data from all configured providers.
2. Save individual provider lists to `data/<provider>.txt`.
3. Save the consolidated list to `data/all_ip_whitelist.txt`.

## Automation

The project includes a GitHub Action ([`.github/workflows/update_ips.yml`](.github/workflows/update_ips.yml)) that:
- Runs **every Monday at 00:00 UTC**.
- Executes the update script.
- Creates a Pull Request with any changes to the IP lists.

## Contributing

To add a new provider:
To add a new provider:
1. Add the provider and its URL to `providers/providers.txt` (format: `provider_name=https://url...`).
2. Add verification keywords to `providers/record_name.txt` if needed.
3. In `scripts/update_ips.py`:
    - Implement a `parse_<provider>` function.
    - Add the parser to the `PARSERS` dictionary.
