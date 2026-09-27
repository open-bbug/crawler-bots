# Crawler Bot IP Whitelist Automation

This project automates the retrieval and maintenance of IP whitelists for major crawler bots (Google, Bing, Facebook, etc.). It fetches IP ranges from official sources and consolidates them into a single whitelist file.

## Features

- **Automated Fetching**: Scripts to fetch IP lists from multiple providers.
- **Consolidation**: Merges all IPs into a single `data/all_ip_whitelist.txt` file.
- **Scheduled Updates**: GitHub Action workflow runs every Monday to update the lists and create a Pull Request.

## Supported Providers

Each provider in [`providers/providers.txt`](providers/providers.txt) writes its own `data/<provider>.txt`; all of them are merged into `data/all_ip_whitelist.txt`.

### Search Engine Crawlers

| Provider | Bots / User-Agents | Data File | Source Type | Status |
|----------|--------------------|-----------|-------------|--------|
| Google | Googlebot, Google-Extended | `google.txt` | JSON | Active |
| Google Special Crawlers | GoogleOther, Google-CloudVertexBot, Google-Firebase | `google-special.txt` | JSON | Active |
| Bing | bingbot, BingPreview (also used by Copilot) | `bing.txt` | JSON | Active |
| DuckDuckGo | DuckDuckBot | `duckduckgo.txt` | JSON | Active |
| Yandex | YandexBot (all Yandex-owned ranges) | `yandex.txt` | HTML | Active |
| Apple | Applebot, Applebot-Extended | `applebot.txt` | JSON | Active |
| Amazon | Amazonbot | `amazonbot.txt` | JSON (HTML embedded) | Active |
| Amazon | Amzn-SearchBot | `amzn-searchbot.txt` | JSON (HTML embedded) | Active |
| Seekport | SeekportBot | `seekport.txt` | Text | Active |

### AI Crawlers & Agents

| Provider | Bots / User-Agents | Data File | Source Type | Status |
|----------|--------------------|-----------|-------------|--------|
| OpenAI | OAI-SearchBot | `openai.txt` | JSON | Active |
| OpenAI | GPTBot | `gptbot.txt` | JSON | Active |
| OpenAI | ChatGPT-User | `chatgpt-user.txt` | JSON | Active |
| Anthropic | ClaudeBot, Claude-User, Claude-SearchBot | `claudebot.txt` | JSON | Active |
| Perplexity | PerplexityBot | `perplexitybot.txt` | JSON | Active |
| Perplexity | Perplexity-User | `perplexity-user.txt` | JSON | Active |
| Mistral AI | MistralAI-User | `mistralai-user.txt` | JSON | Active |
| Mistral AI | MistralAI-Index | `mistralai-index.txt` | JSON | Active |
| DuckDuckGo | DuckAssistBot | `duckassistbot.txt` | JSON | Active |
| Google User-Triggered Fetchers | Google-NotebookLM, GoogleAgent-Mariner, FeedFetcher-Google | `google-user-fetchers.txt` | JSON | Active |
| Google User-Triggered Fetchers (Google) | Google-NotebookLM, GoogleAgent-Mariner, Google-Site-Verification | `google-user-fetchers-google.txt` | JSON | Active |
| Amazon | Amzn-User | `amzn-user.txt` | JSON (HTML embedded) | Active |
| Common Crawl | CCBot | `commoncrawl.txt` | JSON | Active |

### SEO & Other Crawlers

| Provider | Bots / User-Agents | Data File | Source Type | Status |
|----------|--------------------|-----------|-------------|--------|
| Ahrefs | AhrefsBot, AhrefsSiteAudit | `ahrefs.txt` | JSON | Active |
| Babbar | Barkrowler | `barkrowler.txt` | JSON | Active |
| Facebook / Meta | facebookexternalhit, meta-externalagent | `facebook.txt` | Geofeed (CSV) | Active |
| Telegram | TelegramBot (link previews) | `telegram.txt` | CIDR Text | Active |

### Uptime Monitoring

| Provider | Bots / User-Agents | Data File | Source Type | Status |
|----------|--------------------|-----------|-------------|--------|
| UptimeRobot | UptimeRobot | `uptimerobot.txt` | Text | Active |
| Pingdom | Pingdom.com_bot | `pingdom.txt` | Text | Active |

> **Note:** The Yandex list covers all Yandex-owned networks, not only YandexBot, and the Facebook geofeed covers all Meta networks (IPv4 only). The Google user-triggered fetcher and Amazon lists are large and change often.

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
├── .github/
│   ├── dependabot.yml     # Weekly GitHub Actions version updates
│   └── workflows/
│       └── update_ips.yml # Weekly automation workflow
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

[Dependabot](.github/dependabot.yml) checks the GitHub Actions used by the workflow every Monday and opens a single grouped PR when newer versions are available.

## Contributing

To add a new provider:
1. Add the provider and its URL to `providers/providers.txt` (format: `provider_name=https://url...`).
2. Add verification keywords to `providers/record_name.txt` if needed.
3. In `scripts/update_ips.py`:
    - Implement a `parse_<provider>` function (or reuse `parse_prefixes` for the standard `{"prefixes": [{"ipv4Prefix": ...}]}` format).
    - Add the parser to the `PARSERS` dictionary.
