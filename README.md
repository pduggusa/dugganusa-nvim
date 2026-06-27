# DugganUSA Threat Intel — Neovim Plugin

**Check IPs, domains, hashes, CVEs under cursor against 1.10M+ IOCs. For the terminal crowd.**

## What's New

The corpus this plugin queries now ships **three live, no-auth, durable validation endpoints** so you can verify feed quality yourself — they survive deploys, so the numbers are real:

- **Novelty** — [feed-uniqueness](https://analytics.dugganusa.com/api/v1/feed-uniqueness): ~75%+ of what we publish is **not in ThreatFox**.
- **Timeliness** — [kev-lead](https://analytics.dugganusa.com/api/v1/kev-lead): we flag exploited CVEs roughly **31 days ahead of CISA KEV** on average.
- **Accuracy** — [spamhaus-validation](https://analytics.dugganusa.com/api/v1/spamhaus-validation): Spamhaus **independently corroborates** our first-hand contributions.

So the indicator under your cursor is checked against intel that is independently novel, early, and corroborated. (We cap our own claims at 95% honest confidence.)

## Install

### lazy.nvim

```lua
{ "pduggusa/dugganusa-nvim", config = function() require("dugganusa").setup() end }
```

### packer.nvim

```lua
use { "pduggusa/dugganusa-nvim", config = function() require("dugganusa").setup() end }
```

### vim-plug

```vim
Plug 'pduggusa/dugganusa-nvim'
lua require("dugganusa").setup()
```

## Usage

| Command / Keymap | Description |
|------------------|-------------|
| `:DugganUSA` | Look up word under cursor |
| `:DugganUSA 185.39.19.176` | Look up specific indicator |
| `:DugganUSAAipm` | AIPM audit (prompts for domain) |
| `<leader>di` | Look up word under cursor (normal mode) |
| `<leader>di` | Look up selection (visual mode) |
| `<leader>da` | AIPM audit |

## Configuration

```lua
require("dugganusa").setup({
  api_key = "dugusa_YOUR_KEY_HERE",  -- or set DUGGANUSA_API_KEY env var
  api_url = "https://analytics.dugganusa.com/api/v1",
})
```

The feed is **API-key-enforced** — anonymous requests return `401`, an unregistered token returns `429`. The free tier is a **free registered key**, not anonymous access. Register (30 seconds, no card) at [analytics.dugganusa.com/stix/register](https://analytics.dugganusa.com/stix/register), then set `api_key` or the `DUGGANUSA_API_KEY` env var.

## Requirements

- Neovim 0.8+
- `curl` in PATH

## Part of the DugganUSA Ecosystem

- [VS Code Extension](https://marketplace.visualstudio.com/items?itemName=DugganUSALLC.dugganusa-threat-intel)
- [CLI Tool](https://github.com/pduggusa/dugganusa-cli)
- [Chrome Extension](https://github.com/pduggusa/dugganusa-chrome)
- [Raycast](https://github.com/pduggusa/dugganusa-raycast)
- [Obsidian](https://github.com/pduggusa/dugganusa-obsidian)
- [Splunk TA](https://github.com/pduggusa/dugganusa-splunk)
- [Sentinel](https://github.com/pduggusa/dugganusa-sentinel)
- [Elastic](https://github.com/pduggusa/dugganusa-elastic)
- [dugganusa.com](https://www.dugganusa.com)

## License

MIT — [DugganUSA LLC](https://www.dugganusa.com)

---

<!-- DUGGANUSA-FAMILY-FOOTER-V1 -->
## DugganUSA Defender Family

Same threat corpus, surfaced wherever you live. Open source, MIT licensed, receipts on every repo.

| Plugin | Surface |
|---|---|
| [dugganusa-scanner-core](https://github.com/pduggusa/dugganusa-scanner-core) | Core IOC scanning engine |
| [dugganusa-vscode](https://github.com/pduggusa/dugganusa-vscode) | VS Code extension |
| [dugganusa-splunk](https://github.com/pduggusa/dugganusa-splunk) | Splunk Technology Add-on |
| [dugganusa-slack](https://github.com/pduggusa/dugganusa-slack) | Slack bot |
| [dugganusa-raycast](https://github.com/pduggusa/dugganusa-raycast) | Raycast extension |
| [dugganusa-sentinel](https://github.com/pduggusa/dugganusa-sentinel) | Microsoft Sentinel TAXII connector |
| [dugganusa-obsidian](https://github.com/pduggusa/dugganusa-obsidian) | Obsidian plugin |
| **dugganusa-nvim** _(this repo)_ | Neovim plugin |
| [dugganusa-elastic](https://github.com/pduggusa/dugganusa-elastic) | Elastic / OpenSearch integration |
| [dugganusa-edge-shield](https://github.com/pduggusa/dugganusa-edge-shield) | Cloudflare Worker |
| [dugganusa-cli](https://github.com/pduggusa/dugganusa-cli) | CLI scanner |
| [dugganusa-chrome](https://github.com/pduggusa/dugganusa-chrome) | Chrome extension |
| [dugganusa-action](https://github.com/pduggusa/dugganusa-action) | GitHub Action |
| [dredd-mcp](https://github.com/pduggusa/dredd-mcp) | Pre-flight MCP security (this repo) |

Backed by the live DugganUSA threat intel platform: [analytics.dugganusa.com](https://analytics.dugganusa.com).

_Jeevesus saves. Dredd judges._
