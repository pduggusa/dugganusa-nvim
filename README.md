# DugganUSA Threat Intel — Neovim Plugin

**Check IPs, domains, hashes, CVEs under cursor against 1M+ IOCs. For the terminal crowd.**

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

Free tier works without a key. Get one at [analytics.dugganusa.com/stix/register](https://analytics.dugganusa.com/stix/register).

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
