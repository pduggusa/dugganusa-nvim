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
        vim.fn.system("open 'https://aipmsec.com/audit.html?domain=" .. clean .. "' 2>/dev/null || xdg-open 'https://aipmsec.com/audit.html?domain=" .. clean .. "' 2>/dev/null &")
        vim.notify("AIPM audit opened for " .. clean, vim.log.levels.INFO)
      end
    end)
  end, {})

  -- Keymap: <leader>di for lookup, <leader>da for AIPM
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
end

function M.lookup(value)
  if not value or value == "" then
    vim.notify("DugganUSA: no indicator under cursor", vim.log.levels.WARN)
    return
  end

  vim.notify("DugganUSA: checking " .. value .. "...", vim.log.levels.INFO)

  local url = M.config.api_url .. "/search/correlate?q=" .. vim.fn.shellescape(value)
  local cmd = "curl -s"
  if M.config.api_key ~= "" then
    cmd = cmd .. " -H 'Authorization: Bearer " .. M.config.api_key .. "'"
  end
  cmd = cmd .. " '" .. M.config.api_url .. "/search/correlate?q=" .. value .. "'"

  vim.fn.jobstart(cmd, {
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
        vim.notify("✅ DugganUSA: " .. value .. " — clean (not in 1.08M+ IOC index)", vim.log.levels.INFO)
      end
    end,
    on_stderr = function(_, data)
      local err = table.concat(data, "")
      if err ~= "" then vim.notify("DugganUSA: " .. err, vim.log.levels.ERROR) end
    end,
  })
end

return M
