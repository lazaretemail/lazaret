--[[
SPDX-License-Identifier: AGPL-3.0-only

Lazaret plugin for Rspamd.

Sends the message being scanned to lazaret-ingest and folds the result into Rspamd's
score. This is the only integration point where a verdict can stop a message before it
reaches a mailbox; every other source in this project sees mail that has already been
delivered.

Install:

    cp lazaret.lua /etc/rspamd/lua/lazaret.lua

    # /etc/rspamd/rspamd.local.lua
    dofile('/etc/rspamd/lua/lazaret.lua')

    # /etc/rspamd/local.d/lazaret.conf
    lazaret {
      url = "http://lazaret-ingest:8730/rspamd/check";
      secret = "change-me";
      timeout = 20.0;
      enabled = true;
    }

Then register the symbol scores, so an operator can retune without editing Lua:

    # /etc/rspamd/local.d/groups.conf
    group "lazaret" {
      symbols {
        "LAZARET_MALICIOUS"     { weight = 1.0; description = "Lazaret flagged this"; }
        "LAZARET_INDETERMINATE" { weight = 1.0; description = "Lazaret could not fully evaluate"; }
        "LAZARET_CLEAN"         { weight = 0.0; description = "Lazaret found nothing"; }
        "LAZARET_FAIL"          { weight = 0.0; description = "Lazaret was unreachable"; }
      }
    }

# On failure

The plugin fails OPEN. If Lazaret is unreachable or slow, the message is delivered and
LAZARET_FAIL is inserted with a weight of zero.

That is a deliberate choice and worth stating plainly, because the opposite is
defensible too. Failing closed would mean an engine restart stops all mail — an outage
that is more visible, more disruptive, and far more likely to get the whole system
removed than a window of missed detection. The zero-weight symbol exists so the failure
is still *visible*: it appears in the headers and the logs, and it can be alerted on.
An operator who would rather fail closed changes the action in one place, below.

# On indeterminate

Rspamd gets three answers, not two. LAZARET_INDETERMINATE means the engine ran and
could not decide, because something it needed — a model, a file scanner, a lookup — was
unavailable. It scores a little, because an unevaluated message has not been cleared,
and it is a separate symbol from LAZARET_CLEAN so that "we found nothing" and "we could
not look" never read the same in a report.
--]]

local rspamd_http = require "rspamd_http"
local rspamd_logger = require "rspamd_logger"
local ucl = require "ucl"

local N = 'lazaret'

local settings = {
  url = 'http://127.0.0.1:8730/rspamd/check',
  secret = '',
  timeout = 20.0,
  -- Messages above this are not sent. Rspamd has already spent memory on them, and a
  -- 50MB attachment is not where detection value lives.
  max_size = 25 * 1024 * 1024,
  enabled = true,
}

local opts = rspamd_config:get_all_opt(N)
if opts then
  for k, v in pairs(opts) do settings[k] = v end
end

-- Symbols are registered with zero weight here and given real weights in groups.conf,
-- which is where an operator expects to tune them. The score Lazaret returns is applied
-- with the symbol rather than baked into its weight, so severity travels per message.
local symbols = {
  malicious     = 'LAZARET_MALICIOUS',
  indeterminate = 'LAZARET_INDETERMINATE',
  clean         = 'LAZARET_CLEAN',
  fail          = 'LAZARET_FAIL',
}

local function lazaret_check(task)
  if not settings.enabled then return end

  local content = task:get_content()
  if not content or #content == 0 then return end

  if #content > settings.max_size then
    rspamd_logger.infox(task, 'skipping a %s byte message, over the %s limit',
      #content, settings.max_size)
    return
  end

  local headers = { ['Content-Type'] = 'message/rfc822' }
  if settings.secret and settings.secret ~= '' then
    headers['Password'] = settings.secret
  end
  -- The recipient, so the engine can attribute the message to a mailbox. First
  -- recipient only: a message to many is one message, and the engine records it once.
  local rcpts = task:get_recipients('smtp')
  if rcpts and rcpts[1] and rcpts[1].addr then
    headers['Rcpt'] = rcpts[1].addr
  end

  local function on_reply(err, code, body)
    if err then
      -- Fail open. Change this to task:insert_result(symbols.fail, 1.0) plus a
      -- soft_reject if you would rather hold mail than deliver it unscanned.
      rspamd_logger.errx(task, 'lazaret unreachable: %s', err)
      task:insert_result(symbols.fail, 0.0, tostring(err))
      return
    end
    if code ~= 200 then
      rspamd_logger.errx(task, 'lazaret returned %s', code)
      task:insert_result(symbols.fail, 0.0, 'http ' .. tostring(code))
      return
    end

    local parser = ucl.parser()
    local ok, perr = parser:parse_string(body)
    if not ok then
      rspamd_logger.errx(task, 'lazaret sent unparsable json: %s', perr)
      task:insert_result(symbols.fail, 0.0, 'bad json')
      return
    end
    local reply = parser:get_object()

    local verdict = reply.verdict or 'unknown'
    local score = tonumber(reply.score) or 0.0
    local desc = reply.description or verdict

    if verdict == 'malicious' then
      task:insert_result(symbols.malicious, score, desc)
      rspamd_logger.infox(task, 'lazaret flagged %s: %s (score %s)',
        reply.message_id or '?', desc, score)
    elseif verdict == 'indeterminate' then
      task:insert_result(symbols.indeterminate, score, desc)
      rspamd_logger.infox(task, 'lazaret could not fully evaluate %s: %s',
        reply.message_id or '?', desc)
    elseif verdict == 'clean' then
      task:insert_result(symbols.clean, 0.0, desc)
    else
      task:insert_result(symbols.fail, 0.0, 'unknown verdict ' .. tostring(verdict))
    end
  end

  rspamd_http.request({
    task = task,
    url = settings.url,
    body = content,
    headers = headers,
    timeout = settings.timeout,
    callback = on_reply,
    -- Asynchronous, so Rspamd keeps running its own checks while Lazaret works. A
    -- synchronous call here would serialise the whole scan behind the slowest thing
    -- in it, which for a message with attachments is file explosion.
    method = 'POST',
  })
end

local id = rspamd_config:register_symbol({
  name = 'LAZARET_CHECK',
  type = 'callback',
  callback = lazaret_check,
  -- After the cheap checks, so a message Rspamd has already decided about on SPF or
  -- Bayes does not cost a full rule evaluation.
  priority = 5,
})

for _, sym in pairs(symbols) do
  rspamd_config:register_symbol({
    name = sym,
    type = 'virtual',
    parent = id,
    score = 0.0,
  })
end

rspamd_logger.infox(rspamd_config, 'lazaret: registered, posting to %s', settings.url)
