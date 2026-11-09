local util = require("suricata.util")
local ntp = require("suricata.ntp")

function init(args)
   return {}
end

function match(args)
   -- restrict to the v4 client request so the test is deterministic
   local tx, err = ntp.get_tx()
   if tx == nil then
      return 0
   end
   if tx:version() ~= 4 or tx:mode() ~= 3 then
      return 0
   end

   -- signature-hook rule: match runs once per transaction in the
   -- application-layer context; before the fix the ThreadVars registry
   -- entry was only set by the packet match path, so thread_info()
   -- raised "internal error: no tv" here
   local info = util.thread_info()
   if type(info) ~= "table" then
      return 0
   end

   if info.id ~= nil and info.name ~= nil then
      return 1
   end

   return 0
end
