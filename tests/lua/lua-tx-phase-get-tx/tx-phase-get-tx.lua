local dnslib = require("suricata.dns")
local logger = require("suricata.log")

function init(args)
   return {}
end

function match(args)
   -- This rule is registered as dns:request_complete, so it is inspected in
   -- the tx phase only (app_inspect is non-NULL -> DetectRunTx). In the tx
   -- phase the tx registry entry is populated by LuaExtensionsMatchSetup,
   -- so dnslib.get_tx() must return the live tx (not nil): pin its rrname
   -- and tx id.
   local tx = dnslib.get_tx()
   if tx == nil then
      logger.notice("txphase get-tx nil")
      return 0
   end
   local rrname = tx:rrname()
   local txid = tx:txid()
   logger.notice(string.format("txphase ok rrname=%s txid=%s",
      tostring(rrname), tostring(txid)))
   return 1
end
