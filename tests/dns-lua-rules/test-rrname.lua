local dns = require("suricata.dns")

function init (args)
   local needs = {}
   needs["dns.request"] = true
   return needs
end

function match(args)
   local tx = dns.get_tx()
   local rrname = tx:rrname()
   if rrname == "www.suricata-ids.org" then
      return 1
   end
   return 0
end
