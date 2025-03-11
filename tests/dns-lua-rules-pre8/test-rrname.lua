function init (args)
   local needs = {}
   needs["dns.rrname"] = tostring(true)
   return needs
end

function match(args)
   rrname = tostring(args["dns.rrname"])
   if rrname == "www.suricata-ids.org" then
      return 1
   end
   return 0
end
