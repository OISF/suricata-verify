function init (args)
   local needs = {}
   return needs
end

function match(args)
   rrname = DnsGetDnsRrname()
   if rrname == "www.suricata-ids.org" then
      return 1
   end
   return 0
end
