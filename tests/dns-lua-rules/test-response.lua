local io = require("io")
function init (args)
   local needs = {}
   needs["dns.response"] = tostring(true)
   return needs
end

function count(t)
   local count = 0
   for _ in pairs(t) do
      count = count + 1
   end
   return count
end

function match(args)
   if DnsGetTxid() ~= 36146 then
      return 0
   end

   -- The requested name.
   local rrname = DnsGetDnsRrname()
   if rrname ~= "www.suricata-ids.org" then
      return 0
   end

   -- Queries
   local queries = DnsGetQueries()
   if queries == nil then return 0 end

   -- There should only be one query.
   if count(queries) ~= 1 then return 0 end

   local query = queries[0]

   if query["type"] ~= "A" then
      return 0
   end
   
   if query["rrname"] ~= "www.suricata-ids.org" then
      return 0
   end

   local rcode = DnsGetRcode()
   print(rcode)

   local answers = DnsGetAnswers()
   if answers == nil then return 0 end
   if count(answers) ~= 3 then return 0 end

   local authorities = DnsGetAuthorities()
   if authorities == nil then return 0 end
   if count(authorities) ~= 0 then return 0 end

   -- TODO: Look at the answers.

   return 1
end
