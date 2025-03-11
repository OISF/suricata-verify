local dns = require("suricata.dns")

function init (args)
   local needs = {}
   needs["dns.request"] = tostring(true)
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
   if dns.txid() ~= 36146 then
      return 0
   end

   -- The requested name.
   local rrname = dns.rrname()
   if rrname ~= "www.suricata-ids.org" then
      return 0
   end

   -- Queries
   local queries = dns.queries()
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

   local answers = dns.answers()
   if answers == nil then return 0 end
   if count(answers) ~= 0 then return 0 end

   local authorities = dns.authorities()
   if authorities == nil then return 0 end
   if count(authorities) ~= 0 then return 0 end

   return 1
end
