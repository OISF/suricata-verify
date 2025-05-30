local hashlib = require("suricata.hashlib")
local dns = require("suricata.dns")
local logger = require("suricata.log")

-- We don't actually use, but the script will fail to run if it fails
-- to "require".
local dataset = require("suricata.dataset")

-- www.suricata-ids.org
local expected_md5 = "27170ec0609347c6a158bb5b694822a5"

filename = "results.log"

function init (args)
   local needs = {}
   needs["protocol"] = "dns"
   return needs
end

function setup (args)
   logger.notice("lua: setup()")
   file = assert(io.open(SCLogPath() .. "/" .. filename, "w"))
end

function log(args)
   local tx = dns.get_tx()
   queries = tx:queries()
   if queries ~= nil then
      for n, t in pairs(queries) do
         if hashlib.md5_hexdigest(t["rrname"]) == expected_md5 then
            msg = "OK"
         else
            msg = "FAIL"
         end
	 write(msg)
      end
   end
end

function deinit(args)
   file:close(file)
end

function write(msg)
   file:write(msg .. "\n")
end
