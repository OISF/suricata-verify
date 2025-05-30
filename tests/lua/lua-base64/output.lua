-- Test that "suricata.base64" can be used from a Lua output
-- script. More thourough testing of base64 in rule.lua.

local base64 = require("suricata.base64")
local dns = require("suricata.dns")
local logger = require("suricata.log")
local config = require("suricata.config")

local expected_base64 = "d3d3LnN1cmljYXRhLWlkcy5vcmc="

filename = "results.log"

function init (args)
   local needs = {}
   needs["protocol"] = "dns"
   return needs
end

function setup (args)
   logger.notice("lua: setup()")
   file = assert(io.open(config.log_path() .. "/" .. filename, "w"))
end

function log(args)
   local tx = dns.get_tx()
   queries = tx:queries()
   if queries ~= nil then
      for n, t in pairs(queries) do

         if base64.encode(t["rrname"]) == expected_base64 then
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
