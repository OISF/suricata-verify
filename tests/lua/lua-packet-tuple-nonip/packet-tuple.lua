-- Cover: packet:tuple() arity for a non-IP (ARP) packet.
-- Documented contract: 1 value for non-IP (the IP version 0), 6 for IP.
local packet = require("suricata.packet")
local logger = require("suricata.log")

function init(args)
   return {}
end

function match(args)
   local p = packet.get()
   if p == nil then
      logger.notice("ptup no packet")
      return 0
   end
   local t = { p:tuple() }
   logger.notice(string.format("ptup arity %d", #t))
   return 0
end
