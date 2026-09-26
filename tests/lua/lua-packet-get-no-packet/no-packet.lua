-- Cover: packet.get() in an app-layer (tx) context where there is no
-- packet. It must return nil plus the error message "failed to get packet",
-- not a stale packet from a previous packet-phase inspection. Guards the
-- unconditional write of the packet registry entry.
local packet = require("suricata.packet")
local logger = require("suricata.log")

function init(args)
   return {}
end

function match(args)
   local p, err = packet.get()
   if p == nil then
      logger.notice(string.format("nopacket nil err=%s", tostring(err)))
   else
      logger.notice("nopacket got-packet")
   end
   return 0
end
