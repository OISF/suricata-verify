local flowlib = require("suricata.flow")
local logger = require("suricata.log")

function init(args)
   return {}
end

function match(args)
   local f = flowlib.get()
   if f == nil then
      logger.notice("ftup no flow")
      return 0
   end
   -- IP flow: tuple() must return the 6 documented values
   -- (ipver, src ip, dst ip, proto, sport, dport).
   local t = { f:tuple() }
   if #t ~= 6 then
      logger.notice(string.format("ftup arity=%d", #t))
      return 0
   end
   logger.notice(string.format("ftup %s %s %s %s %s %s",
      tostring(t[1]), tostring(t[2]), tostring(t[3]),
      tostring(t[4]), tostring(t[5]), tostring(t[6])))
   return 1
end
