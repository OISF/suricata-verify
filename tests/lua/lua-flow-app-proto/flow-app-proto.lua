local flowlib = require("suricata.flow")
local logger = require("suricata.log")

function init(args)
   return {}
end

function match(args)
   local f = flowlib.get()
   if f == nil then
      logger.notice("alproto no flow")
      return 0
   end
   -- app_layer_proto() must return the 5 documented alproto name strings;
   -- for a dns flow the first value is the flow's proto name "dns".
   local t = { f:app_layer_proto() }
   if #t ~= 5 then
      logger.notice(string.format("alproto arity=%d", #t))
      return 0
   end
   logger.notice(string.format("alproto n=%d first=%s all=%s %s %s %s %s",
      #t, tostring(t[1]), tostring(t[1]), tostring(t[2]), tostring(t[3]),
      tostring(t[4]), tostring(t[5])))
   return 1
end
