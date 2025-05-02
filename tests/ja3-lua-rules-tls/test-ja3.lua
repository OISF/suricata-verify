local ja3 = require("suricata.ja3")

function init (args)
   ja3.enable_ja3()
   local needs = {}
   needs["ja3s"] = tostring(true)
   return needs
end

function match(args)
   local tx = ja3.get_tx()
   local s = tx:ja3s_get_string()
   print(s)
   if s == "771,49199,65281-0-11-16-23" then
      return 1
   end
   return 0
end
