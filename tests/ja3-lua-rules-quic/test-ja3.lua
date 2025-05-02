local ja3 = require("suricata.ja3")

function init (args)
   ja3.enable_ja3()
   local needs = {}
   needs["ja3"] = tostring(true)
   return needs
end

function match(args)
   local tx = ja3.get_tx()
   local s = tx:ja3_get_string()
   print(s)
   if s == "771,4865-4866-4867,5-10-11-13-65281-23-16-18-43-51-57,29-23-24-25,0" then
      return 1
   end
   return 0
end
