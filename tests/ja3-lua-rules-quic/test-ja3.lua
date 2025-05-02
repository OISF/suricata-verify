local ja3 = require("suricata.ja3")

function init (args)
   ja3.enable_ja3()
   local needs = {}
   needs["ja3"] = true
   return needs
end

function match(args)
   local tx = ja3.get_tx()
   local h = tx:ja3_get_hash()
   if h == "ea0aece5703cb982b232a0684fc35b16" then
      local s = tx:ja3_get_string()
      if s == "771,4865-4866-4867,5-10-11-13-65281-23-16-18-43-51-57,29-23-24-25,0" then
         return 1
      end
   end
   return 0
end
