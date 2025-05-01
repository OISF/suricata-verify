local flowintlib = require("suricata.flowint")

function init ()
   return {}
end

function thread_init ()
   root_count = flowintlib.get("root_count")
end

function match ()
   if root_count:value() == 5 then
      return 1
   end

   return 0
end
