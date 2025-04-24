local flowvarlib = require("suricata.flowvar")

function init()
   return {}
end

function thread_init()
   flowvar = flowvarlib.get("test_var")
end

function match()
   local value = flowvar:value()
   if value == "foobar" then
      return 1
   else
      print("flowvar does not have expected value")
      return 0
   end
end
