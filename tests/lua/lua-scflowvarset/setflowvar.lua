local flowvarlib = require("suricata.flowvar")

function init()
   local flowvar = flowvarlib.register("test_var")
   return {}
end

function thread_init()
   flowvar = flowvarlib.get("test_var")
end

function match()
   local value = flowvar:value()
   if value ~= nil then
      print("flowvar value should be nil")
      return 0
   end

   local value = "foobar"
   flowvar:set(value, string.len(value))

   return 1
end
