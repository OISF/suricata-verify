local flowintlib = require("suricata.flowint")

function init ()
   local set_counter = flowintlib.register("set_counter")
   local incr_counter = flowintlib.register("incr_counter")
   local decr_counter = flowintlib.register("decr_counter")
   return {}
end

function thread_init ()
   set_counter = flowintlib.get("set_counter")
   incr_counter = flowintlib.get("incr_counter")
   decr_counter = flowintlib.get("decr_counter")
end

function match ()
   print("update-counter.lua: match")

   local value = set_counter:value()
   if value == nil then
      set_counter:set(10)
   else
      set_counter:set(value + 10)
   end

   local incr_value = incr_counter:value()
   local tmp = incr_counter:incr()
   if incr_value == nil then
      if tmp ~= 1 then
         print("incr return unexpected value")
         return 0
      end
   else
      if tmp ~= incr_value + 1 then
         print("incr return unexpected value")
         return 0
      end
   end

   local decr_value = decr_counter:value()
   if decr_value == nil then
      print("decr_counter not set, initializing to 9")
      decr_counter:set(9)
   else
      print("decrementing counter with value", desc_value)
      decr_counter:decr()
   end

   if set_counter:value() ~= 50 then
      print("set_counter has unexpected value of ", set_counter:value())
      return 0
   end

   if decr_counter:value() ~= 5 then
      print("decr_counter has unexpected value of ", decr_counter:value())
      return 0
   end

   if incr_counter:value() ~= 5 then
      print("incr_counter has unexpected value of ", incr_counter:value())
   end

   return 1
end
