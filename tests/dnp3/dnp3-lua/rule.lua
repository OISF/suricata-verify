local dnp3 = require("suricata.dnp3")

function init (args)
   return {}
end

function match(args)
   -- No args for DNP3.
   
   -- Get transaction.
   local tx = dnp3.get_tx()

   if not tx["is_request"] then
      return 0
   end

   local request = tx["request"]
   if request == nil then
      return 0
   end

   if not request["done"] then
      return 0
   end

   if not request["complete"] then
      return 0
   end

   return 1
end
