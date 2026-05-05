local ntp = require("suricata.ntp")

function init(args)
   return {}
end

function match(args)
   local tx, err = ntp.get_tx()
   if tx == nil then
      print(err)
      return 0
   end

   if tx:version() == 4 and tx:mode() == 3 and tx:stratum() == 0 and
      tx:reference_id() == "\0\0\0\0" then
      return 1
   end

   return 0
end
