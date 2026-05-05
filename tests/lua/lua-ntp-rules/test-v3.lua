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

   if tx:version() == 3 and tx:mode() == 4 and tx:stratum() == 2 and
      tx:reference_id() == "\x4c\x4f\x43\x4c" then
      return 1
   end

   return 0
end
