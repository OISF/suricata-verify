local ssh = require("suricata.hassh")

function init (args)
   return {}
end

function match(args)
   local tx = ssh.get_tx()
   local h = tx:server_hassh()
   print(h)
   if h == "6832f1ce43d4397c2c0a3e2f8c94334e" then
      return 1
   end
   return 0
end
