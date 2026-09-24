local ssh = require("suricata.ssh")

function init(args)
   return {}
end

function match(args)
   local tx = ssh.get_tx()
   if tx and tx:server_proto() == "2.0" then
      return 1
   end
   return 0
end
