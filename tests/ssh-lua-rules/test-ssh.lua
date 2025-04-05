local ssh = require("suricata.ssh")

function init (args)
   return {}
end

function match(args)
   local tx = ssh.get_tx()
   local proto = tx:server_proto()
   if proto == "2.0" then
      local soft = tx:server_software()
      if soft == "OpenSSH_7.4" then
         return 1
      end
   end
   return 0
end
