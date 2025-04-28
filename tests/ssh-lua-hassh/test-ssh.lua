local ssh = require("suricata.ssh")

function init (args)
   local needs = {}
   needs["ssh.hassh"] = tostring(true)
   return needs
end

function match(args)
   local tx = ssh.get_tx()
   local h = tx:client_hassh()
   print(h)
   if h == "2dd6531c7e89d3c925db9214711be76a" then
      return 1
   end
   return 0
end
