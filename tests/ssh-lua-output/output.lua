local ssh = require("suricata.ssh")

filename = "results.log"

function init (args)
    local needs = {}
    needs["protocol"] = "ssh"
    return needs
end

function setup (args)
    SCLogNotice("lua: setup()")
    file = assert(io.open(SCLogPath() .. "/" .. filename, "w"))
end

function log(args)
    local tx = ssh.get_tx()
    local proto = tx:server_proto()
    if proto == "2.0" then
       local msg = tx:client_software().." -> "..tx:server_software()
       write(msg)
    end
end

function deinit(args)
    file:close(file)
end

function write(msg)
    file:write(msg .. "\n")
end
