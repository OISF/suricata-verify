local tls = require("suricata.tls")

function init (args)
    return {}
end

function match(args)
    local t, err = tls.get_tx()
    if t == err then
        print(err)
    end

    srv_serial = t:get_server_serial()
    if srv_serial == "00:BB:2A:80:CC:14:FC:DD:BC:12:02:B2:A0:86:BD:1D:17" then
        return 1
    end
    cl_version = t:get_client_version()
    if cl_version == "TLS 1.2" then
       return 1
    end

    return 0
end
