local base64 = require("suricata.base64")

function init(args)
    return {}
end

function match(args)
    -- "AA==" decodes to a single NUL byte
    local d = base64.decode("AA==")
    if #d ~= 1 or string.byte(d, 1) ~= 0 then
        return 0
    end

    -- interior NUL: "foo\0bar"
    d = base64.decode("Zm9vAGJhcg==")
    if #d ~= 7 or string.byte(d, 4) ~= 0 then
        return 0
    end

    d = base64.decode_nopad("Zm9vAGJhcg")
    if #d ~= 7 or string.byte(d, 4) ~= 0 then
        return 0
    end

    d = base64.decode_padopt("Zm9vAGJhcg==")
    if #d ~= 7 or string.byte(d, 4) ~= 0 then
        return 0
    end

    d = base64.decode_rfc4648("Zm9vAGJhcg==")
    if #d ~= 7 or string.byte(d, 4) ~= 0 then
        return 0
    end

    d = base64.decode_rfc2045("Zm9vAGJhcg==")
    if #d ~= 7 or string.byte(d, 4) ~= 0 then
        return 0
    end

    return 1
end
