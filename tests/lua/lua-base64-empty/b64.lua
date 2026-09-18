local base64 = require("suricata.base64")

function init(args)
    return {}
end

function match(args)
    -- empty input must decode/encode to an empty string, not raise
    if base64.decode("") ~= "" then
        return 0
    end
    if base64.decode_nopad("") ~= "" then
        return 0
    end
    if base64.decode_padopt("") ~= "" then
        return 0
    end
    if base64.decode_rfc2045("") ~= "" then
        return 0
    end
    if base64.decode_rfc4648("") ~= "" then
        return 0
    end
    if base64.encode("") ~= "" then
        return 0
    end
    return 1
end
