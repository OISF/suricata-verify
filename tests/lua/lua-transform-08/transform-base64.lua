local base64 = require("suricata.base64")

function transform(input, args)
    encoded = base64.encode(input)
    return encoded, #encoded
end
