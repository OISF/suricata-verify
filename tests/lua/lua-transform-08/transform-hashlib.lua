local hashlib = require("suricata.hashlib")

local function tohex(str)
    local hex = {}
    for i = 1, #str do
        hex[i] = string.format("%02x", string.byte(str, i))
    end
    return table.concat(hex)
end

function transform(input, args)
    local hash = hashlib.sha256_digest(input)
    print(string.format("hash: \"%s\"\n", tohex(hash)))
    local phash = tohex(hash)
    return phash, #phash

end
