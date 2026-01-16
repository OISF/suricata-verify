function manual_xor(a, b)
    local result = 0
    local bit = 1
    while a > 0 or b > 0 do
        local bit_a = a % 2
        local bit_b = b % 2
        if bit_a ~= bit_b then
            result = result + bit
        end
        a = math.floor(a / 2)
        b = math.floor(b / 2)
        bit = bit * 2
    end
    return result
end

function init(args)
    local needs = {}
    needs["payload"] = tostring(true)
    return needs
end

function match(args)
    local payload = args["payload"]
    if not payload then
        return 0
    end

    if #payload < 6 then
        return 0
    end

    local byte1 = payload:byte(1)
    local byte2 = payload:byte(2) 
    local byte3 = payload:byte(3)
    local byte4 = payload:byte(4)

    if byte1 ~= 0x00 or byte2 ~= 0x00 or byte3 ~= 0x04 or byte4 ~= 0x01 then
        return 0
    end

    local xor_key = payload:byte(5)

    local encrypted_data = payload:sub(6)

    local decrypted = "" 
    for i = 1, #encrypted_data do
        local encrypted_byte = encrypted_data:byte(i)
        local decrypted_byte = manual_xor(encrypted_byte, xor_key)
        decrypted = decrypted .. string.char(decrypted_byte)
    end

    local traffic_found = string.find(decrypted:lower(), "traffic")

    if traffic_found then
        SCLogInfo("XOR Traffic Detected - 'traffic' keyword found!")
        SCLogInfo("XOR Key: 0x" .. string.format("%02x", xor_key))
        SCLogInfo("Decrypted Message: " .. decrypted)
        SCLogInfo("Payload Length: " .. #encrypted_data .. " bytes")
        SCLogInfo("Validation Method: Keyword 'traffic' found at position " .. traffic_found)

        return 1
    end

    return 0
end
