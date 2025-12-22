function hex_esc(s)
    return string.gsub(s, ".", function(c) return string.format("%02x", string.byte(c)) end)
end

function transform(input, args)
    print("luaxform args: " .. table.concat(args, "|"))

    print("luaxform input size: " .. #input)
    print("luaxform input start: " .. hex_esc(input:sub(1, 128)))

    return input, #input
end
