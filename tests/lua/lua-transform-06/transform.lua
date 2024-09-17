function init (args)
    local needs = {}
    return needs
end

-- Arguments supported
local bytes_key = "bytes"
local offset_key = "offset"
function transform(input_len, input, argc, args)
    local bytes = input_len
    local offset = 0

    local sub = string.sub(input, offset + 1, offset + bytes)
    -- Note -- only one value is returned when 2 are expected: buffer, byte-count
    return string.upper(sub)
end
