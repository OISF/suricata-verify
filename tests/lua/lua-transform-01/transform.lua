-- Arguments supported
local bytes_key = "bytes"
local offset_key = "offset"
function transform(input_len, input, argc, args)
    local bytes = input_len
    local offset = 0

    local sub = string.sub(input, offset + 1, offset + bytes)
    return string.upper(sub), bytes
end
