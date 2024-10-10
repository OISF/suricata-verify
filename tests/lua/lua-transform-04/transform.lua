-- Arguments supported
local bytes_key = "bytes"
local offset_key = "offset"
function transform(input_len, input, argc, args)
    offset = 0
    bytes = input_len
    for i, item in ipairs(args) do
        print(i .. " item: " .. item)
    end

    local sub = string.sub(input, offset + 1, offset + bytes)
    return string.upper(sub), bytes
end
