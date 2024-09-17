-- Arguments supported
local bytes_key = "bytes"
local offset_key = "offset"
function transform(input, args)
    offset = 0
    bytes = #input
    for i, item in ipairs(args) do
        print(i .. " item: " .. item)
    end

    local sub = string.sub(input, offset + 1, offset + bytes)
    return string.upper(sub), bytes
end
