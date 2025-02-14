function transform(input, args)
    local bytes = #input
    local offset = 0

    local sub = string.sub(input, offset + 1, offset + bytes)
    return string.upper(sub), bytes
end
