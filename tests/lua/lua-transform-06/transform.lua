function transform(input, args)
    local bytes = #input
    local offset = 0

    local sub = string.sub(input, offset + 1, offset + bytes)
    -- Note -- only one value is returned when 2 are expected: buffer, byte-count
    return string.upper(sub)
end
