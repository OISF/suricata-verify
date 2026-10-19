-- the input itself on a KEEP body, a valid empty result otherwise
function transform(input, args)
    if string.find(input, "KEEP") ~= nil then
        return input, #input
    end
    return "", 0
end
