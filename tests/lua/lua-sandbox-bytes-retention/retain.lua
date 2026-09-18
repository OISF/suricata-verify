retained = {}

function init(args)
    return {}
end

function match(args)
    retained[#retained + 1] = string.rep("R", 8000)
    return 1
end
