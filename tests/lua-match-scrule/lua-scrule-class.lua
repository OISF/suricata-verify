local rule = require("suricata.rule")

function init(args)
    local needs = {}
    return needs
end

function match(args)
    local sig = rule.get_rule()

    local class_description = sig:class_description()
    if class_description ~= "Potentially Bad Traffic" then
       return 0
    end

    local priority = sig:priority()
    if priority ~= 2 then
       return 0
    end

    return 1
end
