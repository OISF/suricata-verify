function init(args)
    return {}
end

function match(args)
    sid, rev, gid = SCRuleIds()

    if sid == 1 and rev == 7 and gid == 1 then
        return 1
    else
        return 0
    end
end
