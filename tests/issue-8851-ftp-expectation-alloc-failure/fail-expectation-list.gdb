set pagination off
set confirm off
set $seen = 0
set $armed = 0
set $target_ipp = 0
break app-layer-expectation.c:260
commands
    silent
    set $seen = $seen + 1
    if $seen == 2
        set $target_ipp = ipp
        set $armed = 1
        set exp_list = 0
        disable $_hit_bpnum
        printf "SV_FAULT_INJECTION: ExpectationList allocation -> NULL\n"
    end
    continue
end
break IPPairRelease
commands
    silent
    if $armed == 1 && h == $target_ipp
        set $armed = 0
        printf "SV_EXPECTED: failed expectation released IPPair\n"
    end
    continue
end
run
