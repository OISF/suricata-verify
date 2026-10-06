set pagination off
set confirm off
set $in_curve_helper = 0

break TLSDecodeHSHelloExtensionEllipticCurves
commands
    silent
    set $in_curve_helper = 1
    continue
end

break util-ja3.c:181 if $in_curve_helper == 1
commands
    silent
    set (*buffer)->data = 0
    set $in_curve_helper = 0
    printf "SV_FAULT_INJECTION: JA3 curve data allocation -> NULL\n"
    continue
end

run
