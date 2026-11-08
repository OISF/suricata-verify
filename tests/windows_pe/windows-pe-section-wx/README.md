Tests the `section_wx` option of the `windows_pe` keyword, which detects
PEs containing sections with both Write and Execute permissions — a common
indicator of packed or self-modifying code. The test PEs have no W+X
sections, so the `section_wx` rule produces zero alerts while a bare
`windows_pe` rule matches all five PEs.
