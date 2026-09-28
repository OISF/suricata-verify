# relative pcre with an unusable preceding keyword

The load time check for a relative pcre must stay strict: `byte_test` and
`isdataat` only read the detection pointer, they do not move it, and a bare
relative pcre has nothing to anchor on. All 3 rules of this test must fail to
load with

    pcre with /R (relative) needs preceding match in the same buffer

which makes Suricata exit with an error because of --init-errors-fatal.

Guards the fix of Redmine #7987 against loosening the check beyond the keywords
that do move the detection pointer. The pcap is the one of the
detect-pcre-relative-bytejump test; it is never read as the rules do not load.
