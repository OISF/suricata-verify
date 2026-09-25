# ruletype-firewall-281-lte-uncounted-sibling-coverage

An LTE candidate that is excluded from the coverage (here: an out-of-scope,
flowbits-activated rule appended to the walk) must not be treated as carrying
its own count in `DetectFwOtherLteCoversHook()`. While the in-scope
`<request_headers` rule (sid:101) is still pending, the uncounted sibling must
not set the hook default: sid:101 resolves and accepts at packet 10.

Guards the count-aware coverage check and the retire clearing the candidate's
counted state; the pure arithmetic is unit-tested in `src/tests/detect.c`
(`DetectFwLteCoverageTest01/02`).
