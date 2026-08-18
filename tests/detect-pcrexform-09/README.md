Test invalid use of `absent: or_else` with pcrexform. Verifies that
using or_else with a transform that can fail causes a fatal error
during rule loading.
