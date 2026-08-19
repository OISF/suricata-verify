# app-layer-protocol-negated-duplicate-invalid

Verifies that two negated `app-layer-protocol` keywords with identical (or
otherwise intersecting) protocol value sets under the same mode are rejected at
rule load as a conflict. Disjoint negated sets (e.g. `!http; !dns;`) remain a
valid NOR combination and are unaffected.
