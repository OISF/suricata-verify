# app-layer-protocol-prefilter

Verifies that a single-value `app-layer-protocol` rule is prefilterable and
matches through the prefilter path. The rule uses an explicit `prefilter;` to
force the prefilter engine; the alert firing on the tls flow confirms the
prefilter set/compare/match path works for single-value keywords (the positive
counterpart to `app-layer-protocol-list-prefilter-invalid`).
