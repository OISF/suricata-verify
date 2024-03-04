# JA4 Disabled Test Case -- With `required` Keyword

This test checks -- in cases where JA4 support is disabled -- whether
using rules that require JA4 support are actually skipped if the "requires"
keyword is given.

We expect something like:

```
Info: detect-requires: Suricata did not meet the rule requirements: Suricata missing a required feature: feature ja4 [DetectRequiresSetup:detect-requires.c:38]
Info: detect: Skipping signature due to missing requirements: alert quic any any -> any any (msg:"JA4 Requires Test 1"; requires: feature ja4; sid:1;) from file /home/satta/tmp/suricata-verify/tests/ja4-rules-requires/test.rules at line 1 [DetectLoadSigFile:detect-engine-loader.c:203]
Info: detect-requires: Suricata did not meet the rule requirements: Suricata missing a required feature: feature ja4 [DetectRequiresSetup:detect-requires.c:38]
Info: detect: Skipping signature due to missing requirements: alert tls any any -> any any (msg:"JA4 Requires Test 2"; requires: feature ja4; sid:2;) from file /home/satta/tmp/suricata-verify/tests/ja4-rules-requires/test.rules at line 2 [DetectLoadSigFile:detect-engine-loader.c:203]
Warning: detect: 1 rule files specified, but no rules were loaded! [SigLoadSignatures:detect-engine-loader.c:359]
```
