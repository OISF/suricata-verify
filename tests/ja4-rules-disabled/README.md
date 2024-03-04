# JA4 Disabled Test Case

This test checks -- in cases where JA4 support is disabled -- whether
using rules that require JA4 support are actually rejected if no "requires"
keyword is given.

We expect something like:

```
Error: detect-ja4-hash: JA4 support is not enabled [DetectJa4HashSetup:detect-ja4-hash.c:122]
Error: detect: error parsing signature "alert quic any any -> any any (msg:"JA4 QUIC Test 1"; ja4.hash; content: "q13d0310h3_55b375c5d22e_cd85d2d88918"; sid:1;)" from file suricata-verify/tests/ja4-rules-disabled/test.rules at line 1 [DetectLoadSigFile:detect-engine-loader.c:183]
Error: suricata: Loading signatures failed. [LoadSignatures:suricata.c:2427]
```
