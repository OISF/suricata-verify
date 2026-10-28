TCP reassembly overlap check misses a non-adjacent predecessor ("shield segment")

src/stream-tcp-list.c CheckOverlap() tests only the immediate RB-tree predecessor
/successor. The seg tree is keyed on (seq, len), not as an interval tree, so an
earlier-starting segment A that covers a later segment C can sit far back in tree
order. An attacker inserts a small "shield" segment S that sorts as C's immediate
predecessor and does not reach C; C's overlap with A is then never detected
(DoHandleDataCheckBackwards() breaks at S with the comment "no more overlap will
be found"). C silently overwrites A's already-reassembled bytes with no
reassembly_overlap_different_data event. stream->segs_right_edge (max right edge
of all segments) is maintained but not consulted in the overlap check.

input.pcap: A (SEQ 1050, "EXPLOITMARKER..."), shield S (small, sorts between A and
C, does not reach C), then C (overlaps A with different data), to 10.0.0.2:9999.

Expected (fixed): the A/C overlap is detected -> sid:2
(stream-event:reassembly_overlap_different_data) fires, and A's content is
retained under the default overlap policy so sid:1 (content:"EXPLOITMARKER") fires.
Actual (vulnerable, main d996d85d): neither fires (both count 0) — C silently
overwrote A and no overlap anomaly was raised.

Validation: the same rules + a control pcap (A then C, no shield) yield sid:1 == 1
and sid:2 == 1 on current code — i.e. this test passes once the shielded overlap
is detected.

https://redmine.openinfosecfoundation.org/issues/9099
