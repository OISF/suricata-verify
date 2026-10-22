# A filestore match must not open the trailer block's completeness gate

A chunked response puts its body in one segment and the trailer block in the three that
follow, each acknowledged by the peer. sid 1 stores the body; storing a transaction marks it in
that direction, and that mark is not the same fact as the reassembly depth limit being reached.

Read as completion it would open the gate while the trailer block is still arriving, and sid 2 -
which can only match the partial block - would fire early. It must stay at 0; sid 3 shows the
complete block is inspected as usual.

Run `python3 make-pcap.py` to regenerate `input.pcap`.
