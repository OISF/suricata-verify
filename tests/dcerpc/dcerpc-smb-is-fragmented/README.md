Tests the dcerpc.is_fragmented keyword on DCE/RPC carried over SMB, per
direction, with genuine multi-PDU fragmentation.

Reuses the filestore-filecontainer-smb capture, a busy SMB2 session doing many
registry/service (WINREG/SVCCTL) operations. Three of its DCE/RPC responses are
fragmented at the DCE/RPC layer across multiple PDUs over SMB:

  - call_id 14:  first + last              (2 fragments, WINREG response)
  - call_id 3:   first + middle + last     (3 fragments, SVCCTL response)
  - call_id 573: first + middle + last     (3 fragments, SVCCTL response)

Each reassembles into a single SMB DCE/RPC transaction whose response side is
fragmented (resp_is_fragmented = true, derived from the record's
first_frag/last_frag). All other DCE/RPC PDUs are single complete PDUs (both
PFC_FIRST_FRAG and PFC_LAST_FRAG set) and thus not fragmented.

The rules confirm:

  - is_fragmented:true on to_client matches exactly the three fragmented
    responses (via smb_tx_match_dce_is_fragmented);
  - is_fragmented:true on to_server matches nothing (no request is fragmented);
  - is_fragmented:false matches every complete request (to_server) and every
    complete response (to_client).

This exercises both the fragmented and not-fragmented cases, in both directions,
using real multi-PDU fragmented DCE/RPC-over-SMB traffic.
