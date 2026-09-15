Tests the dcerpc.is_fragmented keyword over DCE/RPC-over-TCP with a real
multi-PDU fragmented request.

The pcap (see dcerpc_fragmented_tcp_scapy.py) is a single TCP connection with
two client -> server calls:

  - call_id 1: one REQUEST fragmented across TWO PDUs, each in its own TCP
    segment: PFC_FIRST_FRAG (0x01) then PFC_LAST_FRAG (0x02). These reassemble
    into a single request transaction; per C706 it is fragmented because no
    single PDU sets both FIRST and LAST.
  - call_id 2: a single complete REQUEST PDU with both PFC_FIRST_FRAG and
    PFC_LAST_FRAG set (0x03) -> not fragmented.

dcerpc.is_fragmented:true matches the fragmented request (call_id 1, one
transaction) and dcerpc.is_fragmented:false matches the complete request
(call_id 2). This exercises genuine multi-PDU fragmentation and reassembly
rather than flipping flag bits on a single PDU. A DCE/RPC connection whose first
PDU is a request is detected as DCERPC to_server, so no bind is needed.
