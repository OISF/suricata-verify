from scapy.all import *

def make_http_request(host, uri, headers, body):
    req = f"GET {uri} HTTP/1.1\r\nHost: {host}\r\n"
    for k, v in headers.items():
        req += f"{k}: {v}\r\n"
    req += "\r\n"
    req = req.encode() + body
    return req

def make_http_response(headers, body):
    resp = "HTTP/1.1 200 OK\r\n"
    for k, v in headers.items():
        resp += f"{k}: {v}\r\n"
    resp += "\r\n"
    resp = resp.encode() + body
    return resp

def make_tcp_stream(req, resp, sport=12345, dport=80):
    # SYN
    syn = IP(src="192.168.1.100", dst="192.168.1.1")/TCP(sport=sport, dport=dport, flags="S", seq=100)
    # SYN-ACK
    synack = IP(src="192.168.1.1", dst="192.168.1.100")/TCP(sport=dport, dport=sport, flags="SA", seq=200, ack=101)
    # ACK
    ack = IP(src="192.168.1.100", dst="192.168.1.1")/TCP(sport=sport, dport=dport, flags="A", seq=101, ack=201)
    # HTTP request
    req_pkt = IP(src="192.168.1.100", dst="192.168.1.1")/TCP(sport=sport, dport=dport, flags="PA", seq=101, ack=201)/Raw(load=req)
    # HTTP response
    resp_pkt = IP(src="192.168.1.1", dst="192.168.1.100")/TCP(sport=dport, dport=sport, flags="PA", seq=201, ack=101+len(req))/Raw(load=resp)
    # FIN
    fin = IP(src="192.168.1.100", dst="192.168.1.1")/TCP(sport=sport, dport=dport, flags="FA", seq=101+len(req), ack=201+len(resp))
    # FIN-ACK
    finack = IP(src="192.168.1.1", dst="192.168.1.100")/TCP(sport=dport, dport=sport, flags="FA", seq=201+len(resp), ack=102+len(req))
    # Final ACK
    lastack = IP(src="192.168.1.100", dst="192.168.1.1")/TCP(sport=sport, dport=dport, flags="A", seq=102+len(req), ack=202+len(resp))
    return [syn, synack, ack, req_pkt, resp_pkt, fin, finack, lastack]


# All edge cases use the same URI: /test

# Edge Case 1: Out-of-bounds local_id (huge Content-Length)
headers1 = {"Content-Length": str(2**21)}
body1 = b"test"
req1 = make_http_request("example.com", "/test", headers1, b"")
resp1 = make_http_response(headers1, body1)
print("[DEBUG] Edge Case 1 Headers:", headers1)
print("[DEBUG] Edge Case 1 Body:", body1)
pkts1 = make_tcp_stream(req1, resp1)

# Edge Case 2: Multiple extractions in both directions (response with both headers)
headers2 = {"Content-Length": "4", "X-Other-Length": "4"}
body2 = b"test"
req2 = make_http_request("example.com", "/test", {}, b"")
resp2 = make_http_response(headers2, body2)
print("[DEBUG] Edge Case 2 Headers:", headers2)
print("[DEBUG] Edge Case 2 Body:", body2)
pkts2 = make_tcp_stream(req2, resp2)

# Edge Case 3: No byte_extract used (normal request)
headers3 = {"Content-Length": "4"}
body3 = b"test"
req3 = make_http_request("example.com", "/test", headers3, b"")
resp3 = make_http_response(headers3, body3)
print("[DEBUG] Edge Case 3 Headers:", headers3)
print("[DEBUG] Edge Case 3 Body:", body3)
pkts3 = make_tcp_stream(req3, resp3)

# Edge Case 4: Many unique local_ids (simulate by many headers)
headers4 = {f"X-Len-{i}": "4" for i in range(10)}
headers4["Content-Length"] = "4"
body4 = b"test"
req4 = make_http_request("example.com", "/test", headers4, b"")
resp4 = make_http_response(headers4, body4)
print("[DEBUG] Edge Case 4 Headers:", headers4)
print("[DEBUG] Edge Case 4 Body:", body4)
pkts4 = make_tcp_stream(req4, resp4)


# Print raw HTTP response payloads for debugging
print("Edge Case 1 Response:")
print(repr(resp1))
print("Edge Case 2 Response:")
print(repr(resp2))
print("Edge Case 3 Response:")
print(repr(resp3))
print("Edge Case 4 Response:")
print(repr(resp4))

all_pkts = pkts1 + pkts2 + pkts3 + pkts4
wrpcap("test.pcap", all_pkts)
print("PCAP generated: test.pcap with HTTP request/response pairs for edge cases.")
