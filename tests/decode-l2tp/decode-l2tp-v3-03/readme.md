# L2TPv3 over UDP tunnel with a 8 byte cookie (no sublayer)

## Example Setup (Linux):
```
# setup right hand side
sudo ip l2tp add tunnel \
   tunnel_id 1 peer_tunnel_id 1  encap udp  \
   local 172.31.6.72 remote 172.31.1.211  \
   udp_sport 1701 udp_dport 1701

sudo ip l2tp add session name svtest \
    tunnel_id 1 session_id 1 peer_session_id 1 \
    cookie deadbeefcafebabe peer_cookie deadbeefcafebabe l2spec_type none

sudo ip link set svtest up

sudo ip addr add 10.10.10.2/24 dev svtest

# setup left hand side
sudo ip l2tp add tunnel \
   tunnel_id 1 peer_tunnel_id 1  encap udp  \
   local 172.31.1.211 remote 172.31.6.72 \
   udp_sport 1701 udp_dport 1701

sudo ip l2tp add session name svtest \
    tunnel_id 1 session_id 1 peer_session_id 1 \
    cookie deadbeefcafebabe peer_cookie deadbeefcafebabe l2spec_type none

sudo ip link set svtest up

sudo ip addr add 10.10.10.1/24 dev svtest

# generate traffic, replay a dns pcap
ping -c 2 10.10.10.2; sudo tcpreplay -i svtest 20250129-dns-with-additionals.pcap; ping -c 2 10.10.10.2
```