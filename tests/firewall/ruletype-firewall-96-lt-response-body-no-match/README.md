This PCAP has the classic response body of:

  uid=0(root) gid=0(root) groups=0(root)

Our rules firewall.rules should only allow responses bodies that contain
"suricata", however, this tests shows that nothing is being dropped.
