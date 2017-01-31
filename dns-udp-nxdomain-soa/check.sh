#! /bin/sh

expected='{"timestamp":"2017-01-27T16:03:18.623093+0000","flow_id":1899131178484213,"pcap_cnt":1,"event_type":"dns","src_ip":"10.16.1.11","src_port":59465,"dest_ip":"8.8.4.4","dest_port":53,"proto":"UDP","dns":{"type":"query","id":33429,"rrname":"dne.oisf.net","rrtype":"A","tx_id":0}}
{"timestamp":"2017-01-27T16:03:18.709160+0000","flow_id":1899131178484213,"pcap_cnt":2,"event_type":"dns","src_ip":"8.8.4.4","src_port":53,"dest_ip":"10.16.1.11","dest_port":59465,"proto":"UDP","dns":{"type":"answer","id":33429,"rcode":"NXDOMAIN","rrname":"dne.oisf.net"}}
{"timestamp":"2017-01-27T16:03:18.709160+0000","flow_id":1899131178484213,"pcap_cnt":2,"event_type":"dns","src_ip":"8.8.4.4","src_port":53,"dest_ip":"10.16.1.11","dest_port":59465,"proto":"UDP","dns":{"type":"answer","id":33429,"rcode":"NXDOMAIN","rrname":"oisf.net","rrtype":"SOA","ttl":899}}'

actual=$(cat output/eve.json | jq -c 'select(.event_type == "dns")')

if [ "${actual}" != "${expected}" ]; then
    exit 1
fi

exit 0
