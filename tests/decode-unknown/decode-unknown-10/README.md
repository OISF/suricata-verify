Check the case reported in Redmine 8142 with the pcap attached there: three
RARP frames (ethertype 0x8035) on VLAN 2015. Before this change the alert for
``decoder.ethernet.unknown_ethertype`` showed only ``ether.ether_type``, the
VLAN tag ethertype (0x8100), so the ethertype that raised the event was not
in the log.

Each alert and each ``decoder.ethernet.unknown_ethertype`` and
``decoder.vlan.unknown_type`` anomaly record must now carry
``unknown_ether_type`` 32821 (0x8035), while ``ether.ether_type`` stays
33024 (0x8100).

https://redmine.openinfosecfoundation.org/issues/8142
https://redmine.openinfosecfoundation.org/issues/7849
