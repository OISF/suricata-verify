# Description

Ensure that Suricata logs the expected amount of applayer protocol events,
when there are packet and flow drops.

# Expected behavior

Application layer events for dropped packets or flows should be logged as part
of the drop event, when their corresponding transaction is completed (which also
happens when the flow is dropped). Therefore, we should not see ``sip`` events
after ``pcap_cnt: 4``, since there's a drop in ``pcap_cnt: 5`` and the flow is
dropped with packets 6 and 7 due to the applayer error exception policy.

# Redmine ticket

https://redmine.openinfosecfoundation.org/issues/5802
