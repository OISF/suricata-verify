To test that SCFlowvarGet (lua) doesn't always return nil.

The original issue emerged due to a lua detection script that used a single rule to set up
a flow variable and match on it. 

The problem is that during detection, the steps happen in this order:
- pattern matching
- lua script execution
- setting flow variables as part of post match

So, a workaround is to have 2 rules:
- one that does the pattern matching and setting the flow var
- another second one that does the Lua script

This test works based on that.

Pcap provided by Chris Knott at https://redmine.openinfosecfoundation.org/issues/2094
