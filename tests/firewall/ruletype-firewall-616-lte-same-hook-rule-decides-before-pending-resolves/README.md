A listed rule of a higher id at a pending LTE rule's own hook

`sid 110` uses the auto-accept notation at `request_headers` and its pattern never
arrives, so the rule is pending at its own hook for the update that first inspects
the transaction. `sid 120` is hooked at that same state, has a higher id, and does
match.

The candidate list is walked in id order, so 110 is reached first. Reaching it does
not end the walk: 110 cannot be decided by this update - its buffer can still grow -
and 120 can. So 120's `drop:flow` decides the flow, and 110's accept never gets to
resolve. That is the price the design accepts for not stalling a hook on a rule that
might never resolve; `firewall-design.rst` states it next to the higher-hook case.

Main (215961d67) reaches the same outcome for the same fixture, so this is a guard on
preserved behaviour rather than a red/green pair for a fix: it goes red if the walk is
changed to end at a pending rule of its own hook.

Walk order and file position
----------------------------

`iid` decides the order, and `iid` follows the file: the first line is reached first. Measured with
two rules that both match, so whoever decides reveals the order - `http1:<request_headers`
`accept:flow,alert` sid 110 on `http.host`, and a plain `http1:request_headers` `drop:flow,alert`
sid 120 on the same buffer:

| rules file                 | alert                 | flow action |
|----------------------------|-----------------------|-------------|
| 110 line 1, 120 line 2     | 110 `allowed`         | accept      |
| 120 line 1, 110 line 2     | 120 `blocked`         | drop        |

That is worth writing down because the loading code reads the other way: `DetectFirewallRuleAppendNew()`
prepends (`src/detect-parse.c:3926`) and `SigGroupBuild()` numbers from the list head, which would put
the last line first. Here the pending rule is line 3 and the drop rule line 4, so the drop rule carries
the higher `iid` - the case the design paragraph describes. If the load order ever changes, this
fixture should go red; line 1 and line 2 swapped is the way to check.
