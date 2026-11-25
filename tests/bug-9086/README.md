# Bug 9086: isdataat with a byte variable rewritten to endswith

https://redmine.openinfosecfoundation.org/issues/9086

`isdataat:!1,relative` after a content means the content ends the buffer, and
Suricata rewrites it that way. With a byte variable, `isdataat:!b,relative`, the
same field holds the variable's local id instead of a byte count, and the
rewrite used to fire whenever that id was 1, dropping the length check.

- `bug-9086-01`: One request for `/v/1/5/ENDxx`. Rule 1 reads `b` (local id 1,
  value 5) with two bytes left after "END" and has to alert. Rule 2 is the
  literal form and must not, since "END" does not end the URI. Before the fix
  rule 1 was rewritten like rule 2 and neither alerted.
