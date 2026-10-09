A TD rule positioned after a pending LTE rule is inspected.

Rules:

- `sid 110`: `accept:flow,alert`, hooked at `http1:<request_headers>` (hook 2),
  matching `http.host` `www.example.com`
- `sid 113`: `accept:flow,alert`, hooked at `http1:<request_started>` (hook 0),
  matching a raw content that never appears
- `sid 120` (TD, `td.rules`): `alert`, hooked at `http1:request_headers`,
  matching the same `http.host` value

`sid 113` stays pending, so the walk used to stop before the hook 2 list and
neither the firewall accept (`sid 110`) nor the TD rule after it ran. A pending
LTE rule acts as an `accept:hook` for its own hook, and a full `accept:hook`
match still lets the TD rules behind it run, so the same must hold for the
pending rule: this pins that a TD rule after it is inspected, while the flow is
accepted by `sid 110` and no default policy (2201001) fires.
