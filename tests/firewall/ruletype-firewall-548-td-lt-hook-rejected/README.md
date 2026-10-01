# Description

The `<` lower bound hook form (`tls:<client_hello`) is a firewall policy
construct: it makes the rule cover its own hook and every prior one. For a
threat detection rule the form has no meaning and used to leak into the
firewall policy walk, so it is now rejected at load.

This test pins the rejection: a `test.rules`/`td.rules` entry using `<` fails
to load while the valid firewall rules next to it load normally.

# Rules

`firewall.rules` holds a valid firewall rule; `td.rules` holds the threat
detection rule with the `<` hook, which must fail with

    hook '<client_hello': the lower bound form '<' is only allowed for firewall rules
