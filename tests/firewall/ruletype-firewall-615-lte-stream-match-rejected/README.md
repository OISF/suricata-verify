# LTE rules cannot match the raw stream

`<hook` retires a group once its rules are definitively done, which is only sound
when every match of the rule comes from a buffer of that hook. A `content`/`pcre`
left on the stream can arrive with a later segment above any hook, so such a rule
is refused at load:

    the auto-accept notation ('<hook') cannot match the raw stream

sid 10 shows the accepted form (host buffer), sid 11 the rejected one. Rule 11 is
otherwise identical, so the failure is the stream match alone.
