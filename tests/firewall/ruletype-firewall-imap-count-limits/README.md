With `max-responses` set to 512, verify that 512 untagged responses plus the
tagged reply fit in one IMAP transaction without an event, and that the 513th
parsed email is not retained, raises the sticky `too_many_responses` event,
and does not prevent the tagged response from being kept or a following
transaction from completing.
