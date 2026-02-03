A FETCH whose untagged responses exceed the 1 MiB of lines retained per flow
raises `imap.data_limit_reached` once and loses the lines past the limit. The
tagged reply completing it is kept outside of that budget, as is the command
line of every transaction: the status of the FETCH is still logged, and a
command sent while the budget is used up is still inspected and logged.
