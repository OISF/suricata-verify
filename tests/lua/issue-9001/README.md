Test that the hashlib garbage collector can't be called from a rule script,
and that a finalized hasher can't be used again.

Both lead to a use after free of the hash context.

https://redmine.openinfosecfoundation.org/issues/9001
