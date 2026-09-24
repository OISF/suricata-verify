Tests combining multiple `windows_pe` options in a single keyword instance.
Uses five PEs with varying SizeOfImage values (512, 1024, 512, 4096, 2048)
to exercise combinations of `arch`, `sections`, `entry_point`, `subsystem`,
and `size` in the same rule.
