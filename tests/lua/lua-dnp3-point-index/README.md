Reproducer for ticket 9068: a DNP3 response carrying 65528 points. On
pre-fix code get_tx() eagerly materialized every point into Lua tables,
exhausting the lua sandbox memory budget: the call failed with a memory
limit error and the rule silently did not match. Fixed code keeps large
point sets behind a lazy object; the assertions cover the walk the
ticket's fix must keep correct: entry 1 is the first wire point (index
0), entry 2 the second (index 1), entry #points the highest wire index,
reads past the count stay nil, and a 1..#points walk yields every point
in wire order exactly once.
