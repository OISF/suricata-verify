Test Description
================

Datasets use a static DJB2 hash function to hash all types of datasets. These hashed
datasets are stored in the THash API which has no randomization in place. As
a result of this, the hash table can be exploited with a worst case time scenario of
O(n) where n is the total number of entries in the table as a result of excessive chaining
in a single row.

The test shows that it takes excess time for the THash API to load the datasets from the file
as many of them evaluate the exact same hash using the algorithm so this is not even the worst
case scenario. With bigger dataset and lesser system specs/availability of resources,
this can be worse. Note that it is not just about the number of datasets as there already
does exist a test already that loads 1m+ datasets.

Test data procured from: https://bugs.php.net/bug.php?id=70644

Redmine Ticket
==============

https://redmine.openinfosecfoundation.org/issues/7209
