Tests pgsql output for a Frontend/Backend conversation in Simple Query
PostgreSQL subprotocol where the simple query is split into several
commands and where a rollback is issued by the backed.

This test is for Suricata 7 only.

SimpleQuery messages shown:

BEGIN;
DELETE FROM new_table WHERE NAME='Remus';
DELETE FROM new_table WHERE NAME='Londubat';
DELETE FROM new_table WHERE NAME='Hermione';
DELETE FROM new_table WHERE NAME='Maugre';
COMMIT;

BEGIN;
INSERT INTO new_table VALUES('Hermione', 'prof_gramger@gmail.com');
INSERT INTO new_table VALUES('Remus', 'prof_lupin@gmail.com');
SELECT 1/0;
INSERT INTO new_table VALUES('Maugre', 'prof_folloy@gmail.com');
INSERT INTO new_table VALUES('Londubat', 'prof_londubat@gmail.com');
SELECT * FROM new_table;
COMMIT;

pcap by Juliana Fajardini, with local dummy setup.
