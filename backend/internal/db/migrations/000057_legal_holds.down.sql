-- 000057_legal_holds (down)
--
-- Dropping this table does not merely remove a feature: it removes the record
-- of which audit entries an investigation asked to be preserved, and the next
-- retention sweep then deletes them. The rollback is therefore destructive in a
-- way the up migration is not, and the operator running it at 3am should know
-- that before it runs rather than after.
--
-- It is still a real DROP rather than a no-op, because a table left behind
-- would be read by a sweep on the version being rolled back TO, which has no
-- code that maintains it — holds would be frozen at whatever they said when the
-- rollback happened, protecting rows nobody can release.
--
-- Take a backup of legal_holds first if any hold is active:
--   COPY (SELECT * FROM legal_holds WHERE active) TO '/tmp/legal_holds.csv' CSV HEADER;

DROP TABLE IF EXISTS "legal_holds";
