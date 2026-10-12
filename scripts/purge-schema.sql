-- Purge one stale personal schema. README "Stale personal schemas" has the procedure:
--   pg psql -X -d hindsight -v schema=<ID typed from /ext/admin> -v operator=<your email> < purge-schema.sql
-- It refuses any schema the admin page does not list as stale, so never a Team schema or public.
\set ON_ERROR_STOP on
\if :{?wait}
\else
\set wait 60
\endif

-- Step 1: take the schema off the tenant list and revoke every key that names it. Locking the
-- owner's row, as key creation does, means the staleness check sees a key created meanwhile.
BEGIN;
SELECT email AS owner FROM agent_keys.people WHERE schema = :'schema' AND :'operator' <> '' FOR UPDATE \gset
SELECT schema AS stale FROM agent_keys.stale_schemas WHERE schema = :'schema' \gset
UPDATE agent_keys.people SET schema = NULL WHERE schema = :'schema';
UPDATE agent_keys.keys SET revoked_at = now() WHERE schema = :'schema' AND revoked_at IS NULL;
COMMIT;
\echo Unlisted :schema (owner :owner); its keys are revoked.

-- The worker re-reads the tenant list every half second; let tasks it had already claimed there finish.
SELECT pg_sleep(:wait);

-- Step 2: drop the schema and log the purge. Revoking again catches a key created in the instant before step 1.
BEGIN;
UPDATE agent_keys.keys SET revoked_at = now() WHERE schema = :'schema' AND revoked_at IS NULL;
DROP SCHEMA :"schema" CASCADE;
INSERT INTO agent_keys.events (kind, key_id, email, actor, team)
VALUES ('schema_purged', '(none)', :'owner', :'operator', :'schema');
COMMIT;
\echo Purged :schema.
