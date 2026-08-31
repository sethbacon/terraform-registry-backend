-- 000060_notify_dedup_claims (down)
--
-- A clean drop: unlike 000058's actor_email (which discards otherwise
-- unrecoverable attribution), notify_dedup_claims holds nothing but
-- short-lived reservations already past their own TTL for practical
-- purposes -- see identity/store's dedupPruneGrace. Nothing here is lost by
-- rolling back to a version whose queries do not name the table.

DROP TABLE IF EXISTS notify_dedup_claims;
