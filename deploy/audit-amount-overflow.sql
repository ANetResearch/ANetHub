-- audit-amount-overflow.sql — read-only check of a hub database for traces
-- of the x402 amount-overflow bug (fixed on main by the commits on
-- hotfix/settle-amount-overflow, and on the v0.2 line by the amount range
-- check in internal/aghub/amount.go; see the commit messages).
--
-- The bug: an authorization or receipt amount is a uint64 on the wire and
-- was converted to the int64 ledger with a bare int64(...). An amount of
-- 2^63 or more became negative and was booked backwards: the payer's row
-- went UP, the payee's went DOWN, redemptions minted credit, a peer's
-- receipt debited the local payee. At exactly 2^63 SQLite's integer
-- arithmetic overflowed into REAL. Zero amounts were accepted too.
--
-- What a hit looks like here:
--   * a settlement / redemption / clearing row whose amount is <= 0, or
--     is stored as REAL (typeof(amount) <> 'integer'), or is above
--     9223372036854775807;
--   * a balance stored as REAL, or a negative balance on any row other
--     than the hub's own (the hub's balance row moves opposite to its
--     users' — a redemption credits it, clearing a peer's receipt debits
--     it — so it can legitimately be negative);
--   * a ledger entry of 0 or stored as REAL;
--   * an issuance-chain record (credit_issuance) with an amount <= 0 or
--     stored as REAL.
--
-- READ ONLY. Every statement is a SELECT, and the PRAGMA below makes this
-- connection refuse writes even if one were added by mistake. Run it on a
-- copy, not on the live file:
--
--   sqlite3 /data/projs/anet-hub/data/hub.db ".backup /tmp/hub-audit.db"
--   sqlite3 -readonly /tmp/hub-audit.db < deploy/audit-amount-overflow.sql > /tmp/hub-audit.txt
--
-- (.backup reads the live database through SQLite's own locking, so it is
-- safe while anet-hub is running; it writes only the copy.)
--
-- Every section prints a heading row and then its findings; a section with
-- no findings prints only its heading. Section 0 is informational. On a
-- clean hub, sections 1–9 are empty.
--
-- Times: the credit_* tables and hub_cleared store RFC 3339 text in `at`;
-- credit_issuance stores unix milliseconds, shown here converted to UTC.

PRAGMA query_only = 1;
.headers on
.mode list
.separator " | "

-- ---------------------------------------------------------------------
SELECT '== 0. the hub''s own row(s): may be negative legitimately, excluded from the negative-balance check ==' AS section;
-- The hub's AID is the account every grant is issued from (credit_entry
-- reason 'issued:…') and the subject of the chain's opening record.
WITH hub(aid) AS (
  SELECT aid FROM credit_entry WHERE reason LIKE 'issued:%'
  UNION SELECT aid FROM credit_issuance WHERE kind = 'anet.credit.opening'
)
SELECT h.aid AS hub_aid, b.credits AS hub_row_credits, typeof(b.credits) AS stored_as
FROM hub h LEFT JOIN credit_balance b ON b.aid = h.aid;

-- ---------------------------------------------------------------------
SELECT '== 1. credit_settled: settlements with an amount outside 1..9223372036854775807 ==' AS section;
SELECT auth_id, payer, pay_to, amount, typeof(amount) AS stored_as, interaction_id, at
FROM credit_settled
WHERE typeof(amount) <> 'integer' OR amount <= 0 OR amount > 9223372036854775807
ORDER BY at;

SELECT '== 1b. ledger entries written by those settlements (who actually gained / lost) ==' AS section;
SELECT e.reason AS auth_id, e.aid, e.delta, typeof(e.delta) AS stored_as, e.at
FROM credit_entry e
JOIN credit_settled s ON s.auth_id = e.reason
WHERE typeof(s.amount) <> 'integer' OR s.amount <= 0 OR s.amount > 9223372036854775807
ORDER BY e.at, e.aid;

-- ---------------------------------------------------------------------
SELECT '== 2. credit_redemption: redemptions with an amount outside 1..9223372036854775807 ==' AS section;
SELECT auth_id, aid, amount, typeof(amount) AS stored_as, reference, at
FROM credit_redemption
WHERE typeof(amount) <> 'integer' OR amount <= 0 OR amount > 9223372036854775807
ORDER BY at;

-- ---------------------------------------------------------------------
SELECT '== 3. credit_cleared: peer receipts cleared here with an amount outside 1..9223372036854775807 ==' AS section;
SELECT auth_id, peer_aid, pay_to, amount, typeof(amount) AS stored_as, at
FROM credit_cleared
WHERE typeof(amount) <> 'integer' OR amount <= 0 OR amount > 9223372036854775807
ORDER BY at;

-- ---------------------------------------------------------------------
SELECT '== 4. hub_cleared: peer discharges applied here with an amount outside 1..9223372036854775807 ==' AS section;
SELECT auth_id, peer_aid, amount, typeof(amount) AS stored_as, at
FROM hub_cleared
WHERE typeof(amount) <> 'integer' OR amount <= 0 OR amount > 9223372036854775807
ORDER BY at;

-- ---------------------------------------------------------------------
SELECT '== 5. hub_owed / hub_due: inter-hub positions that are negative or not integers ==' AS section;
-- Zero is legitimate (a debt fully discharged); below zero is not.
SELECT 'hub_owed' AS tbl, peer_aid AS counterparty, amount, typeof(amount) AS stored_as
FROM hub_owed
WHERE typeof(amount) <> 'integer' OR amount < 0 OR amount > 9223372036854775807
UNION ALL
SELECT 'hub_due', payee_aid, amount, typeof(amount)
FROM hub_due
WHERE typeof(amount) <> 'integer' OR amount < 0 OR amount > 9223372036854775807;

-- ---------------------------------------------------------------------
SELECT '== 6. credit_balance: balances stored as REAL, or negative on an account other than the hub''s ==' AS section;
WITH hub(aid) AS (
  SELECT aid FROM credit_entry WHERE reason LIKE 'issued:%'
  UNION SELECT aid FROM credit_issuance WHERE kind = 'anet.credit.opening'
)
SELECT b.aid, b.credits, typeof(b.credits) AS stored_as,
       (SELECT MIN(at) FROM credit_entry e WHERE e.aid = b.aid) AS first_entry_at,
       (SELECT MAX(at) FROM credit_entry e WHERE e.aid = b.aid) AS last_entry_at
FROM credit_balance b
WHERE typeof(b.credits) <> 'integer'
   OR (b.credits < 0 AND b.aid NOT IN (SELECT aid FROM hub))
ORDER BY b.aid;

-- ---------------------------------------------------------------------
SELECT '== 7. credit_entry: ledger entries of 0 or stored as REAL ==' AS section;
SELECT aid, delta, typeof(delta) AS stored_as, reason, at
FROM credit_entry
WHERE typeof(delta) <> 'integer' OR delta = 0
ORDER BY at;

-- ---------------------------------------------------------------------
SELECT '== 8. credit_issuance (the signed issuance chain): records with an amount <= 0 or stored as REAL ==' AS section;
-- The chain records are signed and are not to be edited; a hit here is a
-- statement the hub already made and must be answered with a new record,
-- not by changing this one.
SELECT seq, kind, aid, amount, typeof(amount) AS stored_as, reason,
       datetime(at / 1000, 'unixepoch') AS at_utc
FROM credit_issuance
WHERE typeof(amount) <> 'integer' OR amount <= 0 OR amount > 9223372036854775807
ORDER BY seq;

-- ---------------------------------------------------------------------
SELECT '== 9. affected AIDs, all sources above, with first and last time seen ==' AS section;
WITH hits(aid, role, source, at) AS (
  SELECT payer, 'payer', 'credit_settled', at FROM credit_settled
   WHERE typeof(amount) <> 'integer' OR amount <= 0 OR amount > 9223372036854775807
  UNION ALL
  SELECT pay_to, 'payee', 'credit_settled', at FROM credit_settled
   WHERE typeof(amount) <> 'integer' OR amount <= 0 OR amount > 9223372036854775807
  UNION ALL
  SELECT aid, 'redeemer', 'credit_redemption', at FROM credit_redemption
   WHERE typeof(amount) <> 'integer' OR amount <= 0 OR amount > 9223372036854775807
  UNION ALL
  SELECT pay_to, 'payee', 'credit_cleared', at FROM credit_cleared
   WHERE typeof(amount) <> 'integer' OR amount <= 0 OR amount > 9223372036854775807
  UNION ALL
  SELECT peer_aid, 'peer hub', 'credit_cleared', at FROM credit_cleared
   WHERE typeof(amount) <> 'integer' OR amount <= 0 OR amount > 9223372036854775807
  UNION ALL
  SELECT peer_aid, 'peer hub', 'hub_cleared', at FROM hub_cleared
   WHERE typeof(amount) <> 'integer' OR amount <= 0 OR amount > 9223372036854775807
  UNION ALL
  SELECT aid, 'account', 'credit_entry', at FROM credit_entry
   WHERE typeof(delta) <> 'integer' OR delta = 0
  UNION ALL
  SELECT aid, 'chain subject', 'credit_issuance',
         strftime('%Y-%m-%dT%H:%M:%SZ', at / 1000, 'unixepoch') FROM credit_issuance
   WHERE typeof(amount) <> 'integer' OR amount <= 0 OR amount > 9223372036854775807
)
SELECT aid, role, source, COUNT(*) AS rows, MIN(at) AS first_at, MAX(at) AS last_at
FROM hits
GROUP BY aid, role, source
ORDER BY first_at;

-- ---------------------------------------------------------------------
SELECT '== 10. supply totals (informational): outstanding must equal balances ==' AS section;
-- The same arithmetic /x402/supply publishes. The overflow bug keeps the
-- two sides equal (both were written with the same wrong sign), so a match
-- here does NOT clear the hub; a mismatch, or a REAL total, is a finding.
WITH hub(aid) AS (
  SELECT aid FROM credit_entry WHERE reason LIKE 'issued:%'
  UNION SELECT aid FROM credit_issuance WHERE kind = 'anet.credit.opening'
)
SELECT
  (SELECT -COALESCE(SUM(delta), 0) FROM credit_entry WHERE aid IN (SELECT aid FROM hub) AND delta < 0) AS issued,
  (SELECT COALESCE(SUM(delta), 0) FROM credit_entry WHERE aid IN (SELECT aid FROM hub) AND delta > 0) AS redeemed,
  (SELECT -COALESCE(SUM(delta), 0) FROM credit_entry WHERE aid IN (SELECT aid FROM hub)) AS outstanding,
  (SELECT COALESCE(SUM(credits), 0) FROM credit_balance WHERE aid NOT IN (SELECT aid FROM hub)) AS balances,
  (SELECT typeof(COALESCE(SUM(credits), 0)) FROM credit_balance) AS balances_stored_as;

-- ---------------------------------------------------------------------
SELECT '== 11. self-payments (informational): settlements whose payer is also the payee ==' AS section;
-- Not this bug. Before the gateway compared the signed authorization with
-- the price (R06 D2 on the v0.2 line; the same fix on main's hotfix
-- branch), the gateway issued a full-price voucher for any signed
-- authorization, and "pay 1 credit to myself" was the cheapest one to sign. Vouchers are not stored
-- on the hub, so this is the only trace such a purchase can leave here,
-- and a self-payment is not proof of one.
SELECT auth_id, payer, amount, interaction_id, at
FROM credit_settled
WHERE payer = pay_to
ORDER BY at;
