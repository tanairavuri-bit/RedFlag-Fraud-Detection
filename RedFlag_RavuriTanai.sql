-- =====================================================================
-- RedFlag — Fraud Detection Submission
-- Student: Ravuri Tanai | Batch: DA-DS-1
-- =====================================================================
USE redflag;

-- =====================================================================
-- PATTERN 1 · VELOCITY FRAUD
-- What I'm looking for: users with 30 or more transactions on a single
-- calendar day. Normal users make 3-8 a day; 30+ suggests a bot or an
-- account takeover.
-- Expected suspects: ~45-55 user-days
-- =====================================================================
SELECT
    user_id,
    DATE(txn_time) AS attack_date,
    COUNT(*)       AS daily_txn_count
FROM transactions
GROUP BY user_id, DATE(txn_time)
HAVING COUNT(*) >= 30
ORDER BY daily_txn_count DESC;
-- My findings: <FILL: number of rows returned> suspect user-days flagged.
-- Top examples: <FILL: user_id, count, date from your top 3 rows>.


-- =====================================================================
-- PATTERN 2 · ROUND-AMOUNT CLUSTERING
-- What I'm looking for: users with 15+ transactions of exactly a round
-- amount (100, 200, 500, 1000, 2000, 5000, 10000), a typical
-- money-laundering signature.
-- Expected suspects: 25
-- =====================================================================
SELECT
    user_id,
    COUNT(*)    AS round_txn_count,
    SUM(amount) AS total_round_amount
FROM transactions
WHERE amount IN (100, 200, 500, 1000, 2000, 5000, 10000)
GROUP BY user_id
HAVING COUNT(*) >= 15
ORDER BY round_txn_count DESC;
-- My findings: <FILL: row count> suspects flagged.
-- Top examples: <FILL: user_id and count>.


-- =====================================================================
-- PATTERN 3 · CARD TESTING
-- What I'm looking for: users with 30+ tiny transactions (under Rs 10)
-- in a single day, used to test whether stolen cards are still active.
-- Expected suspects: 20
-- =====================================================================
SELECT
    user_id,
    DATE(txn_time) AS attack_date,
    COUNT(*)       AS tiny_txn_count
FROM transactions
WHERE amount < 10
GROUP BY user_id, DATE(txn_time)
HAVING COUNT(*) >= 30
ORDER BY tiny_txn_count DESC;
-- My findings: <FILL: row count> suspect user-days flagged.
-- Top examples: <FILL: user_id, count, date>.


-- =====================================================================
-- PATTERN 4 · FAILED-THEN-SUCCEEDED (simplified version)
-- What I'm looking for: users with 20+ FAILED transactions. Real users
-- rarely have more than 2-3 failures a year; 20+ means retry scripts.
-- Expected suspects: 25
-- =====================================================================
SELECT
    user_id,
    COUNT(*) AS failed_txn_count
FROM transactions
WHERE status = 'FAILED'
GROUP BY user_id
HAVING COUNT(*) >= 20
ORDER BY failed_txn_count DESC;
-- My findings: <FILL: row count> suspects flagged.
-- Top examples: <FILL: user_id and count>.


-- =====================================================================
-- PATTERN 5 · ODD-HOUR CONCENTRATION
-- What I'm looking for: users with at least 30 transactions where 80%+
-- happen between 2 AM and 5 AM (hours 2, 3, 4), a bot signature.
-- Expected suspects: 20
-- =====================================================================
SELECT
    user_id,
    COUNT(*) AS total_txns,
    SUM(CASE WHEN HOUR(txn_time) BETWEEN 2 AND 4 THEN 1 ELSE 0 END) AS odd_hour_txns,
    ROUND(SUM(CASE WHEN HOUR(txn_time) BETWEEN 2 AND 4 THEN 1 ELSE 0 END) / COUNT(*), 2) AS odd_hour_ratio
FROM transactions
GROUP BY user_id
HAVING COUNT(*) >= 30
   AND SUM(CASE WHEN HOUR(txn_time) BETWEEN 2 AND 4 THEN 1 ELSE 0 END) / COUNT(*) >= 0.8
ORDER BY odd_hour_ratio DESC, total_txns DESC;
-- My findings: <FILL: row count> suspects flagged.
-- Top examples: <FILL: user_id, total_txns, ratio>.


-- =====================================================================
-- PATTERN 6 · MULE ACCOUNTS (advanced version)
-- What I'm looking for: users with 5+ instances where a CREDIT is
-- followed within 30 minutes by a DEBIT of at least 70% of the credit
-- amount (money comes in and goes straight out).
-- Expected suspects: 30
-- =====================================================================
SELECT
    c.user_id,
    COUNT(*) AS fast_in_out_events
FROM transactions c
WHERE c.txn_type = 'CREDIT'
  AND EXISTS (
        SELECT 1
        FROM transactions d
        WHERE d.user_id  = c.user_id
          AND d.txn_type = 'DEBIT'
          AND d.txn_time >  c.txn_time
          AND d.txn_time <= c.txn_time + INTERVAL 30 MINUTE
          AND d.amount   >= 0.7 * c.amount
  )
GROUP BY c.user_id
HAVING COUNT(*) >= 5
ORDER BY fast_in_out_events DESC;
-- My findings: <FILL: row count> suspects flagged.
-- Top examples: <FILL: user_id and event count>.
-- (Simplified Week 3 fallback: SELECT user_id, COUNT(*) FROM transactions
--  WHERE txn_type='CREDIT' GROUP BY user_id HAVING COUNT(*) >= 8;)


-- =====================================================================
-- PATTERN 7 · REFUND ABUSE
-- What I'm looking for: users with 20+ transactions where more than 40%
-- are REFUNDs. Real users stay below 5%.
-- Expected suspects: 24-25
-- =====================================================================
SELECT
    user_id,
    COUNT(*) AS total_txns,
    SUM(CASE WHEN txn_type = 'REFUND' THEN 1 ELSE 0 END) AS refund_txns,
    ROUND(SUM(CASE WHEN txn_type = 'REFUND' THEN 1 ELSE 0 END) / COUNT(*), 2) AS refund_ratio
FROM transactions
GROUP BY user_id
HAVING COUNT(*) >= 20
   AND SUM(CASE WHEN txn_type = 'REFUND' THEN 1 ELSE 0 END) / COUNT(*) > 0.40
ORDER BY refund_ratio DESC;
-- My findings: <FILL: row count> suspects flagged.
-- Top examples: <FILL: user_id, ratio>.


-- =====================================================================
-- PATTERN 8 · MERCHANT COLLUSION
-- What I'm looking for: merchants where the top 5 users by volume make up
-- more than 60% of the merchant's total transaction value. Healthy
-- merchants have a long tail of customers.
-- Expected suspects: 15 merchants
-- =====================================================================
WITH user_volume AS (
    SELECT
        merchant_id,
        user_id,
        SUM(amount) AS user_amount
    FROM transactions
    GROUP BY merchant_id, user_id
),
ranked AS (
    SELECT
        merchant_id,
        user_id,
        user_amount,
        ROW_NUMBER() OVER (PARTITION BY merchant_id ORDER BY user_amount DESC) AS rnk
    FROM user_volume
),
merchant_totals AS (
    SELECT
        merchant_id,
        SUM(CASE WHEN rnk <= 5 THEN user_amount ELSE 0 END) AS top5_amount,
        SUM(user_amount) AS total_amount
    FROM ranked
    GROUP BY merchant_id
)
SELECT
    merchant_id,
    top5_amount,
    total_amount,
    ROUND(top5_amount / total_amount * 100, 1) AS top5_share_pct
FROM merchant_totals
WHERE top5_amount / total_amount > 0.60
ORDER BY top5_share_pct DESC;
-- My findings: <FILL: row count> colluding merchants flagged.
-- Top examples: <FILL: merchant_id and share %>.


-- =====================================================================
-- PATTERN 9 · JUST-UNDER-THRESHOLD (STRUCTURING)
-- What I'm looking for: users with 10+ transactions of exactly Rs 9,999,
-- staying just below the Rs 10,000 enhanced-KYC limit.
-- Expected suspects: 20
-- =====================================================================
SELECT
    user_id,
    COUNT(*) AS structuring_txn_count
FROM transactions
WHERE amount = 9999.00
GROUP BY user_id
HAVING COUNT(*) >= 10
ORDER BY structuring_txn_count DESC;
-- My findings: <FILL: row count> suspects flagged.
-- Top examples: <FILL: user_id and count>.


-- =====================================================================
-- PATTERN 10 · DORMANT-THEN-ACTIVE
-- What I'm looking for: accounts with a gap of 90+ days between two
-- consecutive transactions, followed by 15+ transactions after the gap
-- (possible account takeover of a dormant account).
-- Expected suspects: 25-27
-- =====================================================================
WITH gaps AS (
    SELECT
        user_id,
        txn_time,
        TIMESTAMPDIFF(DAY,
            LAG(txn_time) OVER (PARTITION BY user_id ORDER BY txn_time),
            txn_time) AS gap_days
    FROM transactions
),
returns AS (
    SELECT user_id, txn_time AS return_time, gap_days
    FROM gaps
    WHERE gap_days >= 90
)
SELECT
    r.user_id,
    r.return_time,
    r.gap_days,
    COUNT(*) AS post_gap_txns
FROM returns r
JOIN transactions t
  ON t.user_id = r.user_id
 AND t.txn_time >= r.return_time
GROUP BY r.user_id, r.return_time, r.gap_days
HAVING COUNT(*) >= 15
ORDER BY post_gap_txns DESC;
-- My findings: <FILL: row count> suspects flagged.
-- Top examples: <FILL: user_id, gap_days, post_gap_txns>.


-- =====================================================================
-- PATTERN 11 · VELOCITY SPIKE
-- What I'm looking for: users whose peak monthly transaction count is at
-- least 5x their average monthly count, and the peak is 20+ transactions.
-- Expected suspects: 35-45
-- =====================================================================
WITH monthly AS (
    SELECT
        user_id,
        DATE_FORMAT(txn_time, '%Y-%m') AS txn_month,
        COUNT(*) AS txn_count
    FROM transactions
    GROUP BY user_id, DATE_FORMAT(txn_time, '%Y-%m')
),
stats AS (
    SELECT
        user_id,
        MAX(txn_count) AS peak_monthly,
        AVG(txn_count) AS avg_monthly
    FROM monthly
    GROUP BY user_id
)
SELECT
    user_id,
    peak_monthly,
    ROUND(avg_monthly, 2) AS avg_monthly,
    ROUND(peak_monthly / avg_monthly, 2) AS spike_ratio
FROM stats
WHERE peak_monthly >= 20
  AND peak_monthly / avg_monthly >= 5
ORDER BY spike_ratio DESC;
-- My findings: <FILL: row count> suspects flagged.
-- Top examples: <FILL: user_id, peak, ratio>.


-- =====================================================================
-- PATTERN 12 · GEOGRAPHIC IMPOSSIBILITY
-- What I'm looking for: consecutive transactions by the same user in two
-- different cities within 60 minutes, which is physically impossible and
-- points to account takeover or stolen-card use.
-- Expected suspects: 15
-- =====================================================================
WITH ordered_txns AS (
    SELECT
        user_id,
        txn_time,
        city,
        LAG(city)     OVER (PARTITION BY user_id ORDER BY txn_time) AS prev_city,
        LAG(txn_time) OVER (PARTITION BY user_id ORDER BY txn_time) AS prev_time
    FROM transactions
)
SELECT
    user_id,
    COUNT(*)      AS impossible_jumps,
    MIN(txn_time) AS first_seen
FROM ordered_txns
WHERE prev_city IS NOT NULL
  AND city <> prev_city
  AND TIMESTAMPDIFF(MINUTE, prev_time, txn_time) <= 60
GROUP BY user_id
ORDER BY impossible_jumps DESC;
-- My findings: <FILL: row count> suspects flagged.
-- Top examples: <FILL: user_id, jumps, first_seen>.
