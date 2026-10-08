-- Ad-hoc queries for the obs-agent ClickHouse tables (database obs).
-- Replace the INTERVALs and host filters as needed.

-- Top digests by CPU over the last 6 h, fleet-wide.
SELECT s.digest_id, any(t.digest_text) AS text, sum(s.calls) AS call_count,
       round(sum(s.cpu_ns) / 1e9, 1) AS cpu_s,
       round(sum(s.wall_ns) / greatest(sum(s.calls), 1) / 1e6, 2) AS wall_ms_avg
FROM obs.mysql_digest_stats AS s
LEFT JOIN (SELECT digest_id, digest_text FROM obs.mysql_digest_text FINAL) AS t USING digest_id
WHERE s.window_end > now() - INTERVAL 6 HOUR
GROUP BY s.digest_id ORDER BY cpu_s DESC LIMIT 50;

-- Same, per host.
SELECT host, digest_id, round(sum(cpu_ns) / 1e9, 1) AS cpu_s
FROM obs.mysql_digest_stats
WHERE window_end > now() - INTERVAL 6 HOUR
GROUP BY host, digest_id ORDER BY cpu_s DESC LIMIT 50 BY host;

-- Digest regression: last 24 h vs the same 24 h a week earlier.
SELECT digest_id,
       sumIf(cpu_ns, window_end > now() - INTERVAL 1 DAY) / 1e9 AS cpu_s_now,
       sumIf(cpu_ns, window_end BETWEEN now() - INTERVAL 8 DAY AND now() - INTERVAL 7 DAY) / 1e9 AS cpu_s_week_ago,
       cpu_s_now / greatest(cpu_s_week_ago, 0.001) AS ratio
FROM obs.mysql_digest_stats
WHERE window_end > now() - INTERVAL 8 DAY
GROUP BY digest_id HAVING cpu_s_now > 10 ORDER BY ratio DESC LIMIT 30;

-- Slow queries for one digest.
SELECT ts, host, latency_ms, query FROM obs.mysql_slow_queries
WHERE digest_id = '<digest_id>' AND ts > now() - INTERVAL 1 DAY ORDER BY ts DESC LIMIT 100;

-- Top inbound clients per service port.
SELECT host, family, service_port, replaceRegexpOne(toString(peer_ip), '^::ffff:', '') AS client,
       sum(bytes_rx + bytes_tx) AS bytes, sum(conns_opened) AS conns
FROM obs.netflow_peer_stats
WHERE direction = 'inbound' AND window_end > now() - INTERVAL 1 HOUR
GROUP BY host, family, service_port, client ORDER BY bytes DESC LIMIT 50;

-- Who talks to MySQL.
SELECT host, replaceRegexpOne(toString(peer_ip), '^::ffff:', '') AS client, sum(bytes_tx) AS result_bytes
FROM obs.netflow_peer_stats
WHERE direction = 'inbound' AND service_port = 3306 AND window_end > now() - INTERVAL 1 HOUR
GROUP BY host, client ORDER BY result_bytes DESC;

-- Family CPU, 5-minute average, last day.
SELECT toStartOfFiveMinutes(window_end) AS t, host, family, avg(cpu_percent_avg) AS cpu
FROM obs.family_stats WHERE window_end > now() - INTERVAL 1 DAY
GROUP BY t, host, family ORDER BY t;

-- Latest diagnose snapshot per host, with its I/O verdict summary.
SELECT host, argMax(ts, ts) AS at, argMax(reason, ts) AS reason,
       JSONExtractString(argMax(report, ts), 'io_diagnosis', 'summary') AS io_summary
FROM obs.diagnose_snapshots WHERE ts > now() - INTERVAL 1 DAY GROUP BY host;
