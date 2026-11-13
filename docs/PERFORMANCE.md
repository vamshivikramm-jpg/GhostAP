# Large-site performance (F038)

Measured with `python tools/bench_large_site.py --aps 400 --minutes 20` on the development
Mac (Python 3.12). The site is **synthetic and author-designed**: 80 networks with 5 access
points each plus 2 twins, one beacon per access point per second (real access points send
about ten), 481,200 beacons, 43,320 timeline rows. Re-run the tool for your own hardware.

| Endpoint | Before | After | Change |
|---|---|---|---|
| `/api/timeline` | 65 ms, 1,476 KB | 49 ms, 111 KB | sends the alerting APs and the top 30 others in full, folds the rest into one "highest of the others" line, at most 800 points per line (each bucket keeps its peak) |
| `/api/whatif`, first call | 58 s inside one request | answers in 3 s with "preparing"; ready after 59 s in the background | indicators are evaluated once per session version, then re-scored |
| `/api/whatif`, re-score | (same 58 s) | 0.6 s | |
| `/api/summary` (polled every 2 s) | 1.4 ms | 1.4 ms | already reads counts from `ap_profiles` |
| `/api/aps`, `/api/networks` | 19–21 ms, ~165 KB | same | |
| `/api/ap` / series / related / beacon_diff | 27 / 6 / 143 / 3 ms | same | |

The dashboard also renders at most 300 table rows at a time ("Show all" renders the rest;
search, sort and CSV export always cover every row).

Scoring itself took 58 s for the whole 20-minute capture, about 0.54 s per 10-second step
for 402 access points, so a live capture of this size keeps up. The what-if preparation
costs the same as one full scoring pass; for very long sessions (more than 200,000
access-point steps) it refuses and suggests `evaluate.py` instead.
