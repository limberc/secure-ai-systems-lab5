# Incident reconstruction — dev workload

Answer from **your own gateway log** (and your dashboard), not from the workload file or
the ledger. For each answer, give the query or command you ran — `jq`, Python, a Grafana
panel — so that a reader can rerun it. Handout §3, report section 4.

1. During the distributed flood: which `key_id` was abused, from how many distinct client
   IPs, and at what time (UTC) did your gateway first refuse it?
2. During the key rotation: which client IP was responsible, how many distinct keys did it
   present (valid and invalid), and how many of its requests reached the service?
3. What did the token-amplification segment cost, in total, and which tenants paid for it?
   Reconcile your log's figure with `logs/backend/ledger.jsonl`.
4. During `bon_exfil`: how many requests did your input check refuse, how many responses
   did your output check withhold, and did any secret reach a client? If one did: which
   `request_id`, and why did your scanner miss it?
5. Which alert fired first in each attack segment, and how long after the segment began?
   Which alerts, if any, fired outside the attack segments, and why?
6. Name one question about this run that your log *cannot* answer, and the field you
   would add so that it could.
