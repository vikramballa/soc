# Using SentinelX during an incident

1. **Dashboard → Needs your attention**: start at the top (highest explainable risk).
2. Open the incident: read *What happened*, *How serious* (click *Why this score?*), *Who & what is affected*.
3. **Timeline**: follow the sequence; click any row to see the original event exactly as received.
4. **Start investigating** (sets status, records time-to-acknowledge). Assign it to yourself.
5. Optional **AI analyst** for a plain-language summary, benign explanations and next steps — verify each
   cited event before acting.
6. **Response** (safe actions): add tasks for your team (e.g. reset a password, isolate the host with your
   EDR/network tools), add indicators to the watchlist so recurrences alert immediately.
7. Record findings as **notes**; they become part of the report.
8. **Resolve/close** with a disposition (true positive, benign, false positive) — this keeps the
   false-positive rate honest and helps tuning. Export the **report** for management or auditors.

SentinelX never executes actions on your systems.
