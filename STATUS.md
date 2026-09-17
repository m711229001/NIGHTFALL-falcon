\# Falcon MAG - Project Status



\*\*Last Update:\*\* 2026-09-16



\## ✅ Completed



\### Cleanup

\- 6 DBs → 2 DBs (falcon.db: 30+ scans, users.db: 2 users)

\- NIGHTFALL Core: 22 → 3 files

\- Services: 3 → 1 scanner (scanner\_v3.py)

\- Central archive: `\_archive/`



\### Features

\- \*\*i18n:\*\* Arabic + English (7 pages, \~60 keys)

\- \*\*Language toggle:\*\* AR ↔ EN (persisted in localStorage)

\- \*\*Arabic PDF:\*\* RTL support (reportlab + arabic-reshaper + bidi)

\- \*\*SARIF Export:\*\* 2.1.0 (CI/CD compatible)

\- \*\*Burp Suite Proxy:\*\* Toggle + persisted settings

\- \*\*CLI:\*\* `nightfall scan/version/report/oast-server`



\### Engine (NIGHTFALL Core v2)

\- 14 detection engines (XSS, SQLi, SSRF, IDOR, JWT, XXE, SSTI, NoSQL, GraphQL, LDAP, MongoDB, OpenRedirect, CSRF, XXE-OOB)

\- WAF detection + bypass (15+ signatures, 13 methods)

\- Hidden paths (300+ wordlist)

\- OAST Server (DNS + HTTP)

\- Multi-Turn Reasoning (3 turns)

\- AI: DeepSeek + Claude Haiku



\### Tested

\- \*\*Scan #29:\*\* https://es.hrsd.gov.sa — 2 SSTI (Critical), 38 hidden paths

\- \*\*Scan #30:\*\* Same target — confirmed

\- \*\*AI Plan:\*\* 12 execution steps, 6 success criteria



\## ⏳ Remaining



\- \[ ] Excel/CSV Export

\- \[ ] Notifications (Telegram/Email)

\- \[ ] Scheduled Scans

\- \[ ] Docker + VPS Deployment

\- \[ ] MFA + Multi-user

\- \[ ] PDF Arabic polish (some RTL issues remain)



\## 🚀 Quick Start



\### Backend

