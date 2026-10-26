# How an organization uses SentinelX

This guide explains, in simple words, how a company uses SentinelX to stay safe from cyber attacks.
You do not need to be a security expert to understand it.

---

## 1. What problem does SentinelX solve?

Every computer, server and network device in a company writes **logs**. A log is a small note like:

- "Someone logged in to laptop WS-042"
- "Laptop WS-042 connected to a website"
- "A program called PowerShell started"

A company with 100 employees creates **tens of thousands** of these notes every day.
Hidden among them may be the signs of a hacker. No person can read them all.

**SentinelX reads all of them for you.** It finds the few that look dangerous, connects the ones that
belong together, and shows you a short list of **incidents** — real problems that need a human to look at.

> Think of SentinelX as a security guard who watches every camera all day and only calls you
> when something is actually wrong — and then tells you exactly what they saw.

---

## 2. Who is it for?

| Organization | Why it helps |
|---|---|
| Small and medium companies (about 50–500 people) | They have IT staff, but no full-time security team |
| Schools, clinics, shops, factories, offices | They hold important data but cannot afford expensive security tools |
| IT service companies (MSPs / MSSPs) | One installation can protect many client companies, each kept completely separate |

---

## 3. A simple example

At 2 o'clock at night, a hacker tries to guess an employee's password.

1. The hacker tries 43 wrong passwords.
2. The 44th try works.
3. The hacker runs a hidden command on the laptop.
4. The laptop contacts a dangerous website on the internet.

Without SentinelX, these are **about 50 separate log lines**, mixed with thousands of normal ones.

With SentinelX, the IT person sees **one** clear item in the morning:

> **Critical — Possible account compromise: jdoe on WS-042**
> Many failed logins, then a successful login from a new place, then a suspicious command,
> then a connection to a known dangerous server. Risk 95 out of 100.

Everything they need is on one page: what happened, in what order, which laptop and which user,
and what to check next.

---

## 4. Getting started (one time)

### Step 1 — Install SentinelX
Your IT person installs SentinelX on one computer or server in the company
(a normal server with 4 processors and 8 GB of memory is enough).
It takes about an hour. Your data stays **inside your company** — nothing is sent to the cloud.

### Step 2 — Connect your "eyes"
SentinelX needs to see what is happening. It uses free, well-known tools:

| Tool | Where it goes | What it sees |
|---|---|---|
| **Wazuh** | A small program on each laptop and server | Logins, programs that start, new user accounts, changed files |
| **Suricata** | On the network (for example, next to the firewall) | Known attack patterns in network traffic |
| **Zeek** | On the network | Which computers talk to which websites and servers |

The **Integrations** page in SentinelX shows step-by-step instructions you can copy and paste.

### Step 3 — Tell SentinelX what is important (about 30 minutes)
- On the **Assets** page, mark your most important computers as "critical"
  (for example: the finance server, the customer database).
- On the **Users** page, mark administrator accounts as "privileged".

Now SentinelX knows that a problem on the finance server is more serious than one on a test laptop.

### Step 4 — Add your team
On **Administration → Users**, create an account for each person and give them a role (see section 6).

---

## 5. A normal day (10–15 minutes)

1. **Open the Dashboard.**
   The "Needs your attention" box shows open incidents, the most dangerous one first.
   If it says "Nothing needs your attention", you are done.

2. **Open the top incident.** The page answers six simple questions:

   | Question | Where to look |
   |---|---|
   | What happened? | "What happened" box and the **Timeline** |
   | How serious is it? | The **risk score** (0–100) and "Why this score?" |
   | Which computers and people are affected? | "Who & what is affected" |
   | What is the proof? | Click any line in the Timeline to see the original log |
   | What kind of attack is it? | The **MITRE ATT&CK** labels (a world-standard list of attack methods) |
   | What should I do next? | The **AI analyst** tab and the Response box |

3. **Click "Start investigating"** so your team knows someone is working on it.
   Choose an owner in the **Owner** box.

4. **Ask the AI analyst (optional).**
   Click "Investigate with AI". After about one or two minutes you get a plain-English explanation,
   possible innocent reasons, and suggested next steps. Every sentence links to the real evidence,
   so you can check it. The AI runs on your own computer and **cannot change anything**.

5. **Fix the problem with your normal tools.**
   For example: reset the user's password, disconnect the laptop from the network, or remove a program.
   SentinelX never makes changes to your computers by itself — a human always decides.
   You can add a **Task** in the Response box so the team remembers what to do,
   or click **Watch IOC** so SentinelX warns you immediately if the attacker's address appears again.

6. **Write a short note** about what you found and did. Notes become part of the report.

7. **Close the incident and pick the outcome:**
   - *True positive* — it was a real attack
   - *Benign* — it was real activity, but allowed (for example, an IT admin doing their job)
   - *False positive* — the alarm was wrong

   This keeps your statistics honest and helps SentinelX get better.

---

## 6. Who does what (roles)

Give each person only the access they need.

| Role | Good for | What they can do |
|---|---|---|
| **Viewer** | Managers, auditors | Look at everything, change nothing |
| **IT operator** | Helpdesk / IT staff | Start working on incidents, add notes, pick owners, update computer details, download reports |
| **Security analyst** | The person who investigates | Everything an IT operator can do, plus close incidents with an outcome, use the AI analyst, manage threat lists |
| **Admin** | Head of IT | Everything above, plus manage users, settings and detection rules for the company |
| **Super admin** | The person who installed SentinelX | Everything, for every organization on the installation |

Admins can create analysts, operators and viewers. Only a super admin can create other admins.
Every important action is written to the **audit log**, which nobody can edit or delete.

Only people whose role can work incidents (IT operator and above) can be made an incident's owner; viewers
are read-only. Everyone can open **My account** (click your name at the bottom of the sidebar) to see
exactly what their role allows, and to sign out sessions on other computers.

**Someone forgot their password or is locked out?** On **Administration → Users**, click **Reset password**
(this also unlocks the account and signs them out everywhere) or **Unlock** if they still know it. Admins
can do this for the roles below their own; for another admin, ask a super admin.

---

## 7. Weekly and monthly habits

| How often | What to do | Where |
|---|---|---|
| Weekly | Check that all data sources are still sending data | Dashboard → "Telemetry sources" |
| Weekly | Look at rules that create many false alarms and switch off the noisy ones | Detection Rules → "Dry-run" and the on/off switch |
| Monthly | Send a short summary to management | Reports → download the incident report (HTML, or print to PDF) |
| Monthly | Review who has access | Administration → Users |
| Monthly | Check the numbers: how fast you respond and how many alarms were false | Dashboard → bottom-right boxes |

---

## 8. What the main screens are for

| Screen | In one sentence |
|---|---|
| **Dashboard** | What needs my attention right now? |
| **Incidents** | The list of real problems, most dangerous first |
| **Alerts** | The single warnings that incidents are built from |
| **Events** | Search all raw logs (for deeper digging) |
| **AI Analyst** | Status and settings of the private AI helper |
| **Assets / Users** | Your computers and accounts, and how important they are |
| **Threat Intel** | Lists of known bad internet addresses and websites; look one up |
| **MITRE ATT&CK** | A map of which attack methods were seen in your company |
| **Detection Rules** | The rules that decide what is suspicious; turn them on/off or write your own |
| **ML Analytics** | Computers behaving differently from their normal habits |
| **Reports** | Download a report for any incident |
| **Integrations** | Connect data sources and check that everything is healthy |
| **Administration** | Users, settings, access tokens and the audit log |

Tip: press **⌘K** (Mac) or **Ctrl+K** (Windows) anywhere to quickly find an incident, computer, IP address or page.

---

## 9. For IT service companies (MSPs)

One SentinelX installation can protect many customers:

- Each customer is a separate **organization**. Their data is fully separated — one customer can never see another's.
- Your super admin switches between customers with the selector at the top of the left menu.
- Each customer can have their own users, settings and switched-off rules.
- Each customer's log shipping uses its own **ingest token**, so data always lands in the right place.

---

## 10. What SentinelX does **not** do

Being clear about limits helps you use it well:

- It **does not block attacks by itself.** It tells you clearly what is happening; you take the action.
- It **does not replace antivirus.** Keep your antivirus / endpoint protection running.
- It is **not a person watching 24/7.** Someone in your team should check the dashboard every day.
- The **AI can be wrong.** That is why every AI sentence links to the evidence — always check before acting.

---

## 11. Two real-world scenarios

### Scenario A — You run a company and need a SOC

Say you own a 150-person logistics company. No security team, just two IT people.

1. **Install it once** — on one server (4 cores / 8 GB RAM is enough). About an hour. Everything
   stays inside your network — nothing goes to the cloud.
2. **Plug in the "eyes"** — install the free Wazuh agent on laptops/servers, put Suricata next to your
   firewall, run Zeek on the network. The **Integrations** page has copy-paste setup steps for each.
3. **Tell it what matters** — mark the finance server and customer database as "critical" assets, mark
   admin accounts as "privileged" users.
4. **Daily routine (10 minutes)** — someone opens the Dashboard each morning. Instead of wading through
   tens of thousands of raw log lines, they see something like:
   > **Critical — possible account compromise: jdoe on WS-042.** 43 failed logins → success from a new
   > location → suspicious PowerShell → connection to a known-bad IP. Risk 95/100.

   They click in, read the timeline and evidence, optionally ask the AI analyst for a plain-English
   explanation, fix the problem with their normal tools (reset password, disconnect the laptop), and
   close the incident with an outcome.
5. **It never acts on its own.** No auto-blocking. A human always decides. SentinelX does the 24/7
   watching and correlating that a small IT team has no time for.

### Scenario B — You want to sell this as a service to other companies

Two business models, both built on the same mechanic: **one installation, many isolated customers**
(see section 9, "For IT service companies").

**Model A — Managed SOC / MSSP (you host it, they just get results)**
- You run one SentinelX instance. Each client becomes a separate **organization** — fully isolated from
  every other client, enforced by PostgreSQL row-level security, not just app logic.
- You give each client an **ingest token**. Their IT points log shipping at your instance using that
  token — they don't need to give you access to anything else.
- You monitor the dashboard across all organizations, triage incidents, and send a monthly report
  (the **Reports** page exports HTML/PDF) or a weekly call.
- You bill a monthly retainer for "we watch your logs and tell you what's wrong." Lowest-friction model —
  clients only need to trust you with a log feed, not deep system access.

**Model B — On-prem license (they host it, you set it up and support it)**
- You install SentinelX on their server, configure the integrations, train their IT person, and charge a
  setup fee plus an ongoing support contract (tuning rules, keeping false positives down, quarterly reviews).

**How integration with their systems actually works, in either model:**

| Data | How you connect it |
|---|---|
| Endpoint activity | Install the free Wazuh agent on their Windows/Linux machines. It reports to SentinelX (directly, or via the Wazuh indexer that SentinelX polls). |
| Network traffic | Put a Suricata/Zeek sensor on a network tap or SPAN port near their firewall — no agent needed on individual machines. |
| Anything else (cloud logs, custom apps) | They `POST` to `/api/v1/ingest/{source}` with their org's ingest token — useful if they already forward logs somewhere (CloudWatch, Azure, a SIEM) and can send a copy to you. |

A good way to land a cautious first client: start with just the network sensors (no agent installed
on anything), prove the value for a month, then expand to endpoint agents once they trust you.

**The pitch in one line:** "We don't need admin access to your systems — just a log feed. We turn
thousands of raw events into a handful of real incidents, each with the evidence attached." That's an
easy sell because the integration bar is low (ship logs, not grant access) and the output (prioritized
incidents, not raw alerts) is exactly what a company with no SOC is missing.

---

## 12. Quick checklist

**First week**
- [ ] SentinelX installed and running over HTTPS
- [ ] Wazuh agents on all laptops and servers
- [ ] Network sensor (Suricata or Zeek) connected
- [ ] Important computers marked as critical, admin accounts marked as privileged
- [ ] Team accounts created with the right roles
- [ ] First administrator password changed

**Every day**
- [ ] Open the dashboard
- [ ] Handle the top incident (investigate → act → note → close with an outcome)

**Every month**
- [ ] Send a report to management
- [ ] Review users and noisy rules

---

*Want to try it safely first? Sign in as the super admin and click **Explore demo lab** on the dashboard.
It shows realistic, fake attacks so your team can practice without any risk.*
