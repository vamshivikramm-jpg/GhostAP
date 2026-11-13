# GhostAP feature roadmap (selection: ALL, F001–F091)

The catalogue entry for each ID describes the feature itself; this file tracks order,
dependencies and status. Status: `todo` · `done` · `done*` (built and tested with
simulated input; needs real hardware, credentials or Phase 2 data to confirm).

## Dependencies that shape the order

| Feature | Needs first | Why |
|---|---|---|
| F015 Monitored Networks page, F016 wizard, F017 accept change, F034 network health, F043 smart hopping | **F014 saved baselines** | they read or edit the saved baseline |
| F018 new-network inbox, F011 per-network sensitivity | F015 | settings live on a monitored network |
| F012 incident correlation | F005 deauth detection (and F001, F002) | correlates their signals |
| F032 evidence pcap, F054 session bundle | **F040 sessions** | they need a session with its own folder and pcap |
| F075 settings page | F072 config validation | the page writes config through the validator |
| F057 phone push | F056 webhooks | push is a webhook preset |
| F066 two-factor, F067 session management | F065 accounts | they protect accounts |
| F087 Ask GhostAP | F086 AI explainer | same opt-in AI client and redaction |
| F084 learned weights | F048 test splits | weights must be fitted and scored on different data |
| F088 labelling assistant | F046 labelling page | it suggests labels in that page |
| F090 presentation mode | F089 demo button | it drives the demo replay |
| F045 location | F044 several sensors | needs readings from 3+ sensors |

## Phases

| Phase | Features | Theme |
|---|---|---|
| A | F040, F014, F072, F069, F070, F074, F068 | foundations: sessions, saved baselines, config, audit, retention, logs, health |
| B | F001–F013, F042, F043 | detection engine and capture quality |
| C | F015–F019, F034, F035 | monitored networks pages |
| D | F020–F033, F036–F039, F076–F083, F089–F091 | dashboard pages and experience |
| E | F055–F061 | notifications and integrations |
| F | F062–F067 | sign-in, accounts, HTTPS |
| G | F046–F054, F084, F085, F088 | lab, evaluation, reports, learning |
| H | F071, F073, F075 | operations and settings page |
| I | F086, F087 | opt-in AI |
| J | F041, F044, F045 | capture control and several sensors |

## Known blockers (reported, not hidden)

- **Real radio / Kali only:** F005 (deauth frames), F041 (capture control), F044–F045
  (several sensors), F009 (6 GHz). Built and tested with simulated frames here.
- **Credentials from you:** F058 email (SMTP), F057 Telegram bot token, F086–F087 AI API key.
  Built with the integration switched off by default and tested against fake servers.
- **Phase 2 data:** F003 ships with the fingerprint *format* and loader plus clearly marked
  synthetic examples; real tool fingerprints come from your lab recordings. F084–F085 run on
  synthetic data until then.
- **Not installed here:** Docker (F073) and Kismet (F050): files written and syntax-checked only.

## Status

| ID | Feature | Phase | Status |
|---|---|---|---|
| F001 | KARMA / MANA attack detection | B | done |
| F002 | Look-alike network names | B | done |
| F003 | Attack-tool fingerprint library | B | done* |
| F004 | Detailed security downgrade | B | done |
| F005 | Deauthentication flood detection | B | done* |
| F006 | Two transmitters, one address | B | done |
| F007 | Beacon clock-skew fingerprint | B | done* |
| F008 | Beacon-rate anomaly | B | done |
| F009 | Wi-Fi 6 / 6E awareness | B | done* |
| F010 | Passive hidden-network matching | B | done |
| F011 | Per-network sensitivity | B | done |
| F012 | Incident correlation | B | done |
| F013 | Alert throttling and re-alerting | E | todo (moved: throttling belongs with notifications) |
| F014 | Saved network baselines | A | done |
| F015 | Monitored Networks page | C | done |
| F016 | Baseline wizard | C | done |
| F017 | Accept a change into the baseline | C | done |
| F018 | New-network inbox | C | done |
| F019 | Allow-list editor | C | done |
| F020 | Incident story card | D | done |
| F021 | Sensor heartbeat | D | done |
| F022 | Customisable layout | D | todo |
| F023 | "Since you last looked" | D | todo |
| F024 | Alert filters and sorting | D | done |
| F025 | Bulk triage | D | done |
| F026 | Snooze and mute rules | D | done |
| F027 | Triage history | D | done |
| F028 | Beacon difference viewer | D | todo |
| F029 | Vendor names | D | todo |
| F030 | Signal and uptime charts | D | todo |
| F031 | What-if weights | D | todo |
| F032 | Evidence pcap download | D | todo |
| F033 | Related access points | D | todo |
| F034 | Network health card | C | done |
| F035 | Network risk score | C | done |
| F036 | Clock time and time ranges | D | todo |
| F037 | Timeline annotations | D | todo |
| F038 | Large-site performance | D | todo |
| F039 | Table export and columns | D | todo |
| F040 | Sessions page | A | done |
| F041 | Capture control panel | J | todo |
| F042 | Capture quality panel | B | done |
| F043 | Smart channel hopping | B | done |
| F044 | Several sensors | J | todo |
| F045 | Rough location | J | todo |
| F046 | Labelling page | G | todo |
| F047 | Evaluation page | G | todo |
| F048 | Confidence intervals and test splits | G | todo |
| F049 | ROC and precision-recall curves | G | todo |
| F050 | Kismet as a second baseline | G | todo |
| F051 | Scenario builder | G | todo |
| F052 | Session incident report | G | todo |
| F053 | Keep report numbers in sync | G | todo |
| F054 | Session bundle | G | todo |
| F055 | Desktop notifications | E | todo |
| F056 | Webhooks | E | todo |
| F057 | Phone push | E | todo |
| F058 | Email alerts | E | todo |
| F059 | SIEM and syslog export | E | todo |
| F060 | Grafana metrics | E | todo |
| F061 | Documented API with keys | E | todo |
| F062 | Better sign-in page | F | todo |
| F063 | Read-only viewer link | F | todo |
| F064 | HTTPS mode | F | todo |
| F065 | Analyst accounts and roles | F | todo |
| F066 | Two-factor sign-in | F | todo |
| F067 | Session management | F | todo |
| F068 | System health page | A | done |
| F069 | Audit log | A | done |
| F070 | Data retention | A | done |
| F071 | Run as a service | H | todo |
| F072 | Settings validation | A | done |
| F073 | Docker image | H | todo |
| F074 | Log files | A | done |
| F075 | Settings page | H | todo |
| F076 | Guided tour | D | todo |
| F077 | Glossary tooltips | D | todo |
| F078 | Command palette | D | todo |
| F079 | Accessibility pass | D | todo |
| F080 | Colour-blind and high-contrast modes | D | todo |
| F081 | Install as an app | D | todo |
| F082 | Languages | D | todo |
| F083 | Shareable views | D | todo |
| F084 | Learned weights | G | todo |
| F085 | Anomaly model | G | todo |
| F086 | AI alert explainer (opt-in) | I | todo |
| F087 | Ask GhostAP (opt-in) | I | todo |
| F088 | Labelling assistant | G | todo |
| F089 | Demo button | D | todo |
| F090 | Presentation mode | D | todo |
| F091 | Dashboard screenshot for the report | D | todo |
