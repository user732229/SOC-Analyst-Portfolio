# Wireshark Traffic Analysis

<details>
<summary>Report metadata</summary>

| Field | Value |
|---|---|
| Platform | LetsDefend |
| Tool | Wireshark |
| Category | Network traffic analysis |
| Analyst | Portfolio author |
| Date | YYYY-MM-DD |
| Status | In progress |
| Lab reference | [LetsDefend — Malware Traffic Analysis with Wireshark](https://app.letsdefend.io/training/lessons/malware-traffic-analysis-with-wireshark) |

</details>

## 1. Executive summary

**Status:** In progress — no findings are claimed yet.

Summarize the investigation in 3–5 sentences after completing the exercise. State what was examined, the principal observations, the conclusion, and any limitations.

## 2. Objective and scope

- **Objective:** [What question are you trying to answer?]
- **Authorized environment:** [Training lab / own test environment]
- **Scope:** [Files, capture, hosts, timeframe, or exercise components]
- **Out of scope:** [Systems or data not examined]

## 3. Environment and tools

| Item | Details |
|---|---|
| Operating system | [e.g., Windows 11] |
| Wireshark version | [Version] |
| Dataset / capture | [Training-provided filename; do not publish sensitive raw captures] |
| Other tools | [If applicable] |

## 4. Investigation methodology

Document what you actually did, in order. Example prompts:

1. Loaded the authorized training capture.
2. Reviewed packet list and capture metadata.
3. Applied display filters relevant to the investigation.
4. Followed selected protocol conversations where appropriate.
5. Recorded timestamps, endpoints, ports, and protocol details.
6. Cross-checked observations before drawing conclusions.

### Filters used

| Filter | Purpose | What it returned |
|---|---|---|
| `dns` | Inspect DNS traffic | [Observed result] |
| `tcp` | Inspect TCP packets | [Observed result] |
| `http` | Inspect HTTP traffic | [Observed result] |
| `tls` | Inspect TLS handshakes/metadata | [Observed result] |
| [Other] | [Purpose] | [Observed result] |

Only retain filters you actually used.

## 5. Findings

Record observed facts. Use one row per finding.

| ID | Timestamp (with timezone) | Source | Destination | Protocol / port | Observation | Significance |
|---|---|---|---|---|---|---|
| F-01 | [Time] | [IP/host] | [IP/host] | [Protocol] | [What the packet shows] | [Why it matters] |

### Indicators of compromise (if any)

| Type | Value | Evidence | Confidence |
|---|---|---|---|
| Domain | [Value or None observed] | [Packet/frame reference] | [Low/Medium/High] |
| IP address | [Value or None observed] | [Packet/frame reference] | [Low/Medium/High] |
| URL / URI | [Value or None observed] | [Packet/frame reference] | [Low/Medium/High] |
| File hash | [Value or Not available] | [Source] | [Low/Medium/High] |

Do not label an address or domain malicious solely because it is unfamiliar. Explain the supporting evidence and its limitations.

## 6. Evidence

Store sanitized screenshots in `screenshots/`. Refer to them below.

- **Evidence 1:** [Filename] — [What it demonstrates]
- **Evidence 2:** [Filename] — [What it demonstrates]

Before publishing, redact personal/public IP addresses where appropriate, MAC addresses, usernames, internal hostnames, tokens, credentials, and unrelated traffic. Do not upload raw PCAP/PCAPNG files unless you own the data, have permission to publish them, and have reviewed their contents.

## 7. Analysis and assessment

Separate the following:

- **Observed facts:** [Directly supported by packets]
- **Interpretation:** [What those facts may indicate]
- **Alternative explanations:** [Benign or other possibilities]
- **Limitations:** [Missing context, encrypted payloads, incomplete capture, clock uncertainty, etc.]

**Assessment:** [Benign / suspicious / malicious / inconclusive — justify this.]

## 8. Conclusion and recommended actions

[Summarize the answer to the investigation objective.]

Recommended actions, where justified:
- [Action 1]
- [Action 2]

Do not claim that an action was performed unless it was actually carried out.

## 9. Skills demonstrated

- [ ] Packet capture and navigation
- [ ] Display-filter usage
- [ ] DNS analysis
- [ ] TCP/IP and port analysis
- [ ] Protocol conversation inspection
- [ ] Evidence-based assessment
- [ ] Clear technical reporting

## 10. References

- [Wireshark User's Guide](https://www.wireshark.org/docs/wsug_html_chunked/)
- [Wireshark Display Filter Reference](https://www.wireshark.org/docs/dfref/)
- [LetsDefend training lab](https://app.letsdefend.io/training/lessons/malware-traffic-analysis-with-wireshark)

---

**Disclaimer:** This is an educational portfolio exercise conducted in an authorized lab. Findings must reflect the actual exercise evidence and must not be interpreted as an assessment of any third-party network.
