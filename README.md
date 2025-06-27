# 🚀 Brute-Force Login Detection in Splunk

This project demonstrates how to detect brute-force login attempts using Windows Security Event Logs (EventCode=4625) in Splunk. It simulates a real-world SOC detection use case with hands-on log parsing, SPL query development, and dashboard visualization.

---

## 📌 Problem Statement

Brute-force attacks are a common threat where attackers try multiple password guesses to compromise accounts. Detecting high volumes of failed login attempts from the same user or IP address is essential for early warning in a Security Operations Center (SOC).

---

## 📌 Data Source

- **Format:** CSV (sample lab data)
- **Fields:** `_time`, `EventCode`, `user`, `src_ip`, `message`
- **EventCode=4625:** Windows Security Event ID for *failed login*

Example data: [`windows_failed_logins.csv`](./data/windows_failed_logins.csv)

---

## 📌 Detection Logic (SPL Query)

```spl
index=* sourcetype=csv EventCode=4625
| stats count by user, src_ip
| where count > 5
| sort -count


✅ Filters Windows failed login events (EventCode=4625)
✅ Aggregates counts of failures per user and source IP
✅ Applies a threshold (>5) to detect suspicious patterns
✅ Sorts results to prioritize investigation

⸻


