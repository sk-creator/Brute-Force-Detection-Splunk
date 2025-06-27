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

📌 Dashboard Panels

The Splunk dashboard for this project includes:

📊 Brute-Force Attempt Counts by User and Source IP
	•	Bar Chart highlighting top offending accounts/IPs

📋 Detailed Failed Login Events
	•	Table listing user, source IP, and failed attempt count for analyst triage
https://github.com/sk-creator/Brute-Force-Detection-Splunk/blob/DASHBOARD/Screenshot%202025-06-27%20at%2016.47.21.png


📌 MITRE ATT&CK Mapping
	•	Tactic: Credential Access
	•	Technique: T1110 (Brute Force)

This detection aligns with MITRE ATT&CK Framework, helping SOC teams standardize detection coverage.

⸻

📌 Tools & Skills Used
	•	Splunk Enterprise (Free version for lab)
	•	SPL (Search Processing Language)
	•	Data ingestion and indexing
	•	Dashboard design and customization
	•	MITRE ATT&CK framework mapping

⸻

📌 Outcome

✅ Enables SOC teams to:
	•	Detect brute-force login attempts early
	•	Identify high-risk users and source IPs
	•	Investigate and respond faster
	•	Customize detection thresholds based on environment

⸻

📌 Next Steps
	•	Automate alert creation in Splunk
	•	Create Splunk saved searches and scheduled alerts
	•	Build Sigma rules for cross-SIEM compatibility
	•	Extend detection to other EventCodes (e.g. 4624 for successful logins)

⸻

📌 Author

👤 SHIVANSH KAUSHIK
	•	Role: Aspiring SOC Analyst | Blue Team Enthusiast
	•	Certification: CompTIA Security+


⸻

📌 License

This project is for educational purposes. Feel free to use or adapt for your own learning!








