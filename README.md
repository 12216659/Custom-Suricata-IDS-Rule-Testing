# Custom Suricata IDS Rule Testing

## 📌 Project Overview

This project demonstrates the creation, deployment, and validation of a **custom Suricata IDS rule** to detect **HTTP Basic Authentication attempts**. The objective is to showcase hands-on IDS rule writing, traffic generation, packet capture, and alert verification—skills expected in SOC and Cyber Security Analyst roles.

---

## 🎯 Project Objectives

* Write a custom Suricata rule to detect HTTP Basic Authentication
* Deploy the rule in Suricata IDS
* Generate test traffic using `curl`
* Capture traffic in a PCAP file
* Verify alert generation using Suricata logs

---

## 🛠 Tools & Technologies

* **Suricata IDS (v8.x)**
* **Kali Linux**
* **curl** (traffic generation)
* **tcpdump** (packet capture)
* **Python HTTP Server** (controlled test environment)

---

## 📂 Repository Structure

```
Custom-Suricata-IDS-Rule-Testing/
│
├── rules/
│   └── custom.rules              # Custom Suricata rule
│
├── pcaps/
│   └── basic_auth_test.pcap      # Captured HTTP Basic Auth traffic
│
├── logs/
│   └── eve.json                  # Suricata alert log (evidence)
│
└── README.md                     # Project documentation
```

---

## 🧩 Custom Suricata Rule

File: `rules/custom.rules`

```suricata
alert tcp any any -> any 80 (msg:"HTTP Basic Authentication Attempt Detected"; flow:to_server,established; content:"Authorization: Basic"; nocase; classtype:attempted-user; sid:1000001; rev:1;)
```

---

## 🚀 Step-by-Step Execution

### 1️⃣ Start Local HTTP Server

```bash
sudo python3 -m http.server 80
```

### 2️⃣ Capture Traffic

```bash
sudo tcpdump -i lo -w basic_auth_test.pcap
```

### 3️⃣ Generate HTTP Basic Auth Traffic

```bash
curl -v -u admin:admin http://127.0.0.1
```

Stop tcpdump with `CTRL+C`.

---

### 4️⃣ Verify PCAP Contents

```bash
tcpdump -nn -A -r basic_auth_test.pcap | grep -i authorization
```

---

### 5️⃣ Run Suricata on PCAP

```bash
sudo suricata -k none \
-r basic_auth_test.pcap \
-c /etc/suricata/suricata.yaml \
-l suricata-logs
```

---

### 6️⃣ Verify Alert Detection

```bash
grep -i '"event_type":"alert"' suricata-logs/eve.json
```

### ✅ Sample Alert Output

```json
"alert":{
  "signature":"HTTP Basic Authentication Attempt Detected",
  "signature_id":1000001
}
```

---

## 📸 Evidence

* PCAP contains `Authorization: Basic` header
* Suricata alert visible in `eve.json`
* Custom rule successfully triggered

---

## 🧠 Key Learnings

* Writing custom IDS rules in Suricata
* Understanding app-layer vs payload-based detection
* Generating controlled attack traffic
* Validating IDS alerts using JSON logs

---

## 📌 Resume-Ready Description

> Developed and validated a custom Suricata IDS rule to detect HTTP Basic Authentication attempts. Generated test traffic using curl, captured packets with tcpdump, and verified alerts through Suricata log analysis.

---

## ✅ Status

**Project Completed Successfully ✔**

---

## 📬 Author

**G Revanth kumar**
Cyber Security / SOC Analyst Aspirant
