# TITAN : Threat Inspection Targeted Agent Network


**TITAN** is an AI-powered Intrusion Detection System (IDS) designed to identify network anomalies using supervised machine learning. 

Unlike traditional signature based firewalls, TITAN utilizes the **NSL-KDD dataset** to train a behavioral model capable of detecting Zero-Day attacks and subtle malicious patterns that deviate from established network baselines.

**FAQ:**

**Q: How does TITAN work?**

* TITAN operates as a Network-based Intrusion Detection System (NIDS). It sits between your device and router analyzing packet          metadata during packet transitions, such as duration, protocol type, and byte counts to determine if a connection is safe or             malicious. It acts as a secondary layer of "behavioral defense" behind your primary firewall.

**Q: How is it any different from a traditional firewall?**

* Traditional firewalls inspect incoming traffic with a **Rule based** logic: "If IP = X.X.X.X then Block" or  "If Port = 443 then Allow." TITAN is a trained AI model that detects based on overall pattern and behaviour of the traffic flow over a certain timeframe.

**Q: What is the advantage of using AI for security?**

* Traditional systems are blind to Zero-Day vulnerabilities because they require a pre-existing "signature" or database update to recognize a threat. TITAN can identify attacks simply because they don't look like normal traffic, allowing it to flag threats that haven't been officially documented yet.

**Q: Does TITAN replace my existing firewall?**

* No, **ABSOLUTELY NOT.** From a security standpoint, TITAN is a companion tool to your firewall. The firewall blocks the obvious "well known bad traffic" at high speed, while TITAN performs deep behavioral analysis on the traffic that is allowed through, looking for sophisticated or stealthy intrusions.

## Project Goals
* **High Accuracy Detection:** Achieving 95%+ accuracy in classifying DoS, Probe, R2L, and U2R attacks.
* **Explainable AI (XAI):** Utilizing feature importance to explain *why* a specific packet was flagged.
* **Scalable Pipeline:** A reproducible data engineering workflow from raw PCAP/CSV to model inference.
