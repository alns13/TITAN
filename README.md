# TITAN : Traffic Inspection &amp; Threat Analysis Network


**TITAN** is an AI-powered Intrusion Detection System (IDS) designed to identify network anomalies using supervised machine learning. 

Unlike traditional signature based firewalls, TITAN utilizes the **NSL-KDD dataset** to train a behavioral model capable of detecting Zero-Day attacks and subtle malicious patterns that deviate from established network baselines.

## Project Goals
* **High-Fidelity Detection:** Achieving 94%+ accuracy in classifying DoS, Probe, R2L, and U2R attacks.
* **Explainable AI (XAI):** Utilizing feature importance to explain *why* a specific packet was flagged.
* **Scalable Pipeline:** A reproducible data engineering workflow from raw PCAP/CSV to model inference.
