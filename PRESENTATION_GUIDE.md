
## One-Minute Summary

This project is a real-time IoT Intrusion Detection System. It captures live
network packets, extracts packet features, sends those features to a trained
hybrid machine-learning model, and displays whether the traffic looks benign or
suspicious.

## Problem Statement

IoT networks contain many small devices, and those devices are often vulnerable
to attacks such as DDoS, Mirai botnet traffic, reconnaissance, spoofing, and web
attacks. The goal of this project is to monitor network traffic and identify
traffic patterns that look suspicious.

## Dataset And Model

- Dataset used during development: CICIoT2023 CSV traffic data.
- Model class: `scripts/hybrid_model.py`.
- Saved model: `models/hybrid_dl_ml_model.pkl`.
- Saved TensorFlow component: `dl_model_component.h5`.
- This folder is now a runtime version, so the large dataset and training script
  were removed because they are not required for the live demo.

The trained model groups many original CICIoT labels into these final classes:

- `Benign`
- `DDoS`
- `DoS`
- `Mirai`
- `Recon`
- `Spoofing`
- `Web`
- `BruteForce`

## Architecture

The project has four main parts:

1. Packet capture:
   `Tool/packet_sniffer.py` uses Scapy to read packets from the selected network
   interface.

2. GUI:
   `Tool/optimized_sniffer_gui.py` is the PyQt dashboard. It shows live packets,
   stats, logs, and packet details.

3. Background prediction:
   `Tool/async_predictor.py` queues packets and runs model prediction in a
   background thread so the GUI does not freeze. It also includes a simple
   Nmap-style scan heuristic that marks repeated multi-port probing as `Recon`.

4. Hybrid IDS model:
   `scripts/hybrid_model.py` combines a TensorFlow neural network, a Random
   Forest, and a Logistic Regression meta-classifier.

## How Efficiency Is Calculated

For this project, efficiency does not mean only speed. It includes both runtime
performance and model accuracy.

- Capture speed: how many packets are captured per second.
- Processing time: how long the background predictor takes to analyze a batch.
- Processing speed: an approximate rate calculated from the average processing
  time.
- Live efficiency: shown in the app as `Processed / Received × 100`.
- Queue size: how many packets are waiting for prediction. If the queue stays
  low, the system is processing traffic fast enough.
- Validation accuracy: used during model training to check how well the hybrid
  model performs on unseen validation data.

Simple presentation sentence:

"The efficiency of this IDS is measured by packet capture speed, prediction
speed, queue size, and validation accuracy of the trained hybrid model."

## What To Show In The Demo

1. Start the app:

   ```bash
   cd /Users/muneeb/Downloads/IDS
   ./run_macos.sh
   ```

2. Select `en0`.

3. Click `Start Capture`.

4. Generate traffic:

   ```bash
   ping -4 8.8.8.8
   ```

   Optional controlled Nmap demo, only against your own machine. Select `lo0`
   in the app first because localhost traffic does not use `en0`:

   ```bash
   nmap -p 1-100 127.0.0.1
   ```

5. Explain the counters:

   - `Received`: packets captured from the network.
   - `Processed`: packets analyzed by the model.
   - `Attacks`: packets classified as non-benign.
   - `Queue`: packets waiting for prediction.
   - `Speed`: current capture rate.

6. Click a packet and show the Packet Details tab.

## Important Talking Points

- `Benign` means the model thinks the packet is normal.
- `Mirai`, `DDoS`, `Recon`, etc. mean the model detected suspicious behavior.
- `Recon` can also appear when the scan heuristic sees Nmap-like port probing.
- The app logs every prediction in the Live Log tab.
- Queue size near 0 means the app is processing packets fast enough.
- The model is for detection and demonstration, not guaranteed production
  security.


## Future Improvements

- Add flow-level feature extraction so predictions match the training dataset
  more closely.
- Add firewall blocking to turn IDS behavior into IPS behavior.
- Add confidence display in the packet table.
- Add export buttons for reports and captured packets.
- Retrain and validate the model with traffic captured from the target network.
