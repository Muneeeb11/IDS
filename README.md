# Real-Time IoT Intrusion Detection System

This project is a desktop Intrusion Detection System (IDS) for monitoring live
network traffic. It captures packets from a selected network interface, extracts
basic packet features, sends them to a trained hybrid ML/DL model, and displays
the result in a PyQt dashboard.

## Problem Statement

IoT networks contain many small devices, and those devices are often vulnerable
to attacks such as DDoS, Mirai botnet traffic, reconnaissance, spoofing, and web
attacks. The goal of this project is to monitor network traffic and identify
traffic patterns that look suspicious.

## What The App Does

- Captures live packets using Scapy.
- Shows packet time, source, destination, protocol, length, and summary.
- Loads a trained hybrid TensorFlow + scikit-learn model.
- Classifies traffic as `Benign`, `DDoS`, `DoS`, `Mirai`, `Recon`, `Spoofing`,
  `Web`, or `BruteForce`.
- Adds a lightweight Nmap-style port-scan heuristic that flags repeated
  multi-port probing as `Recon`.
- Logs predictions and warnings in the Live Log tab.
- Tracks packet count, processed count, attack count, queue size, and speed.

## Project Structure

```IDS/
├── Tool/
│   ├── optimized_sniffer_gui.py   # Main GUI application
│   ├── packet_sniffer.py          # Live packet capture and packet parsing
│   ├── async_predictor.py         # Background ML prediction worker
│   ├── ids_logger.py              # Central logging setup
│   └── dl_model_component.h5      # TensorFlow model component used at runtime
├── scripts/
│   └── hybrid_model.py            # Hybrid DL/ML model class
├── models/
│   └── hybrid_dl_ml_model.pkl     # Saved scaler, encoders, ML models, meta model
├── requirements.txt               # Python dependencies
├── run_macos.sh                   # One-command macOS launcher
└── PRESENTATION_GUIDE.md          # Simple explanation for presenting
```

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

## Why this Dataset

- IoT-focused: it matches my problem domain, because this IDS is aimed at IoT network attacks.
- Covers multiple attack types: it supports classes like DDoS, DoS, Mirai, Recon, Spoofing, Web, and BruteForce, which fit my model outputs well.
- Good for supervised learning: the traffic is labeled, so it is suitable for training classification models.
- CSV/tabular format: this works well with my hybrid approach using TensorFlow plus scikit-learn.
- Better for a real IDS demo: it gives both benign and malicious traffic, so the model can learn to separate normal traffic from attacks.
- Useful for multiclass detection: instead of only attack vs normal, it helps my system identify the attack category too.

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

## Models Used

This IDS uses a hybrid Deep Learning + Machine Learning pipeline:

- Deep Learning model: a custom TensorFlow/Keras feed-forward neural network
  built from `Dense`, `BatchNormalization`, and `Dropout` layers.
- Machine Learning model: a `RandomForestClassifier` from scikit-learn.
- Final ensemble model: a `LogisticRegression` meta-classifier that combines
  the outputs of the neural network and Random Forest.

- Neural Network to learn complex hidden patterns in network traffic.
- Random Forest to make strong and stable classifications.
- Logistic Regression to combine both model outputs and make the final decision.

So this IDS works like a small team:

The neural network understands complex patterns, the Random Forest gives a reliable second opinion, and Logistic Regression acts like the judge that makes the final decision.

## Why These Models Were Chosen

- Neural network: good for learning complex non-linear patterns from network
  traffic features and for producing higher-level learned features.
- Random Forest: strong and reliable on tabular data, handles mixed feature
  importance well, and gives fast, practical performance.
- Logistic Regression meta-classifier: lightweight and effective for combining
  probability outputs from multiple models into one final prediction.

In short, the neural network is used for deep feature learning, the Random
Forest adds a strong classical ML view of the same traffic, and the Logistic
Regression layer combines both to improve final classification stability.

## How Efficiency Is Measured

In this project, efficiency is measured in two ways: runtime performance and
model effectiveness.

- Capture speed: the GUI calculates live packet speed as captured packets since
  the last update divided by elapsed time, shown as packets per second.
- Average processing time: the background predictor measures how long each
  prediction batch takes and keeps the average of recent batches.
- Speed selector: the prediction worker changes batch size based on the selected
  mode, where `Fast = 32`, `Balanced = 16`, and `Detailed = 8` packets per
  batch.
- Live efficiency: the app  measures runtime efficiency as
  `Processed / Received × 100`, shown as a percentage in the GUI.
- Processing speed: the Performance tab shows an approximate processing rate
  using `1 / average processing time`.
- Queue size: the queue shows how many packets are waiting for prediction. A
  low queue means the system is keeping up with live traffic.
- Model effectiveness: during training, the project checks validation accuracy
  for the Random Forest and the final Logistic Regression meta-classifier.

In simple terms, the project is considered efficient when it can capture and
process packets quickly, keep the queue small, and still maintain good
classification accuracy.


## Run On macOS

Packet capture needs root permission on macOS. Start the app from Terminal:

```bash
cd /Users/muneeb/Downloads/IDS
./run_macos.sh
```

Then:

1. Select interface `en0`.
2. Leave the filter blank for the demo.
3. Click `Start Capture`.
4. Generate traffic by opening a website or running `ping -4 8.8.8.8`.

## Interface Names Explained

On macOS, names like `en0` and `lo0` are network interfaces:

- `en0`: the main Wi-Fi interface. Use this for normal internet or LAN
  traffic.
- `lo0`: the loopback interface for `localhost` or `127.0.0.1`. Use this when
  you generate traffic on the same machine, such as a local Nmap scan.
- `en1`, `en2`, `en3`: other hardware interfaces such as Thunderbolt network
  adapters.
- `utun*`: VPN or tunnel interfaces, usually not needed for a basic IDS demo.

For this project, `en0` is best for browsing, `ping`, or normal network
traffic, while `lo0` is best for local testing against my own Mac.

## Manual Setup

If the `.venv` folder is missing, recreate it:

```bash
cd /Users/muneeb/Downloads/IDS
/opt/homebrew/bin/python3.13 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt
```

Then run:

```bash
./run_macos.sh
```

## How The Live Pipeline Works

```Network interface
    -> packet_sniffer.py
    -> optimized_sniffer_gui.py
    -> async_predictor.py
    -> hybrid_model.py
    -> GUI table + live log
```

The GUI thread stays responsive because packet prediction runs in a background
thread. New packets are queued, processed in batches, then sent back to the GUI.

## Optional Nmap Demo

Nmap is not used for packet capture. It is a scanner that can generate
reconnaissance traffic for a controlled demo. The IDS captures that traffic with
Scapy and can flag repeated multi-port probing as `Recon`.

Only scan systems you own or have permission to test. For a local demo, install
Nmap separately. To scan the same Mac, select `lo0` in the app and run:

```bash
brew install nmap
nmap -p 1-100 127.0.0.1
```

To capture scans on `en0`, run Nmap from another device you own on the same
network and target this Mac's local IP address.

## Future Improvements

- Add flow-level feature extraction so predictions match the training dataset
  more closely.
- Add firewall blocking to turn IDS behavior into IPS behavior.
- Add confidence display in the packet table.
- Add export buttons for reports and captured packets.
- Retrain and validate the model with traffic captured from the target network.


## Known Limitations

- The app detects attacks but does not block them.
- Live feature extraction is simplified compared with the full training dataset.
- Some attack labels may be false positives, especially on normal local network
  traffic.
- This folder is now a trimmed runtime package. The large training dataset,
  training script, old Windows environments, old logs, and unused helper files
  were removed because they are not needed to run the live IDS demo.
