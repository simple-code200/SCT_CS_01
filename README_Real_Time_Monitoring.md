# 🛡️ Real-Time Network Intrusion Detection System

A comprehensive network intrusion detection system using Convolutional Neural Networks (CNN) for real-time traffic analysis and monitoring.

## 📋 Table of Contents

- [Features](#features)
- [System Architecture](#system-architecture)
- [Installation](#installation)
- [Usage](#usage)
- [Configuration](#configuration)
- [Training](#training)
- [Monitoring](#monitoring)
- [Dashboard](#dashboard)
- [API Reference](#api-reference)
- [Troubleshooting](#troubleshooting)

## ✨ Features

- **CNN-based Classification**: Deep learning model for accurate network traffic classification
- **Real-time Monitoring**: Live packet capture and analysis
- **Web Dashboard**: Interactive monitoring interface with real-time charts
- **Alert System**: Automated alerts for detected intrusions
- **Multiple Interfaces**: Command-line and web-based monitoring options
- **Comprehensive Logging**: Detailed logging of all activities and detections
- **Configurable**: Highly configurable system parameters
- **Cross-platform**: Works on Windows, Linux, and macOS

## 🏗️ System Architecture

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Packet        │    │   Feature       │    │   CNN Model     │
│   Capture       │───▶│   Extraction    │───▶│   Classification│
│   (Scapy)       │    │   Engine        │    │   Engine        │
└─────────────────┘    └─────────────────┘    └─────────────────┘
         │                       │                       │
         ▼                       ▼                       ▼
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Real-time     │    │   Alert         │    │   Dashboard     │
│   Analysis      │    │   Generation    │    │   Interface     │
│   Engine        │    │   System        │    │   (Flask)       │
└─────────────────┘    └─────────────────┘    └─────────────────┘
```

## 🚀 Installation

### Prerequisites

- Python 3.8 or higher
- Administrative privileges (for packet capture)
- Network interface access

### Step 1: Clone and Setup

```bash
# Install Python dependencies for CNN training
pip install -r requirements_cnn.txt

# Install dependencies for real-time monitoring
pip install -r requirements_monitoring.txt
```

### Step 2: Train the Model

```bash
# Train the CNN model
python run_monitoring.py --train

# Or use the training script directly
python train_network_intrusion_cnn.py
```

### Step 3: Verify Installation

```bash
# Check system status
python run_monitoring.py --status
```

## 📖 Usage

### Quick Start

```bash
# Run the main monitoring system
python run_monitoring.py
```

This will show an interactive menu with options to:
1. Start Web Dashboard
2. Start CLI Monitor
3. Train CNN Model
4. Show System Status
5. Exit

### Command Line Options

```bash
# Start web dashboard directly
python run_monitoring.py --dashboard

# Start CLI monitor directly
python run_monitoring.py --monitor

# Train model directly
python run_monitoring.py --train
```

## ⚙️ Configuration

The system uses `config_monitoring.json` for configuration:

```json
{
  "model": {
    "model_path": "best_cnn_model.h5",
    "scaler_path": "scaler_cnn_final.pkl",
    "label_encoder_path": "label_encoder_cnn_final.pkl"
  },
  "monitoring": {
    "interface": null,
    "duration": null,
    "alert_threshold": 0.8,
    "max_queue_size": 1000,
    "update_interval": 2
  },
  "dashboard": {
    "host": "0.0.0.0",
    "port": 5000,
    "debug": false
  }
}
```

### Configuration Parameters

- **model**: Paths to trained model files
- **monitoring**: Packet capture and analysis settings
- **dashboard**: Web interface configuration
- **alerts**: Alert system configuration (email, etc.)

## 🎯 Training

### Dataset Preparation

The system expects a CSV file `network_attacks.csv` with network traffic features and labels.

### Training Process

```python
from train_network_intrusion_cnn import main
main()
```

### Training Features

- Automatic data cleaning and preprocessing
- Feature scaling and normalization
- Class imbalance handling with weighted loss
- Early stopping and model checkpointing
- Comprehensive evaluation metrics
- Training history visualization

## 🔍 Monitoring

### Command Line Monitoring

```bash
python run_monitoring.py --monitor
```

Features:
- Real-time packet capture and analysis
- Live statistics display
- Alert generation for suspicious traffic
- Comprehensive logging

### Network Interface Selection

```python
# Monitor specific interface
monitor = RealTimeNetworkMonitor()
monitor.start_monitoring(interface="eth0")

# Monitor for specific duration
monitor.start_monitoring(duration=300)  # 5 minutes
```

## 📊 Dashboard

### Starting the Dashboard

```bash
python run_monitoring.py --dashboard
```

Access the dashboard at: http://localhost:5000

### Dashboard Features

- **Real-time Statistics**: Live packet counts and classifications
- **Traffic Charts**: Visual representation of benign vs attack traffic
- **Alert Panel**: Recent security alerts with details
- **Interactive Controls**: Start/stop monitoring, clear alerts
- **Responsive Design**: Works on desktop and mobile devices

### Dashboard Components

1. **Statistics Cards**
   - Total packets processed
   - Benign traffic count
   - Attack traffic count
   - Alert count

2. **Charts**
   - Traffic classification pie chart
   - Attack types distribution bar chart

3. **Alerts Panel**
   - Real-time alert notifications
   - Alert history with timestamps
   - Alert details and confidence scores

## 🔧 API Reference

### RealTimeNetworkMonitor Class

```python
class RealTimeNetworkMonitor:
    def __init__(self, model_path, scaler_path, label_encoder_path)
    def start_monitoring(self, interface=None, duration=None)
    def extract_packet_features(self, packet)
    def classify_packet(self, features)
    def generate_alert(self, attack_type, confidence, features)
```

### Key Methods

- `start_monitoring()`: Begin packet capture and analysis
- `extract_packet_features()`: Extract features from network packets
- `classify_packet()`: Classify packet using CNN model
- `generate_alert()`: Create alert for detected intrusion

## 🛠️ Troubleshooting

### Common Issues

1. **Permission Denied for Packet Capture**
   ```bash
   # Run with sudo (Linux/Mac)
   sudo python run_monitoring.py --monitor

   # Or run as administrator (Windows)
   ```

2. **Missing Model Files**
   ```bash
   # Train the model first
   python run_monitoring.py --train
   ```

3. **Import Errors**
   ```bash
   # Install required packages
   pip install -r requirements_monitoring.txt
   pip install -r requirements_cnn.txt
   ```

4. **Network Interface Issues**
   ```python
   # List available interfaces
   from scapy.all import get_if_list
   print(get_if_list())
   ```

### Performance Optimization

- Use GPU for model inference if available
- Adjust batch size for packet processing
- Configure appropriate alert thresholds
- Monitor system resources during operation

### Logging

All activities are logged to `network_monitor.log`:

```
2024-01-15 10:30:15 - INFO - Packet classified as: BENIGN (confidence: 0.95)
2024-01-15 10:30:16 - WARNING - ALERT: DoS Hulk detected with confidence 0.89
```

## 📈 Performance Metrics

### Model Performance (Test Set)

- **Accuracy**: ~70%
- **Precision**: 0.70
- **Recall**: 0.70
- **F1-Score**: 0.70

### Supported Attack Types

- BENIGN (Normal traffic)
- DoS Hulk
- FTP-Patator
- Infiltration
- PortScan
- SSH-Patator
- Web Attack

## 🔒 Security Considerations

- Run with minimal required privileges
- Monitor system resource usage
- Regularly update model with new threat patterns
- Implement proper logging and alerting
- Use secure communication for remote monitoring

## 📝 License

This project is open source and available under the MIT License.

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## 📞 Support

For issues and questions:
1. Check the troubleshooting section
2. Review the logs in `network_monitor.log`
3. Open an issue on GitHub

---

**Happy Monitoring! 🛡️**
