import streamlit as st
import pandas as pd
import numpy as np
import joblib
import time
import os
from scapy.all import AsyncSniffer
from tensorflow.keras.models import load_model

# Load CNN model and preprocessing objects
try:
    model = load_model("cnn_network_intrusion_final.h5")
    scaler = joblib.load("scaler_cnn_final.pkl")
    label_encoder = joblib.load("label_encoder_cnn_final.pkl")
    st.success("✅ CNN Model loaded successfully!")
except FileNotFoundError:
    st.error("❌ CNN model files not found. Please run training first.")
    st.stop()

# Feature list (expanded for better CNN performance)
features = [
    ' Destination Port', ' Flow Duration', ' Total Fwd Packets', ' Total Backward Packets',
    'Total Length of Fwd Packets', ' Total Length of Bwd Packets', ' Fwd Packet Length Max',
    ' Fwd Packet Length Min', ' Fwd Packet Length Mean', ' Fwd Packet Length Std',
    'Bwd Packet Length Max', ' Bwd Packet Length Min', ' Bwd Packet Length Mean',
    ' Bwd Packet Length Std', 'Flow Bytes/s', ' Flow Packets/s', ' Flow IAT Mean',
    ' Flow IAT Std', ' Flow IAT Max', ' Flow IAT Min', 'Fwd IAT Total', ' Fwd IAT Mean',
    ' Fwd IAT Std', ' Fwd IAT Max', ' Fwd IAT Min', 'Bwd IAT Total', ' Bwd IAT Mean',
    ' Bwd IAT Std', ' Bwd IAT Max', ' Bwd IAT Min', 'Fwd PSH Flags', ' Bwd PSH Flags',
    ' Fwd URG Flags', ' Bwd URG Flags', ' Fwd Header Length', ' Bwd Header Length',
    'Fwd Packets/s', ' Bwd Packets/s', ' Min Packet Length', ' Max Packet Length',
    ' Packet Length Mean', ' Packet Length Std', ' Packet Length Variance', 'FIN Flag Count',
    ' SYN Flag Count', ' RST Flag Count', ' PSH Flag Count', ' ACK Flag Count',
    ' URG Flag Count', ' CWE Flag Count', ' ECE Flag Count', ' Down/Up Ratio',
    ' Average Packet Size', ' Avg Fwd Segment Size', ' Avg Bwd Segment Size',
    ' Fwd Header Length.1', 'Fwd Avg Bytes/Bulk', ' Fwd Avg Packets/Bulk',
    ' Fwd Avg Bulk Rate', ' Bwd Avg Bytes/Bulk', ' Bwd Avg Packets/Bulk',
    'Bwd Avg Bulk Rate', 'Subflow Fwd Packets', ' Subflow Fwd Bytes',
    ' Subflow Bwd Packets', ' Subflow Bwd Bytes', 'Init_Win_bytes_forward',
    ' Init_Win_bytes_backward', ' act_data_pkt_fwd', ' min_seg_size_forward',
    'Active Mean', ' Active Std', ' Active Max', ' Active Min', 'Idle Mean',
    ' Idle Std', ' Idle Max', ' Idle Min'
]

# Global variables for live monitoring
live_sniffer = None
monitoring_active = False
packet_queue = []
attack_counts = {}
packet_count = 0

# Streamlit config
st.set_page_config(page_title="NIDS - CNN Based", layout="wide")
st.title("🛡️ CNN-Based Network Intrusion Detection System")

st.markdown("""
This app uses a **Convolutional Neural Network (CNN)** to detect **multiple types of network anomalies** in real-time.
The CNN model analyzes comprehensive network traffic features for accurate intrusion detection.

**Features:**
- 🧠 **CNN Model**: Deep learning-based classification
- 📡 **Real-time Monitoring**: Live packet capture and analysis
- 🎯 **Multi-class Detection**: Identifies various attack types
- 📊 **Live Statistics**: Real-time attack monitoring dashboard
- 🔍 **Comprehensive Features**: 78+ network traffic features analyzed
""")

# --- Sidebar: Display Attack Classes ---
st.sidebar.markdown("### 🧾 Detected Attack Types")
attack_classes = list(label_encoder.classes_)
for attack in attack_classes:
    st.sidebar.write(f"- {attack}")

# Initialize attack counts
attack_counts = {attack: 0 for attack in attack_classes}

# --- Prediction Function ---
def predict_attack(df):
    """CNN-based prediction function"""
    try:
        # Scale the features
        scaled = scaler.transform(df[features])

        # Reshape for CNN input: (samples, timesteps, channels)
        scaled_reshaped = scaled.reshape(scaled.shape[0], scaled.shape[1], 1)

        # Make prediction
        predictions_prob = model.predict(scaled_reshaped, verbose=0)

        # Get predicted classes
        predictions = np.argmax(predictions_prob, axis=1)

        # Convert back to original labels
        predicted_labels = label_encoder.inverse_transform(predictions)

        return predicted_labels
    except Exception as e:
        st.error(f"Prediction error: {e}")
        return ["Error"] * len(df)

# --- Packet Processing Functions ---
def extract_features_from_packet(packet):
    """Extract comprehensive features from a network packet for CNN analysis"""
    try:
        # Initialize all features with default values
        features_dict = {}

        # Basic packet information
        packet_len = len(packet) if hasattr(packet, '__len__') else 60

        # IP layer features
        if packet.haslayer('IP'):
            ip_layer = packet['IP']
            features_dict[' Destination Port'] = ip_layer.dport if hasattr(ip_layer, 'dport') else 80
            features_dict['Total Length of Fwd Packets'] = ip_layer.len if hasattr(ip_layer, 'len') else packet_len
            features_dict['Total Length of Bwd Packets'] = packet_len  # Simplified for single packet
        else:
            features_dict[' Destination Port'] = 80
            features_dict['Total Length of Fwd Packets'] = packet_len
            features_dict['Total Length of Bwd Packets'] = packet_len

        # TCP layer features
        if packet.haslayer('TCP'):
            tcp_layer = packet['TCP']

            # Packet counts and lengths
            features_dict[' Total Fwd Packets'] = 1
            features_dict[' Total Backward Packets'] = 0  # Simplified for single packet analysis
            features_dict[' Fwd Packet Length Max'] = packet_len
            features_dict[' Fwd Packet Length Min'] = packet_len
            features_dict[' Fwd Packet Length Mean'] = packet_len
            features_dict[' Fwd Packet Length Std'] = 0.0
            features_dict['Bwd Packet Length Max'] = packet_len
            features_dict[' Bwd Packet Length Min'] = packet_len
            features_dict[' Bwd Packet Length Mean'] = packet_len
            features_dict[' Bwd Packet Length Std'] = 0.0

            # Flow features
            features_dict[' Flow Duration'] = 10000  # Default flow duration
            features_dict['Flow Bytes/s'] = packet_len * 100  # Simplified calculation
            features_dict[' Flow Packets/s'] = 100.0  # Packets per second

            # IAT (Inter-Arrival Time) features
            features_dict[' Flow IAT Mean'] = 10000.0
            features_dict[' Flow IAT Std'] = 5000.0
            features_dict[' Flow IAT Max'] = 20000.0
            features_dict[' Flow IAT Min'] = 5000.0
            features_dict['Fwd IAT Total'] = 9000.0
            features_dict[' Fwd IAT Mean'] = 9000.0
            features_dict[' Fwd IAT Std'] = 3000.0
            features_dict[' Fwd IAT Max'] = 15000.0
            features_dict[' Fwd IAT Min'] = 3000.0
            features_dict['Bwd IAT Total'] = 1000.0
            features_dict[' Bwd IAT Mean'] = 1000.0
            features_dict[' Bwd IAT Std'] = 500.0
            features_dict[' Bwd IAT Max'] = 2000.0
            features_dict[' Bwd IAT Min'] = 500.0

            # TCP Flags
            flags = tcp_layer.flags
            features_dict['Fwd PSH Flags'] = 1 if flags & 0x08 else 0  # PSH flag
            features_dict[' Bwd PSH Flags'] = 0
            features_dict[' Fwd URG Flags'] = 1 if flags & 0x20 else 0  # URG flag
            features_dict[' Bwd URG Flags'] = 0
            features_dict[' Fwd Header Length'] = tcp_layer.dataofs * 4 if hasattr(tcp_layer, 'dataofs') else 20
            features_dict[' Bwd Header Length'] = 0
            features_dict['FIN Flag Count'] = 1 if flags & 0x01 else 0  # FIN flag
            features_dict[' SYN Flag Count'] = 1 if flags & 0x02 else 0  # SYN flag
            features_dict[' RST Flag Count'] = 1 if flags & 0x04 else 0  # RST flag
            features_dict[' PSH Flag Count'] = 1 if flags & 0x08 else 0  # PSH flag
            features_dict[' ACK Flag Count'] = 1 if flags & 0x10 else 0  # ACK flag
            features_dict[' URG Flag Count'] = 1 if flags & 0x20 else 0  # URG flag
            features_dict[' CWE Flag Count'] = 1 if flags & 0x40 else 0  # CWR flag
            features_dict[' ECE Flag Count'] = 1 if flags & 0x80 else 0  # ECE flag

            # Window size
            features_dict['Init_Win_bytes_forward'] = tcp_layer.window if hasattr(tcp_layer, 'window') else 8192
            features_dict[' Init_Win_bytes_backward'] = 8192  # Default for backward

        else:
            # Default values for non-TCP packets
            features_dict.update({
                ' Total Fwd Packets': 1,
                ' Total Backward Packets': 0,
                ' Fwd Packet Length Max': packet_len,
                ' Fwd Packet Length Min': packet_len,
                ' Fwd Packet Length Mean': packet_len,
                ' Fwd Packet Length Std': 0.0,
                'Bwd Packet Length Max': packet_len,
                ' Bwd Packet Length Min': packet_len,
                ' Bwd Packet Length Mean': packet_len,
                ' Bwd Packet Length Std': 0.0,
                ' Flow Duration': 10000,
                'Flow Bytes/s': packet_len * 100,
                ' Flow Packets/s': 100.0,
                ' Flow IAT Mean': 10000.0,
                ' Flow IAT Std': 5000.0,
                ' Flow IAT Max': 20000.0,
                ' Flow IAT Min': 5000.0,
                'Fwd IAT Total': 9000.0,
                ' Fwd IAT Mean': 9000.0,
                ' Fwd IAT Std': 3000.0,
                ' Fwd IAT Max': 15000.0,
                ' Fwd IAT Min': 3000.0,
                'Bwd IAT Total': 1000.0,
                ' Bwd IAT Mean': 1000.0,
                ' Bwd IAT Std': 500.0,
                ' Bwd IAT Max': 2000.0,
                ' Bwd IAT Min': 500.0,
                'Fwd PSH Flags': 0,
                ' Bwd PSH Flags': 0,
                ' Fwd URG Flags': 0,
                ' Bwd URG Flags': 0,
                ' Fwd Header Length': 20,
                ' Bwd Header Length': 0,
                'FIN Flag Count': 0,
                ' SYN Flag Count': 0,
                ' RST Flag Count': 0,
                ' PSH Flag Count': 0,
                ' ACK Flag Count': 0,
                ' URG Flag Count': 0,
                ' CWE Flag Count': 0,
                ' ECE Flag Count': 0,
                'Init_Win_bytes_forward': 8192,
                ' Init_Win_bytes_backward': 8192
            })

        # Additional features with default values
        features_dict.update({
            'Fwd Packets/s': 100.0,
            ' Bwd Packets/s': 0.0,
            ' Min Packet Length': packet_len,
            ' Max Packet Length': packet_len,
            ' Packet Length Mean': packet_len,
            ' Packet Length Std': 0.0,
            ' Packet Length Variance': 0.0,
            ' Down/Up Ratio': 1.0,
            ' Average Packet Size': packet_len,
            ' Avg Fwd Segment Size': packet_len,
            ' Avg Bwd Segment Size': packet_len,
            ' Fwd Header Length.1': features_dict.get(' Fwd Header Length', 20),
            'Fwd Avg Bytes/Bulk': 0,
            ' Fwd Avg Packets/Bulk': 0,
            ' Fwd Avg Bulk Rate': 0,
            ' Bwd Avg Bytes/Bulk': 0,
            ' Bwd Avg Packets/Bulk': 0,
            'Bwd Avg Bulk Rate': 0,
            'Subflow Fwd Packets': 1,
            ' Subflow Fwd Bytes': packet_len,
            ' Subflow Bwd Packets': 0,
            ' Subflow Bwd Bytes': 0,
            ' act_data_pkt_fwd': 1,
            ' min_seg_size_forward': 20,
            'Active Mean': 0.0,
            ' Active Std': 0.0,
            ' Active Max': 0.0,
            ' Active Min': 0.0,
            'Idle Mean': 0.0,
            ' Idle Std': 0.0,
            ' Idle Max': 0.0,
            ' Idle Min': 0.0
        })

        return features_dict

    except Exception as e:
        st.warning(f"Feature extraction error: {e}")
        # Return default values for all features if extraction fails
        return {feature: 0 for feature in features}

def packet_handler(packet):
    """Callback function for packet capture"""
    global packet_queue, packet_count
    packet_count += 1
    features = extract_features_from_packet(packet)
    packet_queue.append(features)

def start_live_monitoring():
    """Start live packet capture"""
    global live_sniffer, monitoring_active
    try:
        live_sniffer = AsyncSniffer(prn=packet_handler, store=False)
        live_sniffer.start()
        monitoring_active = True
        return True
    except Exception as e:
        st.error(f"❌ Failed to start live monitoring: {e}")
        return False

def stop_live_monitoring():
    """Stop live packet capture"""
    global live_sniffer, monitoring_active
    if live_sniffer:
        live_sniffer.stop()
        live_sniffer = None
    monitoring_active = False

# --- Real-Time Monitoring ---
st.markdown("## 📡 Real-Time Network Monitoring")

# Real-time monitoring controls
monitoring_status = st.selectbox("Monitoring Mode", ["Off", "Simulated", "Live"])

if monitoring_status == "Live":
    if not monitoring_active:
        if st.button("🚀 Start Live Monitoring", key="start_live"):
            if start_live_monitoring():
                st.success("✅ Live monitoring started successfully!")
            else:
                st.warning("⚠️ Packet capture requires admin privileges. Run as Administrator.")
    else:
        st.success("✅ Live monitoring is active")
        if st.button("🛑 Stop Live Monitoring", key="stop_live"):
            stop_live_monitoring()
            st.info("🛑 Live monitoring stopped")
            
        # Display current stats
        st.subheader("📊 Live Traffic Monitor")
        col1, col2 = st.columns(2)
        with col1:
            st.metric("Total Packets Captured", packet_count)
        with col2:
            st.metric("Packets in Queue", len(packet_queue))
        
        # Process some packets if available
        if packet_queue:
            processed = min(10, len(packet_queue))
            for i in range(processed):
                packet_features = packet_queue.pop(0)
                df_input = pd.DataFrame([packet_features])
                try:
                    pred = predict_attack(df_input)[0]
                    attack_counts[pred] += 1
                    st.write(f"Packet {i+1}: Predicted as {pred}")
                except Exception as e:
                    st.error(f"Prediction error: {e}")
            
            # Display attack statistics
            st.subheader("📈 Attack Statistics")
            attack_df = pd.DataFrame.from_dict(attack_counts, orient='index', columns=['Count'])
            attack_df = attack_df.sort_values('Count', ascending=False)
            st.dataframe(attack_df)

elif monitoring_status == "Simulated":
    st.info("🔍 Simulating real-time network traffic monitoring with CNN model...")

    # Simulate some packets with comprehensive features
    if st.button("📦 Generate Sample Packets", key="generate_packets"):
        for i in range(5):
            # Generate comprehensive simulated packet features
            packet_len = np.random.choice([64, 128, 256, 512, 1024, 1500])

            simulated_features = {
                ' Destination Port': np.random.choice([80, 443, 22, 21, 25, 53, 110, 143]),
                ' Flow Duration': np.random.uniform(1000, 100000),
                ' Total Fwd Packets': np.random.randint(1, 20),
                ' Total Backward Packets': np.random.randint(0, 15),
                'Total Length of Fwd Packets': np.random.uniform(100, 5000),
                ' Total Length of Bwd Packets': np.random.uniform(0, 3000),
                ' Fwd Packet Length Max': np.random.uniform(50, 1500),
                ' Fwd Packet Length Min': np.random.uniform(40, 100),
                ' Fwd Packet Length Mean': np.random.uniform(100, 800),
                ' Fwd Packet Length Std': np.random.uniform(10, 200),
                'Bwd Packet Length Max': np.random.uniform(0, 1500),
                ' Bwd Packet Length Min': np.random.uniform(0, 100),
                ' Bwd Packet Length Mean': np.random.uniform(0, 600),
                ' Bwd Packet Length Std': np.random.uniform(0, 150),
                'Flow Bytes/s': np.random.uniform(1000, 1000000),
                ' Flow Packets/s': np.random.uniform(10, 1000),
                ' Flow IAT Mean': np.random.uniform(1000, 50000),
                ' Flow IAT Std': np.random.uniform(500, 20000),
                ' Flow IAT Max': np.random.uniform(2000, 100000),
                ' Flow IAT Min': np.random.uniform(100, 5000),
                'Fwd IAT Total': np.random.uniform(500, 80000),
                ' Fwd IAT Mean': np.random.uniform(500, 40000),
                ' Fwd IAT Std': np.random.uniform(100, 15000),
                ' Fwd IAT Max': np.random.uniform(1000, 80000),
                ' Fwd IAT Min': np.random.uniform(50, 2000),
                'Bwd IAT Total': np.random.uniform(0, 60000),
                ' Bwd IAT Mean': np.random.uniform(0, 30000),
                ' Bwd IAT Std': np.random.uniform(0, 10000),
                ' Bwd IAT Max': np.random.uniform(0, 60000),
                ' Bwd IAT Min': np.random.uniform(0, 1000),
                'Fwd PSH Flags': np.random.choice([0, 1]),
                ' Bwd PSH Flags': np.random.choice([0, 1]),
                ' Fwd URG Flags': np.random.choice([0, 1]),
                ' Bwd URG Flags': np.random.choice([0, 1]),
                ' Fwd Header Length': np.random.choice([20, 24, 28, 32]),
                ' Bwd Header Length': np.random.choice([0, 20, 24, 28, 32]),
                'Fwd Packets/s': np.random.uniform(5, 500),
                ' Bwd Packets/s': np.random.uniform(0, 300),
                ' Min Packet Length': np.random.uniform(40, 80),
                ' Max Packet Length': np.random.uniform(200, 1500),
                ' Packet Length Mean': np.random.uniform(100, 700),
                ' Packet Length Std': np.random.uniform(20, 300),
                ' Packet Length Variance': np.random.uniform(400, 90000),
                'FIN Flag Count': np.random.choice([0, 1]),
                ' SYN Flag Count': np.random.choice([0, 1]),
                ' RST Flag Count': np.random.choice([0, 1]),
                ' PSH Flag Count': np.random.choice([0, 1, 2]),
                ' ACK Flag Count': np.random.choice([0, 1, 2]),
                ' URG Flag Count': np.random.choice([0, 1]),
                ' CWE Flag Count': np.random.choice([0, 1]),
                ' ECE Flag Count': np.random.choice([0, 1]),
                ' Down/Up Ratio': np.random.uniform(0.1, 5.0),
                ' Average Packet Size': np.random.uniform(80, 600),
                ' Avg Fwd Segment Size': np.random.uniform(80, 600),
                ' Avg Bwd Segment Size': np.random.uniform(0, 400),
                ' Fwd Header Length.1': np.random.choice([20, 24, 28, 32]),
                'Fwd Avg Bytes/Bulk': np.random.uniform(0, 100),
                ' Fwd Avg Packets/Bulk': np.random.uniform(0, 10),
                ' Fwd Avg Bulk Rate': np.random.uniform(0, 1000),
                ' Bwd Avg Bytes/Bulk': np.random.uniform(0, 100),
                ' Bwd Avg Packets/Bulk': np.random.uniform(0, 10),
                'Bwd Avg Bulk Rate': np.random.uniform(0, 1000),
                'Subflow Fwd Packets': np.random.randint(1, 15),
                ' Subflow Fwd Bytes': np.random.uniform(100, 4000),
                ' Subflow Bwd Packets': np.random.randint(0, 10),
                ' Subflow Bwd Bytes': np.random.uniform(0, 2000),
                'Init_Win_bytes_forward': np.random.choice([8192, 65535, 29200, 16384]),
                ' Init_Win_bytes_backward': np.random.choice([0, 8192, 65535, 29200]),
                ' act_data_pkt_fwd': np.random.randint(1, 10),
                ' min_seg_size_forward': np.random.choice([20, 24, 28, 32]),
                'Active Mean': np.random.uniform(0, 10000),
                ' Active Std': np.random.uniform(0, 5000),
                ' Active Max': np.random.uniform(0, 20000),
                ' Active Min': np.random.uniform(0, 5000),
                'Idle Mean': np.random.uniform(0, 50000),
                ' Idle Std': np.random.uniform(0, 20000),
                ' Idle Max': np.random.uniform(0, 100000),
                ' Idle Min': np.random.uniform(0, 10000)
            }

            random_input = pd.DataFrame([simulated_features])

            try:
                pred = predict_attack(random_input)[0]
                attack_counts[pred] += 1
                st.write(f"Simulated Packet {i+1}: Predicted as **{pred}**")
            except Exception as e:
                st.error(f"Prediction error for packet {i+1}: {e}")

        # Display attack statistics
        st.subheader("📈 Attack Statistics")
        attack_df = pd.DataFrame.from_dict(attack_counts, orient='index', columns=['Count'])
        attack_df = attack_df.sort_values('Count', ascending=False)
        st.dataframe(attack_df)

# Permission instructions
if monitoring_status == "Live":
    st.markdown("---")
    st.warning("⚠️ Live Packet Capture Permissions Required")
    st.info("To enable live packet capture, you need to:")
    if os.name == 'nt':  # Windows
        st.write("1. Close this application")
        st.write("2. Open Command Prompt as Administrator")
        st.write("3. Navigate to this directory")
        st.write("4. Run: `python -m streamlit run app.py`")
        st.code("Run as Administrator in Command Prompt:\npython -m streamlit run app.py")
    else:  # Linux/Mac
        st.write("1. Close this application")  
        st.write("2. Run with sudo privileges")
        st.code("sudo python -m streamlit run app.py")
