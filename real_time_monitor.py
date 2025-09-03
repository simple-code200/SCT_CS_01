import pandas as pd
import numpy as np
import time
import threading
import queue
from datetime import datetime
import logging
from scapy.all import sniff, IP, TCP, UDP, ICMP
from keras.models import load_model
import joblib
import pickle
import warnings
warnings.filterwarnings('ignore')

# Configure logging
logging.basicConfig(
    filename='network_monitor.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

class RealTimeNetworkMonitor:
    def __init__(self, model_path="best_cnn_model.h5",
                 scaler_path="scaler_cnn_final.pkl",
                 label_encoder_path="label_encoder_cnn_final.pkl",
                 alerts_list=None):
        """Initialize the real-time network monitor"""
        print("Initializing Real-Time Network Monitor...")

        # Load trained model and preprocessing objects
        try:
            self.model = load_model(model_path)
            self.scaler = pickle.load(open(scaler_path, "rb"))
            self.label_encoder = pickle.load(open(label_encoder_path, "rb"))
            print("✅ Model and preprocessing objects loaded successfully!")
        except FileNotFoundError as e:
            print(f"❌ Error loading model files: {e}")
            print("Please ensure the model files exist from training.")
            return

        self.alerts_list = alerts_list

        # Packet processing queue
        self.packet_queue = queue.Queue(maxsize=1000)

        # Monitoring statistics
        self.stats = {
            'total_packets': 0,
            'benign_packets': 0,
            'attack_packets': 0,
            'alerts': 0,
            'start_time': datetime.now()
        }

        # Feature columns (same as training)
        self.feature_columns = [
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
            ' Fwd Header Length.1', 'Fwd Avg Bytes/Bulk', ' Fwd Avg Packets/Bulk', ' Fwd Avg Bulk Rate',
            ' Bwd Avg Bytes/Bulk', ' Bwd Avg Packets/Bulk', 'Bwd Avg Bulk Rate', 'Subflow Fwd Packets',
            ' Subflow Fwd Bytes', ' Subflow Bwd Packets', ' Subflow Bwd Bytes', 'Init_Win_bytes_forward',
            ' Init_Win_bytes_backward', ' act_data_pkt_fwd', ' min_seg_size_forward', 'Active Mean',
            ' Active Std', ' Active Max', ' Active Min', 'Idle Mean', ' Idle Std', ' Idle Max', ' Idle Min'
        ]

        # Flow tracking for connection-based features
        self.active_flows = {}

        # Alert thresholds
        self.alert_threshold = 0.8  # Confidence threshold for alerts

        print("Real-Time Network Monitor initialized successfully!")

    def extract_packet_features(self, packet):
        """Extract features from a single packet"""
        features = {}

        try:
            if IP in packet:
                # Basic IP features
                features['source_ip'] = packet[IP].src
                features[' Destination Port'] = packet[IP].dport if hasattr(packet[IP], 'dport') else 0
                features[' Total Fwd Packets'] = 1
                features[' Total Backward Packets'] = 0
                features['Total Length of Fwd Packets'] = len(packet)
                features[' Total Length of Bwd Packets'] = 0

                # Packet length features
                features[' Fwd Packet Length Max'] = len(packet)
                features[' Fwd Packet Length Min'] = len(packet)
                features[' Fwd Packet Length Mean'] = len(packet)
                features[' Fwd Packet Length Std'] = 0
                features['Bwd Packet Length Max'] = 0
                features[' Bwd Packet Length Min'] = 0
                features[' Bwd Packet Length Mean'] = 0
                features[' Bwd Packet Length Std'] = 0

                # Flow features (simplified for real-time)
                features[' Flow Duration'] = 1
                features['Flow Bytes/s'] = len(packet)
                features[' Flow Packets/s'] = 1

                # IAT features (simplified)
                features[' Flow IAT Mean'] = 0
                features[' Flow IAT Std'] = 0
                features[' Flow IAT Max'] = 0
                features[' Flow IAT Min'] = 0

                # Flag counts
                if TCP in packet:
                    features[' SYN Flag Count'] = 1 if packet[TCP].flags & 0x02 else 0
                    features[' ACK Flag Count'] = 1 if packet[TCP].flags & 0x10 else 0
                    features[' PSH Flag Count'] = 1 if packet[TCP].flags & 0x08 else 0
                    features[' RST Flag Count'] = 1 if packet[TCP].flags & 0x04 else 0
                    features[' FIN Flag Count'] = 1 if packet[TCP].flags & 0x01 else 0
                    features[' URG Flag Count'] = 1 if packet[TCP].flags & 0x20 else 0
                else:
                    features[' SYN Flag Count'] = 0
                    features[' ACK Flag Count'] = 0
                    features[' PSH Flag Count'] = 0
                    features[' RST Flag Count'] = 0
                    features[' FIN Flag Count'] = 0
                    features[' URG Flag Count'] = 0

                # Other flags (simplified)
                features[' CWE Flag Count'] = 0
                features[' ECE Flag Count'] = 0
                features[' Fwd PSH Flags'] = features[' PSH Flag Count']
                features[' Bwd PSH Flags'] = 0
                features[' Fwd URG Flags'] = features[' URG Flag Count']
                features[' Bwd URG Flags'] = 0

                # Header lengths
                features[' Fwd Header Length'] = 20  # IP header
                features[' Bwd Header Length'] = 0
                features[' Fwd Header Length.1'] = features[' Fwd Header Length']

                # Packet rates
                features['Fwd Packets/s'] = 1
                features[' Bwd Packets/s'] = 0

                # Packet length statistics
                features[' Min Packet Length'] = len(packet)
                features[' Max Packet Length'] = len(packet)
                features[' Packet Length Mean'] = len(packet)
                features[' Packet Length Std'] = 0
                features[' Packet Length Variance'] = 0

                # Ratios
                features[' Down/Up Ratio'] = 0
                features[' Average Packet Size'] = len(packet)
                features[' Avg Fwd Segment Size'] = len(packet)
                features[' Avg Bwd Segment Size'] = 0

                # Bulk features (simplified)
                features['Fwd Avg Bytes/Bulk'] = 0
                features[' Fwd Avg Packets/Bulk'] = 0
                features[' Fwd Avg Bulk Rate'] = 0
                features[' Bwd Avg Bytes/Bulk'] = 0
                features[' Bwd Avg Packets/Bulk'] = 0
                features['Bwd Avg Bulk Rate'] = 0

                # Subflow features
                features['Subflow Fwd Packets'] = 1
                features[' Subflow Fwd Bytes'] = len(packet)
                features[' Subflow Bwd Packets'] = 0
                features[' Subflow Bwd Bytes'] = 0

                # Window features
                features['Init_Win_bytes_forward'] = 0
                features[' Init_Win_bytes_backward'] = 0

                # Data packet features
                features[' act_data_pkt_fwd'] = 1
                features[' min_seg_size_forward'] = 0

                # Active/Idle features (simplified)
                features['Active Mean'] = 0
                features[' Active Std'] = 0
                features[' Active Max'] = 0
                features[' Active Min'] = 0
                features['Idle Mean'] = 0
                features[' Idle Std'] = 0
                features[' Idle Max'] = 0
                features[' Idle Min'] = 0

        except Exception as e:
            logging.error(f"Error extracting features from packet: {e}")
            return None

        return features

    def preprocess_features(self, features):
        """Preprocess features for model prediction"""
        try:
            # Create DataFrame with all required columns
            df = pd.DataFrame([features])

            # Ensure all required columns exist
            for col in self.feature_columns:
                if col not in df.columns:
                    df[col] = 0

            # Reorder columns to match training
            df = df[self.feature_columns]

            # Handle missing values and infinite values
            df = df.replace([np.inf, -np.inf], np.nan)
            df = df.fillna(0)

            # Scale features
            df_scaled = self.scaler.transform(df)

            # Reshape for CNN
            df_reshaped = df_scaled.reshape(df_scaled.shape[0], df_scaled.shape[1], 1)

            return df_reshaped

        except Exception as e:
            logging.error(f"Error preprocessing features: {e}")
            return None

    def classify_packet(self, features):
        """Classify a packet using the CNN model"""
        try:
            # Preprocess features
            processed_features = self.preprocess_features(features)
            if processed_features is None:
                return None, 0.0

            # Make prediction
            predictions = self.model.predict(processed_features, verbose=0)
            predicted_class_idx = np.argmax(predictions[0])
            confidence = np.max(predictions[0])

            # Convert to original label
            predicted_label = self.label_encoder.inverse_transform([predicted_class_idx])[0]

            return predicted_label, confidence

        except Exception as e:
            logging.error(f"Error classifying packet: {e}")
            return None, 0.0

    def packet_callback(self, packet):
        """Callback function for packet capture"""
        try:
            # Extract features
            features = self.extract_packet_features(packet)
            if features is None:
                return

            # Add to processing queue
            if not self.packet_queue.full():
                self.packet_queue.put(features)
            else:
                logging.warning("Packet queue is full, dropping packet")

        except Exception as e:
            logging.error(f"Error in packet callback: {e}")

    def process_packets(self):
        """Process packets from the queue"""
        while True:
            try:
                # Get packet from queue
                if not self.packet_queue.empty():
                    features = self.packet_queue.get(timeout=1)

                    # Classify packet
                    predicted_label, confidence = self.classify_packet(features)

                    if predicted_label is not None:
                        # Update statistics
                        self.stats['total_packets'] += 1

                        if predicted_label == 'BENIGN':
                            self.stats['benign_packets'] += 1
                        else:
                            self.stats['attack_packets'] += 1

                        # Check for alerts
                        if confidence > self.alert_threshold and predicted_label != 'BENIGN':
                            self.generate_alert(predicted_label, confidence, features)

                        # Log classification
                        logging.info(f"Packet classified as: {predicted_label} (confidence: {confidence:.4f})")

                else:
                    time.sleep(0.1)  # Small delay when queue is empty

            except Exception as e:
                logging.error(f"Error processing packet: {e}")

    def generate_alert(self, attack_type, confidence, features):
        """Generate an alert for detected attack"""
        self.stats['alerts'] += 1

        alert = {
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'attack_type': attack_type,
            'confidence': confidence,
            'details': f"Source IP: {features.get('source_ip', 'Unknown')}, Destination Port: {features.get(' Destination Port', 'Unknown')}, Packet Length: {features.get('Total Length of Fwd Packets', 'Unknown')}"
        }

        if self.alerts_list is not None:
            self.alerts_list.append(alert)

        alert_msg = f"""
🚨 NETWORK INTRUSION ALERT 🚨
Time: {alert['timestamp']}
Attack Type: {attack_type}
Confidence: {confidence:.4f}
{alert['details']}
"""

        print(alert_msg)
        logging.warning(f"ALERT: {attack_type} detected with confidence {confidence:.4f}")

        # Here you could add email notifications, database logging, etc.

    def display_stats(self):
        """Display monitoring statistics"""
        runtime = datetime.now() - self.stats['start_time']
        print(f"\n{'='*50}")
        print("NETWORK MONITORING STATISTICS")
        print(f"{'='*50}")
        print(f"Runtime: {runtime}")
        print(f"Total Packets Processed: {self.stats['total_packets']}")
        print(f"Benign Packets: {self.stats['benign_packets']}")
        print(f"Attack Packets: {self.stats['attack_packets']}")
        print(f"Alerts Generated: {self.stats['alerts']}")
        if self.stats['total_packets'] > 0:
            benign_pct = (self.stats['benign_packets'] / self.stats['total_packets']) * 100
            attack_pct = (self.stats['attack_packets'] / self.stats['total_packets']) * 100
            print(f"Benign Packets Percentage: {benign_pct:.1f}%")
            print(f"Attack Packets Percentage: {attack_pct:.1f}%")

        print(f"{'='*50}\n")

    def start_monitoring(self, interface=None, duration=None):
        """Start real-time network monitoring"""
        print("Starting Real-Time Network Monitoring...")
        print("Press Ctrl+C to stop monitoring")

        # Start packet processing thread
        processor_thread = threading.Thread(target=self.process_packets, daemon=True)
        processor_thread.start()

        # Start packet capture
        try:
            if interface:
                print(f"Monitoring interface: {interface}")
                sniff(iface=interface, prn=self.packet_callback, store=0, timeout=duration)
            else:
                print("Monitoring default interface")
                sniff(prn=self.packet_callback, store=0, timeout=duration)

        except KeyboardInterrupt:
            print("\nStopping monitoring...")
        except Exception as e:
            print(f"Error during monitoring: {e}")
        finally:
            self.display_stats()

def main():
    """Main function for real-time monitoring"""
    print("=== Real-Time Network Intrusion Detection Monitor ===\n")

    # Initialize monitor
    monitor = RealTimeNetworkMonitor()

    if monitor.model is None:
        return

    # Get monitoring parameters
    interface = input("Enter network interface to monitor (press Enter for default): ").strip()
    if not interface:
        interface = None

    duration_input = input("Enter monitoring duration in seconds (press Enter for continuous): ").strip()
    duration = int(duration_input) if duration_input else None

    # Start monitoring
    monitor.start_monitoring(interface=interface, duration=duration)

if __name__ == "__main__":
    main()
