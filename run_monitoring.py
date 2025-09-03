#!/usr/bin/env python3
"""
Network Intrusion Detection - Real-Time Monitoring System
Main entry point for running the monitoring system
"""

import argparse
import sys
import os
import json
from pathlib import Path

def check_requirements():
    """Check if required files exist"""
    required_files = [
        "best_cnn_model.h5",
        "scaler_cnn_final.pkl",
        "label_encoder_cnn_final.pkl",
        "config_monitoring.json"
    ]

    missing_files = []
    for file in required_files:
        if not Path(file).exists():
            missing_files.append(file)

    if missing_files:
        print("❌ Missing required files:")
        for file in missing_files:
            print(f"   - {file}")
        print("\nPlease ensure you have trained the model first by running:")
        print("   python train_network_intrusion_cnn.py")
        return False

    print("✅ All required files found!")
    return True

def load_config():
    """Load configuration from JSON file"""
    try:
        with open('config_monitoring.json', 'r') as f:
            config = json.load(f)
        print("✅ Configuration loaded successfully!")
        return config
    except FileNotFoundError:
        print("❌ Configuration file not found!")
        return None
    except json.JSONDecodeError:
        print("❌ Invalid JSON configuration!")
        return None

def run_dashboard():
    """Run the web dashboard"""
    print("🚀 Starting Network Intrusion Detection Dashboard...")
    try:
        from monitoring_dashboard import app, socketio
        config = load_config()
        if config:
            host = config['dashboard']['host']
            port = config['dashboard']['port']
            debug = config['dashboard']['debug']

            print(f"📊 Dashboard will be available at: http://{host}:{port}")
            print("Press Ctrl+C to stop the dashboard")

            socketio.run(app, host=host, port=port, debug=debug)
        else:
            print("❌ Failed to load configuration")
    except ImportError as e:
        print(f"❌ Import error: {e}")
        print("Please install required packages:")
        print("   pip install -r requirements_monitoring.txt")
    except Exception as e:
        print(f"❌ Error starting dashboard: {e}")

def run_cli_monitor():
    """Run the command-line monitoring"""
    print("🔍 Starting Command-Line Network Monitor...")
    try:
        from real_time_monitor import main as monitor_main
        monitor_main()
    except ImportError as e:
        print(f"❌ Import error: {e}")
        print("Please install required packages:")
        print("   pip install -r requirements_monitoring.txt")
    except Exception as e:
        print(f"❌ Error starting monitor: {e}")

def run_training():
    """Run the model training"""
    print("🎯 Starting CNN Model Training...")
    try:
        from train_network_intrusion_cnn import main as train_main
        train_main()
    except ImportError as e:
        print(f"❌ Import error: {e}")
        print("Please install required packages:")
        print("   pip install -r requirements_cnn.txt")
    except Exception as e:
        print(f"❌ Error during training: {e}")

def show_menu():
    """Show the main menu"""
    print("\n" + "="*60)
    print("🛡️  NETWORK INTRUSION DETECTION SYSTEM")
    print("="*60)
    print("1. 🚀 Start Web Dashboard")
    print("2. 🔍 Start CLI Monitor")
    print("3. 🎯 Train CNN Model")
    print("4. 📋 Show System Status")
    print("5. ❌ Exit")
    print("="*60)

def show_status():
    """Show system status"""
    print("\n" + "="*50)
    print("SYSTEM STATUS")
    print("="*50)

    # Check required files
    files_status = {
        "best_cnn_model.h5": Path("best_cnn_model.h5").exists(),
        "scaler_cnn_final.pkl": Path("scaler_cnn_final.pkl").exists(),
        "label_encoder_cnn_final.pkl": Path("label_encoder_cnn_final.pkl").exists(),
        "config_monitoring.json": Path("config_monitoring.json").exists(),
        "network_attacks.csv": Path("network_attacks.csv").exists()
    }

    print("📁 Required Files:")
    for file, exists in files_status.items():
        status = "✅" if exists else "❌"
        print(f"   {status} {file}")

    # Check Python packages
    try:
        import tensorflow as tf
        print(f"   ✅ TensorFlow {tf.__version__}")
    except ImportError:
        print("   ❌ TensorFlow not installed")

    try:
        import scapy
        print(f"   ✅ Scapy {scapy.__version__}")
    except ImportError:
        print("   ❌ Scapy not installed")

    try:
        import flask
        print(f"   ✅ Flask {flask.__version__}")
    except ImportError:
        print("   ❌ Flask not installed")

    print("\n💡 Tips:")
    print("   - Install monitoring packages: pip install -r requirements_monitoring.txt")
    print("   - Install training packages: pip install -r requirements_cnn.txt")
    print("   - Train model first before monitoring")
    print("="*50)

def main():
    """Main function"""
    parser = argparse.ArgumentParser(description='Network Intrusion Detection System')
    parser.add_argument('--dashboard', action='store_true', help='Start web dashboard directly')
    parser.add_argument('--monitor', action='store_true', help='Start CLI monitor directly')
    parser.add_argument('--train', action='store_true', help='Train model directly')

    args = parser.parse_args()

    # Direct execution based on arguments
    if args.dashboard:
        if check_requirements():
            run_dashboard()
        return
    elif args.monitor:
        if check_requirements():
            run_cli_monitor()
        return
    elif args.train:
        run_training()
        return

    # Interactive menu
    while True:
        show_menu()
        try:
            choice = input("Enter your choice (1-5): ").strip()

            if choice == '1':
                if check_requirements():
                    run_dashboard()
                else:
                    input("Press Enter to continue...")
            elif choice == '2':
                if check_requirements():
                    run_cli_monitor()
                else:
                    input("Press Enter to continue...")
            elif choice == '3':
                run_training()
                input("Press Enter to continue...")
            elif choice == '4':
                show_status()
                input("Press Enter to continue...")
            elif choice == '5':
                print("👋 Goodbye!")
                sys.exit(0)
            else:
                print("❌ Invalid choice. Please enter 1-5.")
                input("Press Enter to continue...")

        except KeyboardInterrupt:
            print("\n👋 Goodbye!")
            sys.exit(0)
        except Exception as e:
            print(f"❌ Error: {e}")
            input("Press Enter to continue...")

if __name__ == "__main__":
    main()
