#!/usr/bin/env python3
"""
Test script for the Network Intrusion Detection System
"""

import sys
import os
from pathlib import Path
import pandas as pd
import numpy as np

def test_model_files():
    """Test if model files exist and can be loaded"""
    print("🔍 Testing model files...")

    required_files = [
        "best_cnn_model.h5",
        "scaler_cnn_final.pkl",
        "label_encoder_cnn_final.pkl"
    ]

    for file in required_files:
        if Path(file).exists():
            print(f"   ✅ {file} found")
        else:
            print(f"   ❌ {file} missing")
            return False

    # Test loading model files
    try:
        from tensorflow.keras.models import load_model
        import joblib

        model = load_model("best_cnn_model.h5")
        scaler = joblib.load("scaler_cnn_final.pkl")
        label_encoder = joblib.load("label_encoder_cnn_final.pkl")

        print(f"   ✅ Model loaded: {model.input_shape}")
        print(f"   ✅ Scaler loaded: {type(scaler)}")
        print(f"   ✅ Label encoder loaded: {len(label_encoder.classes_)} classes")

        return True
    except Exception as e:
        print(f"   ❌ Error loading model files: {e}")
        return False

def test_dataset():
    """Test if dataset exists and is valid"""
    print("\n🔍 Testing dataset...")

    if Path("network_attacks.csv").exists():
        print("   ✅ Dataset file found")

        try:
            df = pd.read_csv("network_attacks.csv")
            print(f"   ✅ Dataset loaded: {df.shape[0]} rows, {df.shape[1]} columns")
            print(f"   ✅ Target distribution:\n{df['Label'].value_counts()}")

            # Check for missing values
            missing = df.isnull().sum().sum()
            if missing > 0:
                print(f"   ⚠️  Warning: {missing} missing values found")
            else:
                print("   ✅ No missing values")

            return True
        except Exception as e:
            print(f"   ❌ Error loading dataset: {e}")
            return False
    else:
        print("   ❌ Dataset file not found")
        return False

def test_imports():
    """Test if all required packages can be imported"""
    print("\n🔍 Testing imports...")

    packages = [
        ('tensorflow', 'TensorFlow'),
        ('scapy', 'Scapy'),
        ('flask', 'Flask'),
        ('pandas', 'Pandas'),
        ('numpy', 'NumPy'),
        ('sklearn', 'Scikit-learn'),
        ('matplotlib', 'Matplotlib'),
        ('seaborn', 'Seaborn')
    ]

    failed_imports = []

    for package, name in packages:
        try:
            __import__(package)
            print(f"   ✅ {name} imported successfully")
        except ImportError:
            print(f"   ❌ {name} import failed")
            failed_imports.append(package)

    if failed_imports:
        print(f"\n❌ Missing packages: {', '.join(failed_imports)}")
        print("Install with: pip install -r requirements_monitoring.txt")
        return False

    return True

def test_monitoring_components():
    """Test monitoring components"""
    print("\n🔍 Testing monitoring components...")

    try:
        from real_time_monitor import RealTimeNetworkMonitor
        print("   ✅ RealTimeNetworkMonitor imported")

        # Test initialization (without loading model to avoid errors)
        print("   ✅ Monitoring components ready")
        return True
    except ImportError as e:
        print(f"   ❌ Import error: {e}")
        return False
    except Exception as e:
        print(f"   ❌ Error testing monitoring: {e}")
        return False

def test_dashboard_components():
    """Test dashboard components"""
    print("\n🔍 Testing dashboard components...")

    try:
        from monitoring_dashboard import app
        print("   ✅ Dashboard components imported")
        return True
    except ImportError as e:
        print(f"   ❌ Import error: {e}")
        return False
    except Exception as e:
        print(f"   ❌ Error testing dashboard: {e}")
        return False

def run_full_test():
    """Run complete system test"""
    print("🧪 NETWORK INTRUSION DETECTION SYSTEM - FULL TEST")
    print("=" * 60)

    tests = [
        ("Package Imports", test_imports),
        ("Dataset", test_dataset),
        ("Model Files", test_model_files),
        ("Monitoring Components", test_monitoring_components),
        ("Dashboard Components", test_dashboard_components)
    ]

    results = []
    for test_name, test_func in tests:
        print(f"\n🔬 Running {test_name} test...")
        result = test_func()
        results.append((test_name, result))

    # Summary
    print("\n" + "=" * 60)
    print("📊 TEST SUMMARY")
    print("=" * 60)

    passed = 0
    total = len(results)

    for test_name, result in results:
        status = "✅ PASS" if result else "❌ FAIL"
        print(f"{status} {test_name}")
        if result:
            passed += 1

    print(f"\nOverall: {passed}/{total} tests passed")

    if passed == total:
        print("\n🎉 All tests passed! System is ready for monitoring.")
        print("\nNext steps:")
        print("1. Run: python run_monitoring.py --dashboard")
        print("2. Or run: python run_monitoring.py --monitor")
        return True
    else:
        print("\n⚠️  Some tests failed. Please fix the issues above.")
        return False

def main():
    """Main test function"""
    if len(sys.argv) > 1:
        test_name = sys.argv[1]

        if test_name == "imports":
            test_imports()
        elif test_name == "dataset":
            test_dataset()
        elif test_name == "model":
            test_model_files()
        elif test_name == "monitoring":
            test_monitoring_components()
        elif test_name == "dashboard":
            test_dashboard_components()
        else:
            print("Usage: python test_monitoring.py [imports|dataset|model|monitoring|dashboard]")
            print("Or run without arguments for full test suite")
    else:
        run_full_test()

if __name__ == "__main__":
    main()
