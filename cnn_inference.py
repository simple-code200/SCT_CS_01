import pandas as pd
import numpy as np
from tensorflow.keras.models import load_model
import joblib

def load_cnn_model(model_path="cnn_network_intrusion_final.h5",
                   scaler_path="scaler_cnn_final.pkl",
                   label_encoder_path="label_encoder_cnn_final.pkl"):
    """Load the trained CNN model and preprocessing objects"""
    print("Loading CNN model and preprocessing objects...")

    try:
        model = load_model(model_path)
        scaler = joblib.load(scaler_path)
        label_encoder = joblib.load(label_encoder_path)
        print("✅ Model and preprocessing objects loaded successfully!")
        return model, scaler, label_encoder
    except FileNotFoundError as e:
        print(f"❌ Error loading files: {e}")
        print("Please ensure the model files exist. Run training first if needed.")
        return None, None, None

def preprocess_input_data(data, scaler, feature_columns=None):
    """Preprocess input data for CNN prediction"""
    print("Preprocessing input data...")

    # If data is a dict or single row, convert to DataFrame
    if isinstance(data, dict):
        data = pd.DataFrame([data])
    elif isinstance(data, list):
        data = pd.DataFrame(data)
    elif not isinstance(data, pd.DataFrame):
        data = pd.DataFrame(data)

    # Clean column names
    data.columns = data.columns.str.strip()

    # If feature columns specified, select only those
    if feature_columns:
        missing_cols = [col for col in feature_columns if col not in data.columns]
        if missing_cols:
            raise ValueError(f"Missing required columns: {missing_cols}")
        data = data[feature_columns]

    # Handle missing values and infinite values
    data = data.replace([np.inf, -np.inf], np.nan)
    if data.isnull().sum().sum() > 0:
        print("⚠️  Warning: Input data contains NaN values. Filling with 0.")
        data = data.fillna(0)

    # Scale the data
    data_scaled = scaler.transform(data)

    # Reshape for CNN: (samples, timesteps, channels)
    data_reshaped = data_scaled.reshape(data_scaled.shape[0], data_scaled.shape[1], 1)

    print(f"Input shape for CNN: {data_reshaped.shape}")
    return data_reshaped

def predict_intrusion(model, scaler, label_encoder, input_data, feature_columns=None):
    """Make predictions using the CNN model"""
    print("Making predictions...")

    # Preprocess input data
    processed_data = preprocess_input_data(input_data, scaler, feature_columns)

    # Make predictions
    predictions_prob = model.predict(processed_data, verbose=0)
    predictions = np.argmax(predictions_prob, axis=1)

    # Convert predictions back to original labels
    predicted_labels = label_encoder.inverse_transform(predictions)

    # Get confidence scores
    confidence_scores = np.max(predictions_prob, axis=1)

    return predicted_labels, confidence_scores, predictions_prob

def predict_single_sample(model, scaler, label_encoder, sample_data):
    """Predict intrusion for a single sample"""
    print("\n=== Single Sample Prediction ===")

    predicted_label, confidence, probabilities = predict_intrusion(
        model, scaler, label_encoder, sample_data
    )

    print(f"Predicted: {predicted_label[0]}")
    print(".4f")

    # Show all class probabilities
    class_names = label_encoder.classes_
    print("\nClass Probabilities:")
    for class_name, prob in zip(class_names, probabilities[0]):
        print(".4f")

    return predicted_label[0], confidence[0]

def predict_batch_samples(model, scaler, label_encoder, batch_data):
    """Predict intrusion for multiple samples"""
    print(f"\n=== Batch Prediction ({len(batch_data)} samples) ===")

    predicted_labels, confidences, _ = predict_intrusion(
        model, scaler, label_encoder, batch_data
    )

    # Create results DataFrame
    results = pd.DataFrame({
        'Predicted_Label': predicted_labels,
        'Confidence': confidences
    })

    print("Prediction Results:")
    print(results)

    return results

def demo_predictions(model, scaler, label_encoder):
    """Demo function with sample predictions"""
    print("\n=== CNN Network Intrusion Detection Demo ===\n")

    # Sample benign traffic features (example values)
    benign_sample = {
        ' Destination Port': 80,
        ' Flow Duration': 1000000,
        ' Total Fwd Packets': 10,
        ' Total Backward Packets': 8,
        'Total Length of Fwd Packets': 1000,
        ' Total Length of Bwd Packets': 800,
        ' Fwd Packet Length Max': 100,
        ' Fwd Packet Length Min': 50,
        ' Fwd Packet Length Mean': 75.5,
        ' Fwd Packet Length Std': 15.2,
        'Bwd Packet Length Max': 90,
        ' Bwd Packet Length Min': 40,
        ' Bwd Packet Length Mean': 65.3,
        ' Bwd Packet Length Std': 12.8,
        'Flow Bytes/s': 1800.0,
        ' Flow Packets/s': 18.0,
        ' Flow IAT Mean': 100000.0,
        ' Flow IAT Std': 50000.0,
        ' Flow IAT Max': 200000.0,
        ' Flow IAT Min': 50000.0,
        'Fwd IAT Total': 900000.0,
        ' Fwd IAT Mean': 112500.0,
        ' Fwd IAT Std': 45000.0,
        ' Fwd IAT Max': 150000.0,
        ' Fwd IAT Min': 75000.0,
        'Bwd IAT Total': 700000.0,
        ' Bwd IAT Mean': 100000.0,
        ' Bwd IAT Std': 35000.0,
        ' Bwd IAT Max': 120000.0,
        ' Bwd IAT Min': 80000.0,
        'Fwd PSH Flags': 0,
        ' Bwd PSH Flags': 0,
        ' Fwd URG Flags': 0,
        ' Bwd URG Flags': 0,
        ' Fwd Header Length': 320,
        ' Bwd Header Length': 256,
        'Fwd Packets/s': 10.0,
        ' Bwd Packets/s': 8.0,
        ' Min Packet Length': 40,
        ' Max Packet Length': 100,
        ' Packet Length Mean': 70.5,
        ' Packet Length Std': 18.3,
        ' Packet Length Variance': 335.0,
        'FIN Flag Count': 0,
        ' SYN Flag Count': 1,
        ' RST Flag Count': 0,
        ' PSH Flag Count': 0,
        ' ACK Flag Count': 1,
        ' URG Flag Count': 0,
        ' CWE Flag Count': 0,
        ' ECE Flag Count': 0,
        ' Down/Up Ratio': 0.8,
        ' Average Packet Size': 72.5,
        ' Avg Fwd Segment Size': 75.5,
        ' Avg Bwd Segment Size': 65.3,
        ' Fwd Header Length.1': 320,
        'Fwd Avg Bytes/Bulk': 0,
        ' Fwd Avg Packets/Bulk': 0,
        ' Fwd Avg Bulk Rate': 0,
        ' Bwd Avg Bytes/Bulk': 0,
        ' Bwd Avg Packets/Bulk': 0,
        'Bwd Avg Bulk Rate': 0,
        'Subflow Fwd Packets': 10,
        ' Subflow Fwd Bytes': 1000,
        ' Subflow Bwd Packets': 8,
        ' Subflow Bwd Bytes': 800,
        'Init_Win_bytes_forward': 8192,
        ' Init_Win_bytes_backward': 8192,
        ' act_data_pkt_fwd': 8,
        ' min_seg_size_forward': 20,
        'Active Mean': 0.0,
        ' Active Std': 0.0,
        ' Active Max': 0.0,
        ' Active Min': 0.0,
        'Idle Mean': 0.0,
        ' Idle Std': 0.0,
        ' Idle Max': 0.0,
        ' Idle Min': 0.0
    }

    # Make prediction
    predict_single_sample(model, scaler, label_encoder, benign_sample)

def main():
    """Main function for CNN inference"""
    # Load model and preprocessing objects
    model, scaler, label_encoder = load_cnn_model()

    if model is None:
        return

    # Run demo predictions
    demo_predictions(model, scaler, label_encoder)

    print("\n=== Inference Complete ===")
    print("You can now use the predict_single_sample() or predict_batch_samples() functions")
    print("for your own network traffic data.")

if __name__ == "__main__":
    main()
