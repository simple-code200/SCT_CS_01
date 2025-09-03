# CNN Network Intrusion Detection System

This repository contains a complete implementation of a Convolutional Neural Network (CNN) based network intrusion detection system using the network attacks dataset.

## 📁 Files Overview

### Core Components
- **`clean_dataset.py`** - Dataset cleaning and preprocessing utilities
- **`train_network_intrusion_cnn.py`** - Complete CNN training pipeline
- **`cnn_inference.py`** - Model inference and prediction utilities
- **`cnn_network_intrusion.py`** - Basic CNN model implementation

### Data Files
- **`network_attacks.csv`** - Original dataset (input)
- **`cleaned_network_attacks.csv`** - Cleaned dataset (output from cleaning)

### Model Files (Generated)
- **`cnn_network_intrusion_final.h5`** - Trained CNN model
- **`scaler_cnn_final.pkl`** - Feature scaler for CNN
- **`label_encoder_cnn_final.pkl`** - Label encoder for CNN

## 🚀 Quick Start

### 1. Data Cleaning
```bash
python clean_dataset.py
```
This will:
- Load the original dataset
- Clean missing values and infinite values
- Remove duplicates
- Save cleaned dataset as `cleaned_network_attacks.csv`
- Generate preprocessing objects for both traditional ML and CNN

### 2. Train CNN Model
```bash
python train_network_intrusion_cnn.py
```
This will:
- Load and preprocess the cleaned dataset
- Build and train a 1D CNN model
- Handle class imbalance with weighted training
- Save the trained model and preprocessing objects
- Generate training history plots and confusion matrix

### 3. Make Predictions
```bash
python cnn_inference.py
```
This will:
- Load the trained CNN model
- Demonstrate predictions on sample data
- Show prediction confidence scores

## 📊 Model Architecture

The CNN model consists of:
- **3 Convolutional layers** with increasing filters (64 → 128 → 256)
- **Batch normalization** and **dropout** for regularization
- **Max pooling** for dimensionality reduction
- **Dense layers** for classification
- **Softmax output** for multi-class classification

## 🔧 Key Features

### Data Preprocessing
- Handles missing values and infinite values
- Standardizes features using StandardScaler
- Encodes categorical labels
- Reshapes data for CNN input (samples, timesteps, channels)

### Model Training
- Early stopping to prevent overfitting
- Model checkpointing to save best model
- Class weight balancing for imbalanced data
- Training history visualization

### Inference
- Single sample prediction
- Batch prediction support
- Confidence score reporting
- Class probability distribution

## 📈 Performance Metrics

The model provides:
- **Accuracy** - Overall classification accuracy
- **Precision, Recall, F1-Score** - Per-class metrics
- **Confusion Matrix** - Detailed classification results
- **Training History** - Loss and accuracy curves

## 🛠️ Dependencies

```bash
pip install pandas numpy scikit-learn tensorflow matplotlib seaborn joblib
```

## 📝 Usage Examples

### Clean Dataset
```python
from clean_dataset import clean_network_intrusion_dataset
df_clean = clean_network_intrusion_dataset()
```

### Train Model
```python
from train_network_intrusion_cnn import main
main()  # Runs complete training pipeline
```

### Make Predictions
```python
from cnn_inference import load_cnn_model, predict_single_sample

model, scaler, label_encoder = load_cnn_model()
sample_data = {...}  # Your network traffic features
prediction, confidence = predict_single_sample(model, scaler, label_encoder, sample_data)
```

## 🎯 Network Traffic Features

The system uses the following key features for intrusion detection:
- Flow Duration, Packet Lengths, Bytes/Packets per second
- Forward/Backward packet statistics
- Inter-Arrival Times (IAT)
- TCP flags (SYN, ACK, RST, etc.)
- Window sizes, Header lengths
- Active/Idle times

## 🔍 Model Evaluation

After training, the model generates:
- `cnn_confusion_matrix.png` - Confusion matrix visualization
- `cnn_training_history.png` - Training curves
- Classification report with detailed metrics

## 🚨 Important Notes

1. **Data Quality**: The original dataset may contain infinite values and missing data that need cleaning
2. **Class Imbalance**: The dataset has imbalanced classes, handled through weighted training
3. **Feature Scaling**: All features are standardized before feeding to the CNN
4. **Model Persistence**: Trained models and scalers are saved for inference

## 🔄 Pipeline Flow

```
Raw Data → Data Cleaning → Feature Scaling → CNN Training → Model Evaluation → Inference
```

## 📞 Support

The system provides comprehensive logging and error handling for:
- Data loading issues
- Model training problems
- Inference errors
- File I/O operations

## 🎉 Summary

This implementation provides a complete end-to-end solution for network intrusion detection using CNNs, from data cleaning to model deployment and inference.
