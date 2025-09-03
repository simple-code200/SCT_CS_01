import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.utils import class_weight
from sklearn.metrics import classification_report, confusion_matrix
import tensorflow as tf
from tensorflow.keras.models import Sequential
from tensorflow.keras.layers import Conv1D, Dense, Flatten, Dropout, MaxPooling1D, BatchNormalization
from tensorflow.keras.callbacks import EarlyStopping, ModelCheckpoint
import joblib
import pickle
import matplotlib.pyplot as plt
import seaborn as sns

def load_and_clean_data(filepath="network_attacks.csv"):
    """Load and clean the network intrusion dataset"""
    print("Loading dataset...")
    df = pd.read_csv(filepath)

    # Clean column names
    df.columns = df.columns.str.strip()

    print(f"Dataset shape: {df.shape}")
    print(f"Columns: {list(df.columns)}")

    # Separate features and target
    X = df.drop("Label", axis=1)
    y = df["Label"]

    print(f"Target distribution:\n{y.value_counts()}")

    # Handle missing values and infinite values
    print("Handling missing values and infinite values...")
    X = X.replace([np.inf, -np.inf], np.nan)
    X = X.dropna()
    y = y[X.index]

    print(f"After cleaning - Dataset shape: {X.shape}")

    return X, y

def preprocess_data(X, y):
    """Preprocess data for CNN training"""
    print("Preprocessing data...")

    # Encode target labels
    label_encoder = LabelEncoder()
    y_encoded = label_encoder.fit_transform(y)

    # Scale features
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)

    # Reshape for Conv1D: (samples, timesteps, channels)
    X_reshaped = X_scaled.reshape(X_scaled.shape[0], X_scaled.shape[1], 1)

    print(f"Reshaped data shape: {X_reshaped.shape}")
    print(f"Number of classes: {len(np.unique(y_encoded))}")

    return X_reshaped, y_encoded, scaler, label_encoder

def build_cnn_model(input_shape, num_classes):
    """Build 1D CNN model for network intrusion detection"""
    print("Building CNN model...")

    model = Sequential([
        Conv1D(filters=64, kernel_size=2, activation='relu', input_shape=input_shape),
        BatchNormalization(),
        MaxPooling1D(pool_size=2),
        Dropout(0.3),

        Conv1D(filters=128, kernel_size=2, activation='relu'),
        BatchNormalization(),
        Dropout(0.3),

        Conv1D(filters=256, kernel_size=2, activation='relu'),
        BatchNormalization(),
        Dropout(0.4),

        Flatten(),
        Dense(256, activation='relu'),
        Dropout(0.5),
        Dense(num_classes, activation='softmax')
    ])

    model.compile(
        optimizer='adam',
        loss='sparse_categorical_crossentropy',
        metrics=['accuracy']
    )

    return model

def train_model(X_train, y_train, X_val, y_val, class_weights_dict):
    """Train the CNN model"""
    print("Training CNN model...")

    input_shape = (X_train.shape[1], 1)
    num_classes = len(np.unique(y_train))

    model = build_cnn_model(input_shape, num_classes)

    # Callbacks
    early_stopping = EarlyStopping(
        monitor='val_loss',
        patience=10,
        restore_best_weights=True,
        verbose=1
    )

    model_checkpoint = ModelCheckpoint(
        'best_cnn_model.h5',
        monitor='val_accuracy',
        save_best_only=True,
        verbose=1
    )

    # Train model
    history = model.fit(
        X_train, y_train,
        epochs=100,
        batch_size=64,
        validation_data=(X_val, y_val),
        class_weight=class_weights_dict,
        callbacks=[early_stopping, model_checkpoint],
        verbose=2
    )

    return model, history

def evaluate_model(model, X_test, y_test, label_encoder):
    """Evaluate the trained model"""
    print("Evaluating model...")

    # Predictions
    y_pred_prob = model.predict(X_test)
    y_pred = np.argmax(y_pred_prob, axis=1)

    # Classification report
    target_names = [str(cls) for cls in label_encoder.classes_]
    print("\nClassification Report:")
    print(classification_report(y_test, y_pred, target_names=target_names))

    # Confusion matrix
    cm = confusion_matrix(y_test, y_pred)
    plt.figure(figsize=(10, 8))
    sns.heatmap(cm, annot=True, fmt='d', cmap='Blues',
                xticklabels=target_names, yticklabels=target_names)
    plt.title('Confusion Matrix - CNN Network Intrusion Detection')
    plt.ylabel('True Label')
    plt.xlabel('Predicted Label')
    plt.tight_layout()
    plt.savefig('cnn_confusion_matrix.png', dpi=300, bbox_inches='tight')
    # plt.show()

    return y_pred

def plot_training_history(history):
    """Plot training history"""
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(15, 5))

    # Accuracy
    ax1.plot(history.history['accuracy'], label='Training Accuracy')
    ax1.plot(history.history['val_accuracy'], label='Validation Accuracy')
    ax1.set_title('Model Accuracy')
    ax1.set_xlabel('Epoch')
    ax1.set_ylabel('Accuracy')
    ax1.legend()

    # Loss
    ax2.plot(history.history['loss'], label='Training Loss')
    ax2.plot(history.history['val_loss'], label='Validation Loss')
    ax2.set_title('Model Loss')
    ax2.set_xlabel('Epoch')
    ax2.set_ylabel('Loss')
    ax2.legend()

    plt.tight_layout()
    plt.savefig('cnn_training_history.png', dpi=300, bbox_inches='tight')
    # plt.show()

def main():
    """Main training pipeline"""
    print("=== Network Intrusion Detection - CNN Training Pipeline ===\n")

    # Load and clean data
    X, y = load_and_clean_data()

    # Preprocess data
    X_processed, y_encoded, scaler, label_encoder = preprocess_data(X, y)

    # Train/test/validation split
    X_train, X_temp, y_train, y_temp = train_test_split(
        X_processed, y_encoded, test_size=0.3, random_state=42, stratify=y_encoded
    )
    X_val, X_test, y_val, y_test = train_test_split(
        X_temp, y_temp, test_size=0.5, random_state=42, stratify=y_temp
    )

    print(f"Training set: {X_train.shape}")
    print(f"Validation set: {X_val.shape}")
    print(f"Test set: {X_test.shape}")

    # Compute class weights
    class_weights = class_weight.compute_class_weight(
        class_weight='balanced',
        classes=np.unique(y_train),
        y=y_train
    )
    class_weights_dict = dict(enumerate(class_weights))
    print(f"Class weights: {class_weights_dict}")

    # Train model
    model, history = train_model(X_train, y_train, X_val, y_val, class_weights_dict)

    # Plot training history
    plot_training_history(history)

    # Evaluate model
    y_pred = evaluate_model(model, X_test, y_test, label_encoder)

    # Save model and preprocessing objects
    print("\nSaving model and preprocessing objects...")
    model.save("best_cnn_model.h5")
    pickle.dump(scaler, open("scaler_cnn_final.pkl", "wb"))
    pickle.dump(label_encoder, open("label_encoder_cnn_final.pkl", "wb"))

    # Final test accuracy
    test_loss, test_accuracy = model.evaluate(X_test, y_test, verbose=0)
    print(f"Final Test Accuracy: {test_accuracy:.4f}")
    print("\n=== Training Complete ===")
    print("Files saved:")
    print("- cnn_network_intrusion_final.h5 (trained model)")
    print("- scaler_cnn_final.pkl (feature scaler)")
    print("- label_encoder_cnn_final.pkl (label encoder)")
    print("- cnn_confusion_matrix.png (confusion matrix plot)")
    print("- cnn_training_history.png (training history plot)")

if __name__ == "__main__":
    main()
