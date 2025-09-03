import pandas as pd
import numpy as np
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.model_selection import train_test_split
import joblib

def clean_network_intrusion_dataset(input_file="network_attacks.csv", output_file="cleaned_network_attacks.csv"):
    """
    Clean the network intrusion dataset by handling missing values, infinite values,
    and preparing it for machine learning models.
    """
    print("=== Network Intrusion Dataset Cleaning ===\n")

    # Load dataset
    print("Loading dataset...")
    df = pd.read_csv(input_file)
    print(f"Original dataset shape: {df.shape}")

    # Clean column names (strip leading/trailing spaces)
    df.columns = df.columns.str.strip()
    print(f"Columns: {list(df.columns)}")

    # Check for missing values
    print(f"\nMissing values per column:\n{df.isnull().sum()}")

    # Check data types
    print(f"\nData types:\n{df.dtypes}")

    # Separate features and target
    X = df.drop("Label", axis=1)
    y = df["Label"]

    print(f"\nTarget distribution:\n{y.value_counts()}")

    # Handle infinite values
    print("\nHandling infinite values...")
    print(f"Infinite values in features: {np.isinf(X.values).sum()}")
    print(f"Infinite values in target: {np.isinf(y.values.astype(str)).sum()}")

    # Replace inf/-inf with NaN
    X = X.replace([np.inf, -np.inf], np.nan)

    # Check for NaN values after replacement
    print(f"NaN values after inf replacement: {X.isnull().sum().sum()}")

    # Drop rows with NaN values
    print("Dropping rows with NaN values...")
    X_clean = X.dropna()
    y_clean = y[X_clean.index]

    print(f"Dataset shape after cleaning: {X_clean.shape}")

    # Check for duplicate rows
    duplicates = X_clean.duplicated().sum()
    print(f"Duplicate rows: {duplicates}")

    if duplicates > 0:
        print("Removing duplicate rows...")
        X_clean = X_clean.drop_duplicates()
        y_clean = y_clean[X_clean.index]
        print(f"Dataset shape after removing duplicates: {X_clean.shape}")

    # Create cleaned dataframe
    df_clean = X_clean.copy()
    df_clean["Label"] = y_clean

    # Save cleaned dataset
    df_clean.to_csv(output_file, index=False)
    print(f"\nCleaned dataset saved to: {output_file}")

    # Print summary statistics
    print("\n=== Dataset Summary ===")
    print(f"Total samples: {len(df_clean)}")
    print(f"Number of features: {len(X_clean.columns)}")
    print(f"Number of classes: {len(y_clean.unique())}")
    print(f"Classes: {sorted(y_clean.unique())}")

    # Feature statistics
    print("\nFeature statistics:")
    print(X_clean.describe())

    return df_clean

def prepare_data_for_modeling(cleaned_file="cleaned_network_attacks.csv", test_size=0.2):
    """
    Prepare cleaned data for machine learning modeling.
    """
    print("\n=== Data Preparation for Modeling ===\n")

    # Load cleaned dataset
    df = pd.read_csv(cleaned_file)

    # Separate features and target
    X = df.drop("Label", axis=1)
    y = df["Label"]

    # Encode target labels
    label_encoder = LabelEncoder()
    y_encoded = label_encoder.fit_transform(y)

    # Scale features
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)

    # Train/test split
    X_train, X_test, y_train, y_test = train_test_split(
        X_scaled, y_encoded, test_size=test_size, random_state=42, stratify=y_encoded
    )

    print(f"Training set: {X_train.shape}")
    print(f"Test set: {X_test.shape}")
    print(f"Class distribution in training: {np.bincount(y_train)}")
    print(f"Class distribution in test: {np.bincount(y_test)}")

    # Save preprocessing objects
    joblib.dump(scaler, "scaler.pkl")
    joblib.dump(label_encoder, "label_encoder.pkl")

    print("\nPreprocessing objects saved:")
    print("- scaler.pkl")
    print("- label_encoder.pkl")

    return X_train, X_test, y_train, y_test, scaler, label_encoder

def create_cnn_ready_data(cleaned_file="cleaned_network_attacks.csv"):
    """
    Prepare data specifically for CNN modeling (reshape for Conv1D).
    """
    print("\n=== Preparing Data for CNN ===\n")

    # Load cleaned dataset
    df = pd.read_csv(cleaned_file)

    # Separate features and target
    X = df.drop("Label", axis=1)
    y = df["Label"]

    # Encode target labels
    label_encoder = LabelEncoder()
    y_encoded = label_encoder.fit_transform(y)

    # Scale features
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)

    # Reshape for Conv1D: (samples, timesteps, channels)
    X_reshaped = X_scaled.reshape(X_scaled.shape[0], X_scaled.shape[1], 1)

    print(f"Original shape: {X_scaled.shape}")
    print(f"Reshaped for CNN: {X_reshaped.shape}")

    # Train/test split
    X_train, X_test, y_train, y_test = train_test_split(
        X_reshaped, y_encoded, test_size=0.2, random_state=42, stratify=y_encoded
    )

    print(f"CNN Training set: {X_train.shape}")
    print(f"CNN Test set: {X_test.shape}")

    # Save CNN-specific preprocessing objects
    joblib.dump(scaler, "scaler_cnn.pkl")
    joblib.dump(label_encoder, "label_encoder_cnn.pkl")

    print("\nCNN preprocessing objects saved:")
    print("- scaler_cnn.pkl")
    print("- label_encoder_cnn.pkl")

    return X_train, X_test, y_train, y_test, scaler, label_encoder

if __name__ == "__main__":
    # Clean the dataset
    df_clean = clean_network_intrusion_dataset()

    # Prepare data for traditional ML models
    X_train, X_test, y_train, y_test, scaler, label_encoder = prepare_data_for_modeling()

    # Prepare data for CNN
    X_train_cnn, X_test_cnn, y_train_cnn, y_test_cnn, scaler_cnn, label_encoder_cnn = create_cnn_ready_data()

    print("\n=== All Data Preparation Complete ===")
    print("Files created:")
    print("- cleaned_network_attacks.csv (cleaned dataset)")
    print("- scaler.pkl, label_encoder.pkl (for traditional ML)")
    print("- scaler_cnn.pkl, label_encoder_cnn.pkl (for CNN)")
