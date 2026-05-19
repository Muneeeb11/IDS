import pandas as pd
import numpy as np
import os
import pickle
import warnings
warnings.filterwarnings('ignore')

# DL imports
import tensorflow as tf
from tensorflow.keras.models import Model
from tensorflow.keras.layers import Dense, Input, Dropout, BatchNormalization, concatenate
from tensorflow.keras.optimizers import Adam
from tensorflow.keras.utils import to_categorical
from tensorflow.keras.callbacks import EarlyStopping, ReduceLROnPlateau

# ML imports
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.metrics import accuracy_score, recall_score, precision_score, f1_score
from sklearn.model_selection import train_test_split

# Set random seeds for reproducibility
np.random.seed(42)
tf.random.set_seed(42)

class MemoryEfficientHybridDLMLModel:
    """Hybrid IDS classifier used by the live sniffer.

    The model combines:
    1. A TensorFlow neural network for deep feature learning.
    2. A Random Forest trained on original + neural-network features.
    3. A Logistic Regression meta-classifier that combines both predictions.
    """

    def __init__(self, num_classes, feature_dim=46):
        self.num_classes = num_classes
        self.feature_dim = feature_dim
        self.scaler = StandardScaler()
        self.label_encoder = LabelEncoder()
        self.dl_model = None
        self.ml_models = {}
        self.meta_classifier = None
        self.is_fitted = False
        self.predict_fn = None  
        
    def build_dl_model(self):
        """Build a deep learning model for feature extraction and classification"""
        # Input layer - FIXED: Only original features
        input_layer = Input(shape=(self.feature_dim,))
        
        # Feature extraction branches
        # Branch 1: Statistical features
        x1 = Dense(128, activation='relu')(input_layer)
        x1 = BatchNormalization()(x1)
        x1 = Dropout(0.3)(x1)
        x1 = Dense(64, activation='relu')(x1)
        x1 = BatchNormalization()(x1)
        x1 = Dropout(0.3)(x1)
        
        # Branch 2: Protocol features
        x2 = Dense(64, activation='relu')(input_layer)
        x2 = BatchNormalization()(x2)
        x2 = Dropout(0.2)(x2)
        x2 = Dense(32, activation='relu')(x2)
        
        # Concatenate branches
        concatenated = concatenate([x1, x2])
        
        # Deep layers
        x = Dense(256, activation='relu')(concatenated)
        x = BatchNormalization()(x)
        x = Dropout(0.4)(x)
        x = Dense(128, activation='relu')(x)
        x = BatchNormalization()(x)
        x = Dropout(0.3)(x)
        
        # Feature extraction layer (for ML models)
        feature_layer = Dense(64, activation='relu', name='feature_layer')(x)
        
        # Output layer
        output_layer = Dense(self.num_classes, activation='softmax')(feature_layer)
        
        model = Model(inputs=input_layer, outputs=output_layer)
        model.compile(
            optimizer=Adam(learning_rate=0.001),
            loss='categorical_crossentropy',
            metrics=['accuracy']
        )
        
        return model
    
    def build_ml_models(self):
        """Initialize ML models - only Random Forest for speed"""
        self.ml_models = {
            'random_forest': RandomForestClassifier(
                n_estimators=100,
                max_depth=20,
                min_samples_split=5,
                min_samples_leaf=2,
                random_state=42,
                n_jobs=-1,
                verbose=1
            )
        }
    
    def build_meta_classifier(self):
        """Build meta-classifier for ensemble predictions"""
        return LogisticRegression(
            multi_class='multinomial',
            solver='lbfgs',
            C=1.0,
            random_state=42,
            max_iter=1000
        )
    
    def extract_dl_features_batch(self, X, batch_size=10000):
        """Extract features from intermediate DL layer in batches"""
        if self.dl_model is None:
            raise ValueError("DL model not trained yet")
        
        # Create feature extractor model
        feature_extractor = Model(
            inputs=self.dl_model.input,
            outputs=self.dl_model.get_layer('feature_layer').output
        )
        
        # Process in batches to avoid memory issues
        num_samples = X.shape[0]
        features_list = []
        
        for i in range(0, num_samples, batch_size):
            end_idx = min(i + batch_size, num_samples)
            batch_features = feature_extractor.predict(
                X[i:end_idx], 
                verbose=0,
                batch_size=min(batch_size, 1024)
            )
            features_list.append(batch_features)
        
        return np.vstack(features_list)
    
    def train_ml_models_batch(self, X_original, y, dl_features):
        """Train ML models on combined features"""
        print("Training ML models...")
        
        # Combine original features with DL features
        X_combined = np.hstack([X_original, dl_features])
        
        ml_predictions_train = []
        ml_predictions_val = []
        
        # Split data for validation
        X_combined_train, X_combined_val, y_train, y_val = train_test_split(
            X_combined, y, test_size=0.2, random_state=42, stratify=y
        )
        
        # Also split original features for DL predictions later
        X_original_train, X_original_val, _, _ = train_test_split(
            X_original, y, test_size=0.2, random_state=42, stratify=y
        )
        
        for name, model in self.ml_models.items():
            print(f"Training {name}...")
            
            # Train model on combined features
            model.fit(X_combined_train, y_train)
            
            # Get predictions
            pred_train = model.predict_proba(X_combined_train)
            pred_val = model.predict_proba(X_combined_val)
            
            ml_predictions_train.append(pred_train)
            ml_predictions_val.append(pred_val)
            
            # Print model performance
            train_acc = accuracy_score(y_train, model.predict(X_combined_train))
            val_acc = accuracy_score(y_val, model.predict(X_combined_val))
            print(f"{name} - Train Acc: {train_acc:.4f}, Val Acc: {val_acc:.4f}")
        
        return (ml_predictions_train, ml_predictions_val, y_train, y_val, 
                X_original_train, X_original_val, X_combined_train, X_combined_val)
    
    def fit(self, X, y, validation_split=0.2, epochs=20, batch_size=2048):
        """Train the hybrid model with memory efficiency"""
        print("Starting memory-efficient hybrid model training...")
        
        # Encode labels
        y_encoded = self.label_encoder.fit_transform(y)
        y_categorical = to_categorical(y_encoded)
        
        # Scale features
        print("Scaling features...")
        self.scaler.fit(X)
        X_scaled = self.scaler.transform(X)
        
        # Split data
        X_train, X_val, y_train, y_val = train_test_split(
            X_scaled, y_categorical, test_size=validation_split, random_state=42, stratify=y_encoded
        )
        
        # Build and train DL model
        print("Training Deep Learning model...")
        self.dl_model = self.build_dl_model()
        
        callbacks = [
            EarlyStopping(monitor='val_loss', patience=5, restore_best_weights=True),
            ReduceLROnPlateau(monitor='val_loss', factor=0.5, patience=3)
        ]
        
        print("Training DL model (this may take a while)...")
        dl_history = self.dl_model.fit(
            X_train, y_train,
            validation_data=(X_val, y_val),
            epochs=epochs,
            batch_size=batch_size,
            callbacks=callbacks,
            verbose=1
        )
        
        # Extract DL features in batches
        print("Extracting DL features in batches...")
        dl_features_train = self.extract_dl_features_batch(X_train, batch_size=5000)
        
        # Get DL predictions for original training data
        print("Getting DL predictions...")
        dl_pred_train = self.dl_model.predict(X_train, verbose=0, batch_size=2048)
        
        # Build and train ML models
        self.build_ml_models()
        
        # Convert back to encoded labels for ML models
        y_train_ml = np.argmax(y_train, axis=1)
        
        # Train ML models - FIXED: Pass original features, not combined
        (ml_preds_train, ml_preds_val, y_ml_train, y_ml_val, 
         X_orig_train, X_orig_val, X_comb_train, X_comb_val) = self.train_ml_models_batch(
            X_train, y_train_ml, dl_features_train
        )
        
        # Prepare meta-features - FIXED: Use original features for DL predictions
        print("Preparing meta-features...")
        
        # Use smaller subset to avoid memory issues
        subset_size = min(50000, len(X_comb_train))
        indices = np.random.choice(len(X_comb_train), subset_size, replace=False)
        
        # Get DL predictions for the ORIGINAL features (not combined)
        dl_pred_meta = self.dl_model.predict(X_orig_train, verbose=0, batch_size=2048)
        
        # Create meta-features - FIXED: Use correct indices and original features
        meta_features_train = np.hstack([
            dl_pred_meta[indices],  # DL predictions on original features
            *[pred[indices] for pred in ml_preds_train]  # ML predictions on combined features
        ])
        
        # Prepare validation meta-features
        val_subset_size = min(10000, len(X_comb_val))
        val_indices = np.random.choice(len(X_comb_val), val_subset_size, replace=False)
        
        # Get DL predictions for validation (original features)
        dl_pred_val_meta = self.dl_model.predict(X_orig_val, verbose=0, batch_size=2048)
        
        meta_features_val = np.hstack([
            dl_pred_val_meta[val_indices],  # DL predictions on original features
            *[pred[val_indices] for pred in ml_preds_val]  # ML predictions on combined features
        ])
        
        # Get corresponding labels
        y_meta_train = y_ml_train[indices]
        y_meta_val = y_ml_val[val_indices]
        
        # Train meta-classifier on subset
        print("Training meta-classifier on subset...")
        self.meta_classifier = self.build_meta_classifier()
        self.meta_classifier.fit(meta_features_train, y_meta_train)
        
        # Validate meta-classifier
        meta_val_pred = self.meta_classifier.predict(meta_features_val)
        meta_val_acc = accuracy_score(y_meta_val, meta_val_pred)
        print(f"Meta-classifier validation accuracy: {meta_val_acc:.4f}")
        
        self.is_fitted = True
        print("Hybrid model training completed!")
        
        return dl_history
    
    def predict(self, X, batch_size=10000):
        """Make predictions with confidence scores using the hybrid model."""
        
        if not self.is_fitted:
            raise ValueError("Model not fitted yet")

        X_scaled = self.scaler.transform(X)
        predictions = []
        confidences = []

        num_samples = X_scaled.shape[0]

        for i in range(0, num_samples, batch_size):
            end_idx = min(i + batch_size, num_samples)
            batch_X = X_scaled[i:end_idx]

            # 1. Deep-learning branch: predicts directly from scaled features.
            dl_pred = self.dl_model.predict(batch_X, verbose=0, batch_size=2048)

            # 2. Intermediate neural features feed the classical ML branch.
            dl_features = self.extract_dl_features_batch(batch_X, batch_size=min(batch_size, 1024))

            # 3. Classical ML branch predicts from original + DL features.
            ml_preds = []
            X_combined = np.hstack([batch_X, dl_features])
            for name, model in self.ml_models.items():
                pred_proba = model.predict_proba(X_combined)  # This is a 2D array
                ml_preds.append(pred_proba)

            # 4. Meta-classifier receives probabilities from both branches and
            # chooses the final attack class.
            meta_features = np.hstack([dl_pred] + ml_preds)

            # --- 5. Meta-classifier predictions ---
            if hasattr(self.meta_classifier, "predict_proba"):
                meta_pred_proba = self.meta_classifier.predict_proba(meta_features)
                batch_pred = np.argmax(meta_pred_proba, axis=1)
                batch_conf = np.max(meta_pred_proba, axis=1)  # Confidence as probability
            else:
                # fallback if meta_classifier doesn't have predict_proba
                batch_pred = self.meta_classifier.predict(meta_features)
                batch_conf = np.ones_like(batch_pred)  # Confidence 100%

            # --- 6. Store results ---
            predictions.extend(batch_pred)
            confidences.extend(batch_conf)

        # Convert back to original labels
        predictions = self.label_encoder.inverse_transform(np.array(predictions))
        confidences = np.array(confidences) * 100  # convert to percentage

        # Return list of tuples: (prediction, confidence%)
        return list(zip(predictions, confidences))

    
    def save(self, filename):
        """Save the hybrid model"""
        if not self.is_fitted:
            raise ValueError("Model not fitted yet")
        
        model_data = {
            'num_classes': self.num_classes,
            'feature_dim': self.feature_dim,
            'scaler': self.scaler,
            'label_encoder': self.label_encoder,
            'ml_models': self.ml_models,
            'meta_classifier': self.meta_classifier,
            'is_fitted': self.is_fitted
        }
        
        # Save DL model separately
        self.dl_model.save('dl_model_component.h5')
        
        with open(filename, 'wb') as f:
            pickle.dump(model_data, f)
        
        print(f"Hybrid model saved to {filename}")
    
    @classmethod
    def load(cls, filename):
        """Load a saved hybrid model"""
        with open(filename, 'rb') as f:
            model_data = pickle.load(f)
        
        # Create instance
        instance = cls(
            num_classes=model_data['num_classes'],
            feature_dim=model_data['feature_dim']
        )
        
        # Load attributes
        instance.scaler = model_data['scaler']
        instance.label_encoder = model_data['label_encoder']
        instance.ml_models = model_data['ml_models']
        instance.meta_classifier = model_data['meta_classifier']
        instance.is_fitted = model_data['is_fitted']
        
        # The pickle stores the scaler, encoders, ML models, and meta-classifier.
        # The TensorFlow model is stored separately as dl_model_component.h5.
        instance.dl_model = tf.keras.models.load_model(
            cls._find_dl_component(filename),
            compile=False
        )
        
        return instance

    @staticmethod
    def _find_dl_component(filename):
        """Find the saved TensorFlow component in common project locations."""
        model_dir = os.path.dirname(os.path.abspath(filename))
        project_dir = os.path.dirname(model_dir)
        # The pickle stores the sklearn pieces only, so we search a few runtime
        # locations for the separate TensorFlow `.h5` file.
        candidates = [
            os.path.join(os.getcwd(), 'dl_model_component.h5'),
            os.path.join(model_dir, 'dl_model_component.h5'),
            os.path.join(project_dir, 'Tool', 'dl_model_component.h5'),
            os.path.join(project_dir, 'scripts', 'dl_model_component.h5'),
        ]

        for path in candidates:
            if os.path.exists(path):
                return path

        searched = "\n".join(f"- {path}" for path in candidates)
        raise FileNotFoundError(
            "Could not find dl_model_component.h5. Searched:\n" + searched
        )
