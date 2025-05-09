import numpy as np
import tensorflow as tf
from tensorflow.keras.models import Sequential
from tensorflow.keras.layers import Conv1D, MaxPooling1D, Dense, Flatten, Dropout
from tensorflow.keras.optimizers import Adam
import joblib
import json

class ModelTrainer:
    def __init__(self):
        self.model = self.build_model()
        self.history = None
        self.load_dataset()

    def load_dataset(self):
        try:
            import pandas as pd
            self.data = pd.read_parquet("cic-collection.parquet")
            # Select relevant features for network traffic analysis
            self.features = ['Protocol', 'Flow Duration', 'Total Fwd Packets', 
                           'Total Backward Packets', 'Total Length of Fwd Packets',
                           'Total Length of Bwd Packets', 'Flow Bytes/s', 'Flow Packets/s']
            self.X = self.data[self.features].values
            self.y = self.data['Label'].values

            # Reshape data for CNN (samples, timesteps, features)
            self.X = self.X.reshape(self.X.shape[0], self.X.shape[1], 1)
        except Exception as e:
            print(f"Error loading dataset: {str(e)}")

    def build_model(self):
        model = Sequential([
            Conv1D(filters=64, kernel_size=3, activation='relu', input_shape=(8, 1)),
            MaxPooling1D(pool_size=2),
            Conv1D(filters=32, kernel_size=3, activation='relu'),
            MaxPooling1D(pool_size=2),
            Flatten(),
            Dense(100, activation='relu'),
            Dropout(0.5),
            Dense(50, activation='relu'),
            Dense(1, activation='sigmoid')
        ])

        model.compile(optimizer=Adam(learning_rate=0.001),
                     loss='binary_crossentropy',
                     metrics=['accuracy', tf.keras.metrics.AUC()])
        return model

    def get_model_metrics(self):
        metrics = {
            'model_type': 'CNN Deep Learning',
            'architecture': {
                'layers': [
                    {'name': 'Conv1D', 'filters': 64, 'kernel_size': 3},
                    {'name': 'MaxPooling1D', 'pool_size': 2},
                    {'name': 'Conv1D', 'filters': 32, 'kernel_size': 3},
                    {'name': 'MaxPooling1D', 'pool_size': 2},
                    {'name': 'Dense', 'units': 100},
                    {'name': 'Dense', 'units': 50},
                    {'name': 'Dense', 'units': 1}
                ]
            }
        }

        if self.history:
            metrics['training_history'] = {
                'accuracy': float(max(self.history.history['accuracy'])),
                'loss': float(min(self.history.history['loss'])),
                'auc': float(max(self.history.history['auc']))
            }

        return metrics

    def train(self, X, y):
        try:
            # Reshape input data for CNN
            X = X.reshape(X.shape[0], X.shape[1], 1)
            self.history = self.model.fit(
                X, y,
                epochs=10,
                batch_size=32,
                validation_split=0.2,
                verbose=1
            )
            return True
        except Exception as e:
            print(f"Error training model: {str(e)}")
            return False

    def evaluate(self, X_test, y_test):
        try:
            X_test = X_test.reshape(X_test.shape[0], X_test.shape[1], 1)
            return self.model.evaluate(X_test, y_test)[1]
        except Exception as e:
            print(f"Error evaluating model: {str(e)}")
            return None

    def save_model(self):
        self.model.save('models/nids_cnn_model.h5')

    def load_model(self):
        try:
            self.model = tf.keras.models.load_model('models/nids_cnn_model.h5')
            return self.model
        except:
            print("Error loading model from file. Returning new model.")
            return self.build_model()