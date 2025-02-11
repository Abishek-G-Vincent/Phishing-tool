# Import necessary libraries
import joblib
import warnings
import pandas as pd
import seaborn as sns
import numpy as np
from sklearn.metrics import confusion_matrix, classification_report, accuracy_score, precision_score, recall_score, f1_score
from sklearn.model_selection import train_test_split
from sklearn.neural_network import MLPClassifier
from sklearn.preprocessing import StandardScaler
from ucimlrepo import fetch_ucirepo

# Suppress warnings
warnings.filterwarnings('ignore')

# Load the dataset
phishing_websites = fetch_ucirepo(id=327)

# Data (as pandas dataframes)
X = phishing_websites.data.features
y = phishing_websites.data.targets

# Data info
print(phishing_websites.metadata)
print(phishing_websites.variables)

# Check data info
X.info()
y.info()

# Data visualization using Seaborn
df = pd.concat([X, y], axis=1)

# Plot the distribution of 'having_ip_address' vs 'result'
sns.catplot(x='having_ip_address', hue='result', data=df, kind='count')
sns.catplot(x='result', data=df, kind='count')

# Normalize the features data
X_min_max_scaled = X.copy()

for column in X_min_max_scaled.columns[:]:
    X_min_max_scaled[column] = (X_min_max_scaled[column] - X_min_max_scaled[column].min()) / (X_min_max_scaled[column].max() - X_min_max_scaled[column].min())

# Assign normalized data back to X
X = X_min_max_scaled

# Normalize the target variable (y)
y_min_max_scaled = y.copy()
y_min_max_scaled = (y_min_max_scaled - y_min_max_scaled.min()) / (y_min_max_scaled.max() - y_min_max_scaled.min())

# Split data into training and testing sets
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.3, random_state=42)

# Define and train the MLP model
model1 = MLPClassifier(hidden_layer_sizes=(100, 50), activation='relu', alpha=0.05,
                       learning_rate_init=0.001, learning_rate='constant', batch_size=10, max_iter=1000)

model1.fit(X_train, y_train)

# Save the model to a file
joblib.dump(model1, 'phishing_detection_model.joblib')
print("Model saved as 'phishing_detection_model.joblib'.")

# Predict on the test set
y_pred = model1.predict(X_test)

# Confusion matrix
cm = confusion_matrix(y_test, y_pred)
tn, fp, fn, tp = cm.ravel()

print('Confusion Matrix:')
print(cm)
print(f'True Positives: {tp}')
print(f'True Negatives: {tn}')
print(f'False Positives: {fp}')
print(f'False Negatives: {fn}')

# Classification report
print(classification_report(y_test, y_pred))

# Accuracy, Precision, Recall, F1-Score, Specificity
accuracy = accuracy_score(y_test, y_pred)
print("Accuracy:", accuracy)

precision = precision_score(y_test, y_pred)
print("Precision:", precision)

recall = recall_score(y_test, y_pred)
print("Recall:", recall)

f1 = f1_score(y_test, y_pred)
print("F1-score:", f1)

specificity = tn / (fp + tn)
print("Specificity:", specificity)
