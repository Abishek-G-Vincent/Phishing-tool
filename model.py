import pandas as pd
import numpy as np

import joblib

from sklearn.model_selection import train_test_split, StratifiedKFold, cross_val_score
from sklearn.metrics import accuracy_score, classification_report
from xgboost import XGBClassifier

df = pd.read_csv("Training_Dataset.csv")

print("Dataset Shape:", df.shape)
print(df.head())

# Check for missing values
print("Missing Values:\n", df.isnull().sum())

X = df.iloc[:, :-1]
y = df.iloc[:, -1]


X = df.iloc[:, :-1]
y = df.iloc[:, -1]

y = y.replace(-1, 0)

X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)

xgb_model = XGBClassifier(eval_metric="logloss", n_estimators=100, random_state=42)
xgb_model.fit(X_train, y_train)

y_pred = xgb_model.predict(X_test)


accuracy = accuracy_score(y_test, y_pred)
print(f"Model Accuracy: {accuracy:.4f}")
print("\nClassification Report:\n", classification_report(y_test, y_pred))

joblib.dump(xgb_model, "phishing_detector.pkl")


cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
scores = cross_val_score(xgb_model, X, y, cv=cv, scoring="accuracy")

print(f"Mean Cross-Validation Accuracy: {scores.mean():.4f}")

joblib.dump(xgb_model, "phishing_detector.pkl")
print("Model Saved as phishing_detector.pkl ✅")


def predict_website(features):
    if len(features) != 30:
        raise ValueError(f"Expected 30 features, but got {len(features)}")

    prediction = xgb_model.predict([features])
    return "Phishing" if prediction[0] == 0 else "Legitimate"



example_website = [-1,1,1,1,-1,-1,-1,-1,-1,1,1,-1,1,-1,1,-1,-1,-1,0,1,1,1,1,-1,-1,-1,-1,1,1,-1]
print("Prediction:", predict_website(example_website))
