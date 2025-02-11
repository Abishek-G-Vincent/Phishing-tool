from flask import Flask, request, jsonify
from flask_cors import CORS
import joblib
import numpy as np

app = Flask(__name__)
CORS(app)

model = joblib.load("phishing_detector.pkl")

@app.route('/predict', methods=['POST'])
def predict():
    try:
        data = request.get_json()
        features = np.array(data["features"]).reshape(1, -1)
        prediction = model.predict(features)

        result = "Phishing" if prediction[0] == -1 else "Legitimate"
        return jsonify({"prediction": result})
    except Exception as e:
        return jsonify({"error": "Error processing the request"}), 500

if __name__ == "__main__":
    app.run(debug=True)
