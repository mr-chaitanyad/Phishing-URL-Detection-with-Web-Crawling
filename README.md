# 🔍 Phishing URL Detection & Web Crawler

A Machine Learning–powered web application that detects phishing URLs and visualizes link relationships using a web crawler.

---

## 🚀 Features

* ✅ Detect whether a URL is **Phishing** or **Benign**
* 📊 Uses **TF-IDF + handcrafted features (50+)**
* 🤖 Model powered by **XGBoost**
* 🌐 Web crawler to extract and analyze links
* 🔗 Graph-based visualization (nodes & edges)
* 🛡️ Heuristic fallback when ML model is unavailable
* 🧪 Debug API to inspect extracted features

---

## 🧠 Machine Learning Pipeline

1. **Input URL**
2. Extract:

   * TF-IDF features (URL text)
   * 50+ engineered features:

     * URL length, entropy
     * Suspicious keywords
     * Domain properties
     * IP usage, ports, etc.
3. Feature Scaling using `StandardScaler`
4. Combine features:

   * TF-IDF + Numeric features
5. Prediction using XGBoost classifier

---

## 📁 Project Structure

```
webCrawler/
│
├── Model V3/
|   ├── templates/
│   |   └── index.html               # Frontend UI
│   ├── main.py                  # Flask backend
│   ├── xgb_tfidf_enhanced.pkl   # Trained model
│   ├── tfidf_vectorizer.pkl     # TF-IDF vectorizer
│   ├── numeric_scaler.pkl       # Feature scaler
│
│
└── README.md
```

---

## ⚙️ Installation

### 1️⃣ Clone the repository

```bash
git clone <your-repo-link>
cd webCrawler/Model\ V3
```

### 2️⃣ Install dependencies

```bash
pip install -r requirements.txt
```

Or manually:

```bash
pip install flask numpy pandas scikit-learn xgboost beautifulsoup4 requests scipy
```

---

## ▶️ Run the Application

```bash
python main.py
```

App will run at:

```
http://127.0.0.1:5000/
```

---

## 🔌 API Endpoints

### 🔹 1. Predict URL

**POST** `/predict`

```json
{
  "url": "https://example.com"
}
```

**Response:**

```json
{
  "prediction": "Phishing",
  "probability": 0.87
}
```

---

### 🔹 2. Crawl Website

**POST** `/crawl`

```json
{
  "url": "https://example.com"
}
```

Returns:

* Nodes (URLs)
* Edges (connections)

---

### 🔹 3. Feature Debugging

**POST** `/features`

```json
{
  "url": "https://example.com"
}
```

Returns:

* All extracted features
* Fired features
* Prediction details

---

## ⚠️ Configuration

### Detection Threshold

```python
PHISHING_THRESHOLD = 0.35
```

* Lower → more phishing detected (⚠️ more false positives)
* Higher → safer predictions (⚠️ may miss attacks)

---

## 🧪 Example Results

| URL                     | Prediction | Probability |
| ----------------------- | ---------- | ----------- |
| google.com              | Benign     | 0.10        |
| paypal-secure-login.xyz | Phishing   | 0.99        |
| 192.168.1.1/login       | Phishing   | 1.00        |

---

## 🛠️ Technologies Used

* Python
* Flask
* Scikit-learn
* XGBoost
* BeautifulSoup
* Pandas / NumPy
* SciPy

---

## ⚡ Fallback Mechanism

If ML model fails or is not loaded:

➡️ System switches to **rule-based heuristic scoring**

---

## 📌 Future Improvements

* 🔍 Domain reputation API integration
* 🌐 Real-time browser extension
* 📊 Advanced graph visualization
* 🤖 Deep learning models (LSTM / Transformer)

---

## 👨‍💻 Author

**Chaitanya Dhayarkar**

---

## 📜 License

This project is for educational and research purposes.
