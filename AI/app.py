# # Thêm các thư viện cần thiết:

import pandas as pd
import numpy as np
import re
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import RandomForestClassifier
from sklearn.tree import DecisionTreeClassifier
from sklearn.pipeline import Pipeline
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score
from sklearn.model_selection import train_test_split
from sklearn.decomposition import PCA, TruncatedSVD

from sklearn.preprocessing import LabelBinarizer
from sklearn import metrics
from sklearn.svm import SVC
from sklearn.naive_bayes import MultinomialNB
from sklearn.preprocessing import MaxAbsScaler, MinMaxScaler, StandardScaler
from tensorflow.keras.models import load_model

from scipy.sparse import issparse
import joblib
from flask import Flask, request, jsonify
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.base import MIMEBase
from email import encoders
import smtplib

app = Flask(__name__)

# Hàm gửi email cảnh báo
def send_notification(image, message):
    sender_email = "12c1chuyenphanngochien@gmail.com"  # Email của bạn
    sender_password = "gqyj kqmq kaas ljcs"  # Mật khẩu ứng dụng Gmail
    recipient_email = "trunghieudonguyen4@gmail.com"  # Email người nhận
    subject = "Detection Notification"
    
    # Tạo đối tượng email
    msg = MIMEMultipart()
    msg['From'] = sender_email
    msg['To'] = recipient_email
    msg['Subject'] = subject

    # Thêm nội dung email
    msg.attach(MIMEText(message, 'plain'))

    # Đính kèm hình ảnh cảnh báo
    if image:
        with open(image, "rb") as attachment:
            part = MIMEBase("application", "octet-stream")
            part.set_payload(attachment.read())
            encoders.encode_base64(part)
            part.add_header(
                "Content-Disposition",
                f"attachment; filename= {image}",
            )
            msg.attach(part)

    # Thiết lập kết nối SMTP và gửi email
    try:
        server = smtplib.SMTP('smtp.gmail.com', 587)
        server.starttls()
        server.login(sender_email, sender_password)
        server.sendmail(sender_email, recipient_email, msg.as_string())
        server.quit()
        print("Email đã được gửi thành công!")
    except Exception as e:
        print(f"Không thể gửi email. Lỗi: {str(e)}")


class Detection:
    def __init__(self):
        self.model = load_model('mlp_detection.h5')
        self.vectorizer = joblib.load('tfidf_vectorizer.joblib')
        self.labelsML = ['CMDI', 'NORMAL', 'PATH-TRAVERSAL', 'SQLI', 'XSS'] 
        self.labels_encML = [0, 1, 2, 3, 4]
        self.demxss = 0
        self.demsql = 0
        self.demcmd = 0
        self.dem = 0
        self.dembrute = 1
    
    def pre_data(self, text):
        # Biểu thức chính quy để trích xuất thông tin
        log_pattern = re.compile(r'(?P<ip>\d+\.\d+\.\d+\.\d+) - - \[\d{2}/\w{3}/\d{4}:\d{2}:\d{2}:\d{2} \+\d{4}\] "(?P<method>[A-Z]+) (?P<payload>[^"]+) HTTP/[\d.]+"')

        match = log_pattern.search(text)
        if match:
            payload = match.group('payload')
            patternURL = re.compile(r'^(?P<path>[^?]+)\?(?P<query>.*)$')
            match2 = patternURL.search(payload)
            if match2:
                path = match2.group('path')  # Phần đường dẫn
                query = match2.group('query')  # Phần sau dấu ?
                return np.array([query]), path
            else:
                return False, False 
        else:
            return False, False
        
    def get_lb(self, link, label):
        label_dem = ""
        if "sqli" in link.lower():
            label_dem = "SQLI"
            self.demsql += 1
        elif "xss_" in link.lower(): 
            label_dem = "XSS"
            self.demxss += 1
        elif "exec" in link.lower():
            label_dem = "CMDI"
            self.demcmd += 1
        else:
            label_dem = "NORMAL"
        if label =="NORMAL":
            if self.demsql > 5 and label_dem == "SQLI":
                self.demsql = 0
                return label_dem
            elif self.demxss > 5 and label_dem == "XSS":
                self.demxss = 0
                return label_dem
            elif self.demcmd > 5 and label_dem == "CMDI":
                self.demcmd = 0
                return label_dem
            else:
                return "NORMAL"
        else:
            return label 
        
    def get_labels(self, text):
        X, link = self.pre_data(text)
        if X == False:
            return "NORMAL"
        if "brute" in link.lower():
            self.dembrute += 1
            if self.dembrute > 5:
                self.dembrute = 0
                return "BRUTE-FORCE"
            else: 
                return "NORMAL"
        if "exec" in text.lower():
            return "COMMAND INJECTION"
        tfidf_train = self.vectorizer.transform(X)  # (1, 8000)
        X_dense = tfidf_train.toarray()           # (1, 8000)
        X_dense = X_dense.reshape((X_dense.shape[0],X_dense.shape[1]))
        Y_pred_prob = self.model.predict(X_dense)
        Y_pred = np.argmax(Y_pred_prob, axis=1)
        label1 = self.labelsML[Y_pred[0]]
        return label1

detec = Detection()
detec.demxss = 1
detec.dembrute = 1

@app.route('/prediction', methods=['POST'])
def predict():
    try:
        data = request.get_json()
        if data is None:
            return jsonify({'error': 'Invalid JSON'})
        else:
            input_text = data.get('text', '')
            label = detec.get_labels(input_text)
            strings = "Cảnh báo, xảy ra tấn công `" + label + "` trên hệ thống web!"
            if label != "NORMAL" and label != "Lỗi đầu vào":
                send_notification("shivanya.jpg", strings)  # Gửi email cảnh báo
            return jsonify({'Label': label})
    except Exception as e:
        return jsonify({'Label': "NORMAL"})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5010, debug=True)
