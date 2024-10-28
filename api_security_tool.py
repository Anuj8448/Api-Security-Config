from flask import Flask, jsonify, request, render_template
import subprocess
import requests
import jwt
import time
from report_generator import generate_compliance_report

app = Flask(__name__)

# Global settings
API_KEY = "your-api-key-here"
JWT_SECRET = "your-jwt-secret-here"
POSTMAN_COLLECTION = "api_collection.json"

headers = {
    'Authorization': f'Bearer {API_KEY}',
    'Content-Type': 'application/json'
}

# --------------------- Helper Functions ---------------------

def check_https(url):
    if not url.startswith("http://") and not url.startswith("https://"):
        url = "https://" + url  # Default to HTTPS if no scheme is provided
    try:
        response = requests.get(url, verify=True)
        if response.url.startswith('https'):
            return True, "HTTPS is enforced."
        else:
            return False, "HTTPS is not enforced."
    except requests.exceptions.SSLError:
        return False, "SSL certificate error."
    except requests.exceptions.MissingSchema:
        return False, "Invalid URL format. Ensure the URL includes a scheme (e.g., 'https://')."

def check_jwt(token, secret):
    try:
        decoded = jwt.decode(token, secret, algorithms=["HS256"])
        return True, "JWT is valid."
    except jwt.ExpiredSignatureError:
        return False, "JWT token has expired."
    except jwt.InvalidTokenError:
        return False, "Invalid JWT token."

def test_rate_limiting(api_url, headers):
    for i in range(10):
        response = requests.get(api_url, headers=headers)
        if response.status_code == 429:
            return True, "Rate limiting is enforced."
        time.sleep(0.5)
    return False, "Rate limiting is not enforced."

def extract_hostname(url):
    # Extract hostname from URL (without path or scheme)
    hostname = url.split("//")[-1].split("/")[0]
    return hostname

# --------------------- Integration with Tools ---------------------

def run_postman_tests(collection_file):
    try:
        command = f"newman run {collection_file} --reporters cli,html --reporter-html-export newman_report.html"
        subprocess.run(command, shell=True, check=True)
        return True, "Postman API tests completed. Check newman_report.html for details."
    except subprocess.CalledProcessError as e:
        return False, f"Postman API tests failed: {str(e)}"

def run_owasp_zap_scan(api_url):
    try:
        scan_command = f"zap-api-scan.py -t {api_url} -r zap_report.html"
        subprocess.run(scan_command, shell=True, check=True)
        return True, "OWASP ZAP scan completed. Check zap_report.html for details."
    except subprocess.CalledProcessError as e:
        return False, f"OWASP ZAP scan failed: {str(e)}"

def run_nmap_scan(api_url):
    try:
        hostname = extract_hostname(api_url)
        scan_command = f"nmap -Pn -sV {hostname}"
        result = subprocess.run(scan_command, shell=True, check=True, capture_output=True, text=True)
        return True, f"Nmap scan completed:\n{result.stdout}"
    except subprocess.CalledProcessError as e:
        return False, f"Nmap scan failed: {str(e)}"

def run_sslyze_scan(api_url):
    try:
        hostname = extract_hostname(api_url)
        scan_command = f"sslyze --regular {hostname}"
        result = subprocess.run(scan_command, shell=True, check=True, capture_output=True, text=True)
        return True, f"SSLyze scan completed:\n{result.stdout}"
    except subprocess.CalledProcessError as e:
        return False, f"SSLyze scan failed: {str(e)}"

# --------------------- Flask Routes for UI ---------------------

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/run-tests', methods=['POST'])
def run_tests():
    api_url = request.json.get('url')
    if not api_url:
        return jsonify({"error": "API URL is required"}), 400

    results = {}

    print("Running HTTPS enforcement check...")
    results["HTTPS Enforcement"] = check_https(api_url)

    print("Validating JWT token...")
    jwt_token = jwt.encode({"user": "test"}, JWT_SECRET, algorithm="HS256")
    results["JWT Validation"] = check_jwt(jwt_token, JWT_SECRET)

    print("Testing rate limiting...")
    results["Rate Limiting"] = test_rate_limiting(api_url, headers)

    print("Running Postman API tests...")
    results["Postman API Tests"] = run_postman_tests(POSTMAN_COLLECTION)

    print("Running OWASP ZAP scan...")
    results["OWASP ZAP Scan"] = run_owasp_zap_scan(api_url)

    print("Running Nmap scan...")
    results["Nmap Scan"] = run_nmap_scan(api_url)

    print("Running SSLyze scan...")
    results["SSLyze Scan"] = run_sslyze_scan(api_url)

    # Generate compliance report
    compliance_report = generate_compliance_report(results)
    
    # Return the results and report in JSON format
    return jsonify({"report": compliance_report, "results": results})

if __name__ == "__main__":
    app.run(debug=True)
