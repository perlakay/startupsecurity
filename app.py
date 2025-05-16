from flask import Flask, render_template, request, jsonify
import validators
import requests
import dns.resolver
import whois
from bs4 import BeautifulSoup
import json
from datetime import datetime
import re
from urllib.parse import urlparse
import os
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)

def validate_url(url):
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
    return validators.url(url)

def get_dns_info(domain):
    try:
        records = {}
        for record_type in ['A', 'AAAA', 'MX', 'NS', 'TXT']:
            try:
                answers = dns.resolver.resolve(domain, record_type)
                records[record_type] = [str(rdata) for rdata in answers]
            except:
                continue
        return records
    except Exception as e:
        return {"error": str(e)}

def get_whois_info(domain):
    try:
        w = whois.whois(domain)
        return {
            "registrar": w.registrar,
            "creation_date": str(w.creation_date),
            "expiration_date": str(w.expiration_date),
            "name_servers": w.name_servers
        }
    except Exception as e:
        return {"error": str(e)}

def get_headers(url):
    try:
        response = requests.get(url, timeout=10)
        return dict(response.headers)
    except Exception as e:
        return {"error": str(e)}

def get_tech_stack(url):
    try:
        response = requests.get(url, timeout=10)
        soup = BeautifulSoup(response.text, 'html.parser')
        
        # Basic tech detection
        techs = {
            "server": response.headers.get('Server', 'Unknown'),
            "powered_by": response.headers.get('X-Powered-By', 'Unknown'),
            "frameworks": [],
            "cms": None
        }
        
        # Check for common frameworks
        if 'wp-content' in response.text:
            techs["cms"] = "WordPress"
        elif 'drupal' in response.text.lower():
            techs["cms"] = "Drupal"
            
        return techs
    except Exception as e:
        return {"error": str(e)}

def get_robots_txt(url):
    try:
        robots_url = f"{url.rstrip('/')}/robots.txt"
        response = requests.get(robots_url, timeout=10)
        return response.text if response.status_code == 200 else "No robots.txt found"
    except:
        return "Error fetching robots.txt"

def find_subdomains(domain):
    try:
        url = f'https://crt.sh/?q=%25.{domain}&output=json'
        response = requests.get(url, timeout=10)
        if response.status_code != 200:
            return []
        data = response.json()
        subdomains = set()
        for entry in data:
            name_value = entry.get('name_value', '')
            for sub in name_value.split('\n'):
                if sub.endswith(domain):
                    subdomains.add(sub.strip())
        return sorted(subdomains)
    except Exception as e:
        return [f"Error: {e}"]

def calculate_security_score(results):
    score = 10
    deductions = {
        "no_https": 2,
        "exposed_server": 1,
        "exposed_tech": 1,
        "no_security_headers": 2,
        "exposed_robots": 1
    }
    
    if not results.get('url', '').startswith('https'):
        score -= deductions["no_https"]
    
    if results.get('headers', {}).get('Server'):
        score -= deductions["exposed_server"]
        
    if results.get('tech_stack', {}).get('server') != 'Unknown':
        score -= deductions["exposed_tech"]
        
    if not any(h.lower().startswith(('x-frame-options', 'x-content-type-options', 'x-xss-protection')) 
              for h in results.get('headers', {}).keys()):
        score -= deductions["no_security_headers"]
        
    if results.get('robots_txt') != "No robots.txt found":
        score -= deductions["exposed_robots"]
        
    return max(0, min(10, score))

def generate_roast(results, score):
    roasts = [
        f"Your website security is like a screen door on a submarine - {score}/10",
        f"I've seen better security in a paper house during a hurricane - {score}/10",
        f"Your security is so weak, it makes a wet paper bag look like Fort Knox - {score}/10",
        f"This security is like using a screen door to keep out a tornado - {score}/10",
        f"Your website's security is like a chocolate teapot - {score}/10"
    ]
    
    return roasts[score % len(roasts)]

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/scan', methods=['POST'])
def scan():
    url = request.json.get('url', '').strip()
    
    if not validate_url(url):
        return jsonify({"error": "Invalid URL format"}), 400
        
    domain = urlparse(url).netloc
    
    results = {
        "url": url,
        "domain": domain,
        "dns_info": get_dns_info(domain),
        "whois_info": get_whois_info(domain),
        "headers": get_headers(url),
        "tech_stack": get_tech_stack(url),
        "robots_txt": get_robots_txt(url),
        "subdomains": find_subdomains(domain),
        "scan_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    }
    
    score = calculate_security_score(results)
    roast = generate_roast(results, score)
    
    results["security_score"] = score
    results["roast"] = roast
    
    return jsonify(results)

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port) 