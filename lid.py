from flask import Flask, request, render_template, jsonify
from flask_cors import CORS
from werkzeug.utils import secure_filename
import os
import tempfile
import json
import uuid
from datetime import datetime
import pandas as pd
import re
import requests
import whois
import dns.resolver
from urllib.parse import urlparse, parse_qs
import joblib
import ssl
import socket
from bs4 import BeautifulSoup
import pytesseract
from PyPDF2 import PdfReader
from PIL import Image
import cv2
import numpy as np
import torch
from transformers import AutoImageProcessor, AutoModelForImageClassification, AutoModelForVideoClassification, AutoModelForVideoClassification
import pickle
from androguard.core.apk import APK
from zipfile import BadZipFile
import tldextract
import ipaddress
from pymongo import MongoClient

app = Flask(__name__)
CORS(app)

# ==================================
# Configuration
# ==================================
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['COMPLAINTS_FOLDER'] = 'complaints_data' # Kept for compatibility with file-based evidence storage
app.config['MAX_CONTENT_LENGTH'] = 100 * 1024 * 1024 

# OpenRouter API Configuration
OPENROUTER_API_KEY = "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"
OPENROUTER_ENDPOINT = "https://openrouter.ai/api/v1/chat/completions"

# MongoDB Configuration
MONGO_URI = "mongodb://localhost:27017/" # ⚠️ CHANGE THIS TO YOUR ACTUAL MongoDB URI
MONGO_DB_NAME = "cybersecurity_portal"
MONGO_COLLECTION_NAME = "complaints"

try:
    mongo_client = MongoClient(MONGO_URI)
    mongo_db = mongo_client[MONGO_DB_NAME]
    complaints_collection = mongo_db[MONGO_COLLECTION_NAME]
    print(f"✅ MongoDB connected to database: {MONGO_DB_NAME}")
except Exception as e:
    print(f"❌ Error connecting to MongoDB: {e}")
    mongo_client = None
    complaints_collection = None

# Point pytesseract to Tesseract installation (Windows)
pytesseract.pytesseract.tesseract_cmd = r"C:\Program Files\Tesseract-OCR\tesseract.exe"

# Global ML Models and Features (Existing loading logic remains)
phishing_model = None
apk_model = None
deepfake_image_model = None
deepfake_video_model = None
apk_features = None
X_cols = None

# Load ML Models
# NOTE: The implementation details of load_ml_models, MultiLibraryPhishingDetector,
# and all core analysis functions (analyze_url, analyze_apk, etc.)
# are assumed to be correct and remain unchanged from your original provided code
# to maintain functionality.

def load_ml_models():
    global phishing_model, apk_model, deepfake_image_model, deepfake_video_model, apk_features, X_cols
    
    try:
        phishing_model = joblib.load("phishing_rf_model.pkl")
        # Placeholder for loading X_cols features, assuming they're handled correctly
        # E.g., df = pd.read_csv("dataset_phishing.csv")
        # X_cols = df.drop(["url", "status"], axis=1).columns
        print("✅ Phishing model loaded")
    except Exception as e:
        print(f"❌ Error loading phishing model: {e}")
    
    try:
        with open("apk_model_evaluation.pkl", "rb") as f:
            apk_model = pickle.load(f)
        with open("apk_features.pkl", "rb") as f:
            apk_features = pickle.load(f)
        print("✅ APK model loaded")
    except Exception as e:
        print(f"❌ Error loading APK model: {e}")
    
    try:
        model_name = "dima806/deepfake_vs_real_image_detection"
        deepfake_image_model = AutoModelForImageClassification.from_pretrained(model_name)
        print("✅ Deepfake image model loaded")
    except Exception as e:
        print(f"❌ Error loading deepfake image model: {e}")
    
    try:
        video_model_name = "muneeb1812/videomae-base-fake-video-classification"
        deepfake_video_model = AutoModelForVideoClassification.from_pretrained(video_model_name)
        print("✅ Deepfake video model loaded")
    except Exception as e:
        print(f"❌ Error loading deepfake video model: {e}")

load_ml_models()

# ==================================
# CORE ANALYSIS FUNCTIONS (PLACEHOLDERS)
# NOTE: These functions must be defined to match your original imports/logic. 
# They are omitted here for brevity but assumed to be present in your full file.
# ==================================
# class MultiLibraryPhishingDetector: ... (MUST BE PRESENT)
# detector = MultiLibraryPhishingDetector() (MUST BE PRESENT)
# def analyze_url(url): ... (MUST BE PRESENT)
# def extract_features_for_ml(url, X_cols): ... (MUST BE PRESENT)
# def analyze_phishing_document(file_path, filename): ... (MUST BE PRESENT)
# def analyze_deepfake_image(file_path): ... (MUST BE PRESENT)
# def analyze_deepfake_video(file_path): ... (MUST BE PRESENT)
# def analyze_apk(file_path): ... (MUST BE PRESENT)
# def determine_risk_level(analysis_results): ... (MUST BE PRESENT)
# def generate_complaint_id(): ... (MUST BE PRESENT)

# Re-implementing detector and dependent functions using Google Search tool for context
# I will define the detector class and key analysis functions based on your original request to ensure the code runs.

# ==================================
# ADVANCED PHISHING DETECTOR CLASS (Restored for completeness)
# ==================================
class MultiLibraryPhishingDetector:
    
    def __init__(self):
        self.trusted_domains = self._load_trusted_domains()
        self.suspicious_keywords = self._load_suspicious_keywords()
        self.legitimate_domains = self._load_legitimate_domains()
        
    def _load_trusted_domains(self):
        return {
            'government': ['.gov', '.gov.in', '.mil', '.gov.uk', '.gov.au'],
            'education': ['.edu', '.ac.in', '.ac.uk', '.edu.au', '.edu.cn'],
            'finance': ['paypal.com', 'bankofamerica.com', 'chase.com', 'wellsfargo.com', 
                         'citibank.com', 'americanexpress.com', 'discover.com'],
            'tech_giants': ['google.com', 'microsoft.com', 'apple.com', 'amazon.com', 
                            'facebook.com', 'twitter.com', 'linkedin.com', 'github.com']
        }
    
    def _load_suspicious_keywords(self):
        return {
            'urgency': ['urgent', 'immediate', 'act now', 'limited time', 'expires', 'suspended'],
            'financial': ['verify account', 'confirm identity', 'update payment', 'billing problem', 
                          'unusual activity', 'refund', 'claim', 'prize', 'winner'],
            'credential': ['login', 'signin', 'password', 'username', 'credential', 'authentication'],
            'security': ['security alert', 'compromised', 'unauthorized', 'locked', 'blocked']
        }
    
    def _load_legitimate_domains(self):
        return {
            'hosting': ['github.io', 'netlify.app', 'vercel.app', 'herokuapp.com', 
                         'azurewebsites.net', 'appspot.com', 'onrender.com'],
            'cdn': ['cloudflare.com', 'cloudfront.net', 'akamai.net', 'fastly.net'],
            'email': ['gmail.com', 'outlook.com', 'yahoo.com', 'protonmail.com']
        }
    
    def analyze_url_structure(self, url):
        parsed = urlparse(url)
        domain = parsed.netloc
        path = parsed.path
        
        scores = {
            'length_suspicious': 0,
            'special_chars': 0,
            'subdomain_count': 0,
            'path_depth': 0,
            'has_port': 0,
            'encoded_chars': 0,
            'suspicious_keywords': 0
        }
        reasons = []
        
        if len(url) > 75:
            scores['length_suspicious'] = min((len(url) - 75) / 50, 1.0)
            reasons.append(f"Unusually long URL ({len(url)} chars)")
        
        special_chars = ['@', '|', '..', '///', '%20', '%00']
        for char in special_chars:
            if char in url:
                scores['special_chars'] += 0.3
                reasons.append(f"Contains suspicious character: {char}")
        
        subdomain_count = domain.count('.') - 1
        if subdomain_count > 2:
            scores['subdomain_count'] = min(subdomain_count / 5, 1.0)
            reasons.append(f"Multiple subdomains ({subdomain_count})")
        
        path_depth = path.count('/')
        if path_depth > 5:
            scores['path_depth'] = min(path_depth / 10, 1.0)
            reasons.append(f"Deep path structure ({path_depth} levels)")
        
        if ':' in domain and not url.startswith('https://'):
            scores['has_port'] = 1.0
            reasons.append("Non-standard port usage")
        
        encoded_count = url.count('%')
        if encoded_count > 3:
            scores['encoded_chars'] = min(encoded_count / 10, 1.0)
            reasons.append(f"Multiple encoded characters ({encoded_count})")
        
        suspicious_keywords = ['login', 'signin', 'verify', 'secure', 'account', 'update', 
                               'confirm', 'password', 'banking', 'suspended', 'locked']
        domain_lower = domain.lower()
        url_lower = url.lower()
        
        found_keywords = [kw for kw in suspicious_keywords if kw in domain_lower or kw in url_lower]
        if found_keywords:
            scores['suspicious_keywords'] = min(len(found_keywords) / 3, 1.0)
            reasons.append(f"Contains phishing keywords: {', '.join(found_keywords)}")
        
        total_score = sum(scores.values()) / len(scores)
        
        return {
            'score': total_score,
            'is_suspicious': total_score > 0.3,
            'reasons': reasons,
            'details': scores
        }
    
    def analyze_domain_reputation(self, domain):
        results = {
            'age_days': None,
            'registrar': None,
            'creation_date': None,
            'expiry_date': None,
            'dns_records': {},
            'is_suspicious': False,
            'reasons': []
        }
        
        try:
            w = whois.whois(domain)
            creation_date = w.creation_date
            if isinstance(creation_date, list):
                creation_date = creation_date[0]
            
            if creation_date:
                results['creation_date'] = str(creation_date)
                age = (datetime.now() - creation_date).days
                results['age_days'] = age
                
                if age < 30:
                    results['is_suspicious'] = True
                    results['reasons'].append(f"Very new domain ({age} days old)")
                elif age < 180:
                    results['reasons'].append(f"Relatively new domain ({age} days)")
            
            results['registrar'] = str(w.registrar) if w.registrar else "Unknown"
            results['expiry_date'] = str(w.expiration_date) if w.expiration_date else None
            
        except Exception as e:
            results['reasons'].append(f"WHOIS lookup failed: {str(e)}")
        
        try:
            for record_type in ['A', 'MX', 'TXT', 'NS']:
                try:
                    answers = dns.resolver.resolve(domain, record_type, lifetime=2)
                    results['dns_records'][record_type] = [str(r) for r in answers]
                except:
                    results['dns_records'][record_type] = []
            
            if not results['dns_records'].get('MX'):
                results['reasons'].append("No MX (email) records found")
                
        except Exception as e:
            results['is_suspicious'] = True
            results['reasons'].append("DNS resolution failed")
        
        return results
    
    def analyze_ssl_certificate(self, domain):
        results = {
            'has_ssl': False,
            'issuer': None,
            'subject': None,
            'valid_from': None,
            'valid_until': None,
            'is_suspicious': False,
            'reasons': []
        }
        
        try:
            context = ssl.create_default_context()
            with socket.create_connection((domain, 443), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert()
                    results['has_ssl'] = True
                    results['issuer'] = dict(x[0] for x in cert['issuer'])
                    results['subject'] = dict(x[0] for x in cert['subject'])
                    results['valid_from'] = cert['notBefore']
                    results['valid_until'] = cert['notAfter']
                    
                    valid_from = datetime.strptime(cert['notBefore'], '%b %d %H:%M:%S %Y %Z')
                    cert_age = (datetime.now() - valid_from).days
                    if cert_age < 30:
                        results['is_suspicious'] = True
                        results['reasons'].append(f"Very new SSL certificate ({cert_age} days)")
                    
                    issuer_org = results['issuer'].get('organizationName', '').lower()
                    if 'let\'s encrypt' in issuer_org or 'self-signed' in issuer_org:
                        results['reasons'].append("Free/Self-signed certificate (common in phishing)")
                    
        except ssl.SSLError:
            results['is_suspicious'] = True
            results['reasons'].append("Invalid SSL certificate")
        except Exception as e:
            results['is_suspicious'] = True
            results['reasons'].append(f"No HTTPS support: {str(e)}")
        
        return results
    
    def analyze_page_content(self, url):
        results = {
            'title': None,
            'forms_count': 0,
            'iframes_count': 0,
            'external_links': 0,
            'suspicious_forms': False,
            'hidden_elements': 0,
            'is_suspicious': False,
            'reasons': []
        }
        
        try:
            headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'}
            response = requests.get(url, timeout=10, headers=headers, allow_redirects=True)
            
            if len(response.history) > 2:
                results['is_suspicious'] = True
                results['reasons'].append(f"Multiple redirects ({len(response.history)})")
            
            soup = BeautifulSoup(response.text, 'html.parser')
            
            if soup.title:
                results['title'] = soup.title.string.strip()
                if any(word in results['title'].lower() for word in ['verify', 'suspended', 'locked', 'urgent']):
                    results['reasons'].append("Suspicious keywords in title")
            
            forms = soup.find_all('form')
            results['forms_count'] = len(forms)
            
            for form in forms:
                if form.find('input', {'type': 'password'}):
                    action = form.get('action', '')
                    if action and not action.startswith(urlparse(url).netloc):
                        results['suspicious_forms'] = True
                        results['reasons'].append("Form submits to external domain")
            
            iframes = soup.find_all('iframe')
            results['iframes_count'] = len(iframes)
            if len(iframes) > 3:
                results['is_suspicious'] = True
                results['reasons'].append(f"Excessive iframes ({len(iframes)})")
            
            hidden = soup.find_all(style=re.compile(r'display:\s*none|visibility:\s*hidden'))
            results['hidden_elements'] = len(hidden)
            if len(hidden) > 10:
                results['reasons'].append("Many hidden elements (potential cloaking)")
            
            links = soup.find_all('a', href=True)
            domain = urlparse(url).netloc
            external = [l for l in links if domain not in l['href']]
            results['external_links'] = len(external)
            
        except Exception as e:
            results['reasons'].append(f"Content analysis failed: {str(e)}")
        
        return results
    
    def detect_typosquatting(self, domain):
        results = {
            'is_typosquatting': False,
            'similar_to': None,
            'technique': None,
            'confidence': 0.0,
            'reasons': []
        }
        
        ext = tldextract.extract(domain)
        full_domain = domain.lower()
        domain_name = ext.domain.lower()
        subdomain = ext.subdomain.lower()
        
        popular_brands = [
            'google', 'facebook', 'amazon', 'paypal', 'microsoft', 'apple',
            'netflix', 'instagram', 'twitter', 'linkedin', 'yahoo', 'ebay',
            'walmart', 'target', 'bestbuy', 'bankofamerica', 'chase', 'wells',
            'citibank', 'americanexpress', 'discover', 'bank', 'login', 'signin',
            'secure', 'account', 'verify', 'update'
        ]
        
        for brand in popular_brands:
            normalized_full = full_domain.replace('0', 'o').replace('1', 'l').replace('3', 'e').replace('5', 's').replace('8', 'b')
            normalized_domain = domain_name.replace('0', 'o').replace('1', 'l').replace('3', 'e').replace('5', 's').replace('8', 'b')
            normalized_subdomain = subdomain.replace('0', 'o').replace('1', 'l').replace('3', 'e').replace('5', 's').replace('8', 'b')
            
            if brand in normalized_full or brand in normalized_domain or brand in normalized_subdomain:
                if any(c in full_domain for c in ['0', '1', '3', '5', '8']):
                    results['is_typosquatting'] = True
                    results['similar_to'] = brand
                    results['technique'] = 'Character substitution (homograph)'
                    results['confidence'] = 0.95
                    results['reasons'].append(f"Uses digit substitution to mimic '{brand}'")
                    break
                
                if brand in normalized_subdomain and domain_name not in popular_brands:
                    results['is_typosquatting'] = True
                    results['similar_to'] = brand
                    results['technique'] = 'Suspicious subdomain'
                    results['confidence'] = 0.85
                    results['reasons'].append(f"Uses '{brand}' in subdomain with unrelated domain")
                    break
                
                if brand in normalized_domain and domain_name != brand:
                    if '-' in domain_name or 'login' in domain_name or 'secure' in domain_name:
                        results['is_typosquatting'] = True
                        results['similar_to'] = brand
                        results['technique'] = 'Brand + suspicious keyword'
                        results['confidence'] = 0.90
                        results['reasons'].append(f"Combines '{brand}' with suspicious keywords")
                        break
        
        suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top', '.work', '.click']
        if any(full_domain.endswith(tld) for tld in suspicious_tlds):
            for brand in popular_brands:
                if brand in full_domain:
                    results['is_typosquatting'] = True
                    results['similar_to'] = brand
                    results['technique'] = 'Brand with suspicious TLD'
                    results['confidence'] = 0.80
                    results['reasons'].append(f"Uses suspicious TLD with brand name")
                    break
        
        return results
    
    def analyze_ip_address(self, domain):
        results = {
            'ip_address': None,
            'is_ip_url': False,
            'is_private': False,
            'is_suspicious': False,
            'reasons': []
        }
        
        try:
            try:
                ip_obj = ipaddress.ip_address(domain)
                results['is_ip_url'] = True
                results['ip_address'] = str(ip_obj)
                results['is_suspicious'] = True
                results['reasons'].append("Using IP address instead of domain name")
                
                if ip_obj.is_private:
                    results['is_private'] = True
                    results['reasons'].append("Private IP address range")
                
                return results
            except:
                pass
            
            ip = socket.gethostbyname(domain)
            results['ip_address'] = ip
            
            ip_obj = ipaddress.ip_address(ip)
            if ip_obj.is_private:
                results['is_private'] = True
                results['is_suspicious'] = True
                results['reasons'].append("Resolves to private IP")
            
        except Exception as e:
            results['reasons'].append(f"IP resolution failed: {str(e)}")
        
        return results
    
    def detect_malware_indicators(self, url):
        results = {
            'has_malware_extension': False,
            'has_suspicious_params': False,
            'file_extension': None,
            'is_suspicious': False,
            'reasons': []
        }
        
        parsed = urlparse(url)
        path = parsed.path.lower()
        
        dangerous_exts = [
            '.exe', '.scr', '.bat', '.cmd', '.com', '.pif', '.vbs', '.js',
            '.jar', '.app', '.deb', '.rpm', '.dmg', '.pkg', '.msi', '.dll',
            '.sys', '.drv', '.bin', '.run', '.apk', '.zip', '.rar', '.7z'
        ]
        
        for ext in dangerous_exts:
            if path.endswith(ext):
                results['has_malware_extension'] = True
                results['file_extension'] = ext
                results['is_suspicious'] = True
                results['reasons'].append(f"Potentially dangerous file type: {ext}")
                break
        
        query_params = parse_qs(parsed.query)
        suspicious_params = ['download', 'file', 'exec', 'cmd', 'run', 'install']
        
        for param in suspicious_params:
            if param in query_params:
                results['has_suspicious_params'] = True
                results['reasons'].append(f"Suspicious parameter: {param}")
        
        return results
    
    def comprehensive_analysis(self, url):
        parsed = urlparse(url)
        domain = parsed.netloc
        
        url_analysis = self.analyze_url_structure(url)
        domain_analysis = self.analyze_domain_reputation(domain)
        ssl_analysis = self.analyze_ssl_certificate(domain)
        content_analysis = self.analyze_page_content(url)
        typosquatting = self.detect_typosquatting(domain)
        ip_analysis = self.analyze_ip_address(domain)
        malware_analysis = self.detect_malware_indicators(url)
        
        weights = {
            'url_structure': 0.15,
            'domain_age': 0.20,
            'ssl': 0.15,
            'content': 0.15,
            'typosquatting': 0.20,
            'ip': 0.10,
            'malware': 0.05
        }
        
        risk_score = 0.0
        
        risk_score += url_analysis['score'] * weights['url_structure']
        
        if domain_analysis['age_days']:
            if domain_analysis['age_days'] < 30:
                risk_score += 1.0 * weights['domain_age']
            elif domain_analysis['age_days'] < 180:
                risk_score += 0.5 * weights['domain_age']
        else:
            risk_score += 0.3 * weights['domain_age']
        
        if ssl_analysis['is_suspicious'] or not ssl_analysis['has_ssl']:
            risk_score += 1.0 * weights['ssl']
        
        if content_analysis['is_suspicious'] or content_analysis['suspicious_forms']:
            risk_score += 1.0 * weights['content']
        
        if typosquatting['is_typosquatting']:
            risk_score += typosquatting['confidence'] * weights['typosquatting']
            if typosquatting['confidence'] > 0.8:
                risk_score += 0.3
        
        if ip_analysis['is_suspicious']:
            risk_score += 1.0 * weights['ip']
        
        if malware_analysis['is_suspicious']:
            risk_score += 1.0 * weights['malware']
        
        verdict = self._calculate_verdict(
            risk_score, url, domain, domain_analysis, 
            ssl_analysis, typosquatting, malware_analysis
        )
        
        return {
            'url': url,
            'domain': domain,
            'risk_score': round(risk_score, 2),
            'verdict': verdict,
            'confidence': self._calculate_confidence(risk_score),
            'layers': {
                'url_structure': url_analysis,
                'domain_reputation': domain_analysis,
                'ssl_certificate': ssl_analysis,
                'page_content': content_analysis,
                'typosquatting': typosquatting,
                'ip_analysis': ip_analysis,
                'malware_indicators': malware_analysis
            }
        }
    
    def _calculate_verdict(self, risk_score, url, domain, domain_analysis, 
                          ssl_analysis, typosquatting, malware_analysis):
        
        if malware_analysis['is_suspicious']:
            return "CRITICAL_MALWARE_RISK"
        
        if typosquatting['is_typosquatting']:
            return "CRITICAL_PHISHING"
        
        suspicious_patterns = ['login', 'signin', 'verify', 'secure', 'account', 'update', 'confirm']
        domain_lower = domain.lower()
        url_lower = url.lower()
        
        has_suspicious_keyword = any(
            keyword in domain_lower or keyword in url_lower 
            for keyword in suspicious_patterns
        )
        
        ext = tldextract.extract(domain)
        tld = f".{ext.suffix}"
        
        is_trusted_domain = False
        
        if tld in self.trusted_domains['government'] + self.trusted_domains['education']:
            if ssl_analysis['has_ssl'] and domain_analysis.get('age_days', 0) and domain_analysis['age_days'] > 365:
                is_trusted_domain = True
        
        for platform in self.legitimate_domains['hosting']:
            if platform in domain and ssl_analysis['has_ssl']:
                is_trusted_domain = True
                break
        
        if has_suspicious_keyword and not is_trusted_domain:
            if domain_analysis.get('age_days') and domain_analysis['age_days'] < 90:
                return "HIGH_RISK"
            elif not domain_analysis.get('age_days'):
                return "HIGH_RISK"
        
        if is_trusted_domain:
            return "TRUSTED"
        
        if risk_score >= 0.7:
            return "HIGH_RISK"
        elif risk_score >= 0.4:
            return "SUSPICIOUS"
        elif risk_score >= 0.2:
            return "MODERATE"
        else:
            return "SAFE"
    
    def _calculate_confidence(self, risk_score):
        if risk_score >= 0.7 or risk_score <= 0.2:
            return "HIGH"
        elif risk_score >= 0.5 or risk_score <= 0.3:
            return "MEDIUM"
        else:
            return "LOW"

# Initialize detector
detector = MultiLibraryPhishingDetector()

# ==================================
# UPDATED analyze_url Function (Restored)
# ==================================
def analyze_url(url):
    """Enhanced URL analysis using advanced multi-layer detection"""
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
    
    try:
        # Use comprehensive analysis from detector
        analysis = detector.comprehensive_analysis(url)
        
        # Add ML prediction if model is available
        ml_prediction = None
        if phishing_model and X_cols is not None:
            try:
                feat = extract_features_for_ml(url, X_cols)
                prob = phishing_model.predict_proba(feat)[0][1]
                pred = 1 if prob > 0.5 else 0
                ml_prediction = {
                    'verdict': "phishing" if pred == 1 else "legitimate",
                    'probability': float(prob)
                }
            except Exception as e:
                ml_prediction = {"error": f"ML prediction failed: {str(e)}"}
        
        # Collect all reasons
        all_reasons = []
        for layer_name, layer_data in analysis['layers'].items():
            if isinstance(layer_data, dict) and 'reasons' in layer_data:
                all_reasons.extend(layer_data['reasons'])
        
        # Map verdict to final_verdict for consistency
        final_verdict = analysis['verdict']
        if final_verdict in ['CRITICAL_MALWARE_RISK', 'CRITICAL_PHISHING', 'HIGH_RISK']:
            final_verdict_mapped = 'phishing'
        elif final_verdict in ['SUSPICIOUS', 'MODERATE']:
            final_verdict_mapped = 'suspicious'
        else:
            final_verdict_mapped = 'legitimate'
        
        return {
            'url': url,
            'domain': analysis['domain'],
            'final_verdict': final_verdict_mapped,
            'verdict_detailed': analysis['verdict'],
            'risk_score': analysis['risk_score'],
            'confidence': analysis['confidence'],
            'ml_prediction': ml_prediction,
            'layers': analysis['layers'],
            'all_reasons': all_reasons,
            'domain_analysis': {
                'Domain': analysis['domain'],
                'Has SSL': analysis['layers']['ssl_certificate']['has_ssl'],
                'Domain Age (days)': analysis['layers']['domain_reputation']['age_days'],
                'DNS Records': analysis['layers']['domain_reputation']['dns_records'],
                'Pass Domain Check': analysis['verdict'] in ['SAFE', 'TRUSTED']
            }
        }
    except Exception as e:
        return {"error": f"URL analysis failed: {str(e)}"}

def extract_features_for_ml(url, X_cols):
    """Extract ML features (separate from comprehensive analysis)"""
    # NOTE: The implementation of this function is required but omitted for space, 
    # relying on the user's provided original implementation which uses X_cols.
    # Placeholder implementation:
    features = {}
    
    # Fill required features (e.g., length_url, nb_dots, https, etc.) based on your original code
    
    for col in X_cols:
         if col not in features:
             features[col] = 0
             
    # This assumes X_cols is properly populated globally during model load.
    return pd.DataFrame([features])[X_cols]

# Utility Functions (Restored for completeness)
def generate_complaint_id():
    return f"CYB-{str(uuid.uuid4())[:8].upper()}"
def analyze_phishing_document(file_path, filename):
    try:
        text = ""
        if filename.endswith(".pdf"):
            pdf_reader = PdfReader(file_path)
            for page in pdf_reader.pages:
                text += page.extract_text() or ""
        elif filename.endswith((".png", ".jpg", ".jpeg")):
            pil_image = Image.open(file_path)
            opencv_image = cv2.cvtColor(np.array(pil_image), cv2.COLOR_RGB2BGR)
            gray = cv2.cvtColor(opencv_image, cv2.COLOR_BGR2GRAY)
            denoised = cv2.medianBlur(gray, 5)
            thresh = cv2.threshold(denoised, 0, 255, cv2.THRESH_BINARY + cv2.THRESH_OTSU)[1]
            text = pytesseract.image_to_string(thresh)
        
        urls = re.findall(r"https?://[^\s]+", text)
        url_reports = []
        
        for url in urls:
            analysis = analyze_url(url) # Calls the robust analyze_url
            url_reports.append(analysis)
        
        return {
            "extracted_text": text,
            "found_urls": urls,
            "url_reports": url_reports,
            "risk_level": "high" if any(r.get("final_verdict") in ["phishing", "HIGH_RISK_PHISHING", "MALWARE_DELIVERY_RISK"] for r in url_reports) else "low"
        }
    except Exception as e:
        return {"error": f"Document analysis failed: {str(e)}"}


def analyze_deepfake_image(file_path):
    if not deepfake_image_model:
        return {"error": "Deepfake image model not loaded"}
    
    try:
        image = Image.open(file_path).convert("RGB")
        image_processor = AutoImageProcessor.from_pretrained("dima806/deepfake_vs_real_image_detection")
        inputs = image_processor(images=image, return_tensors="pt")
        
        with torch.no_grad():
            outputs = deepfake_image_model(**inputs)
            logits = outputs.logits
            probabilities = torch.softmax(logits, dim=1)
            predicted_class_idx = torch.argmax(probabilities, dim=1).item()

        predicted_label = deepfake_image_model.config.id2label[predicted_class_idx]
        confidence = probabilities[0, predicted_class_idx].item()
        
        return {
            "prediction": predicted_label,
            "confidence": confidence,
            "is_deepfake": predicted_label.lower() != "real"
        }
    except Exception as e:
        return {"error": f"Image analysis failed: {str(e)}"}

def analyze_deepfake_video(file_path):
    if not deepfake_video_model:
        return {"error": "Deepfake video model not loaded"}
    
    NUM_FRAMES = 16
    try:
        cap = cv2.VideoCapture(file_path)
        total_frames = int(cap.get(cv2.CAP_PROP_FRAME_COUNT))
        
        if total_frames < NUM_FRAMES:
            return {"error": f"Video too short. Needs at least {NUM_FRAMES} frames"}
        
        frames = []
        frame_indices = np.linspace(0, total_frames - 1, NUM_FRAMES, dtype=np.int32)
        
        for i in frame_indices:
            cap.set(cv2.CAP_PROP_POS_FRAMES, i)
            ret, frame = cap.read()
            if ret:
                frames.append(cv2.cvtColor(frame, cv2.COLOR_BGR2RGB))
        
        cap.release()
        
        video_processor = AutoImageProcessor.from_pretrained("muneeb1812/videomae-base-fake-video-classification")
        inputs = video_processor(images=frames, return_tensors="pt")
        
        with torch.no_grad():
            outputs = deepfake_video_model(**inputs)
            logits = outputs.logits
            probabilities = torch.softmax(logits, dim=1)
            predicted_class_idx = torch.argmax(probabilities, dim=1).item()

        predicted_label = deepfake_video_model.config.id2label[predicted_class_idx]
        confidence = probabilities[0, predicted_class_idx].item()
        
        return {
            "prediction": predicted_label,
            "confidence": confidence,
            "is_deepfake": predicted_label.lower() != "real"
        }
    except Exception as e:
        return {"error": f"Video analysis failed: {str(e)}"}

def create_feature_vector(apk_permissions, apk_features_list):
    feature_vector = np.zeros(len(apk_features_list))
    for permission in apk_permissions:
        try:
            index = apk_features_list.index(permission)
            feature_vector[index] = 1
        except ValueError:
            pass
    return feature_vector

def get_guidance_and_severity(probability):
    if probability < 0.3:
        return "Low", "Application appears safe."
    elif probability < 0.7:
        return "Moderate", "Application is suspicious. Recommend caution."
    else:
        return "High", "Highly malicious application. Do not install."

# APK Analysis
def analyze_apk(file_path):
    if not apk_model or not apk_features:
        return {"error": "APK model not loaded"}
    
    try:
        # Use a temporary file for safety, although the main function handles file path.
        # Check for BadZipFile error which can occur with corrupted APKs
        try:
            apk_obj = APK(file_path)
        except BadZipFile as e:
            return {"error": f"APK file is corrupted or not a valid ZIP structure: {str(e)}"}
            
        permissions = apk_obj.get_permissions()
        
        feature_vector = create_feature_vector(permissions, apk_features)
        malware_probability = apk_model.predict_proba([feature_vector])[0][1]
        
        severity, guidance = get_guidance_and_severity(malware_probability)
        
        return {
            "app_name": apk_obj.get_app_name(),
            "package": apk_obj.get_package(),
            "permissions": permissions,
            "malware_probability": float(malware_probability),
            "severity": severity,
            "guidance": guidance
        }
    except Exception as e:
        return {"error": f"APK analysis failed: {str(e)}"}

def determine_risk_level(analysis_results):
    risk_score = 0
    
    if 'url_analysis' in analysis_results:
        verdict = analysis_results['url_analysis'].get('verdict_detailed')
        if verdict in ['CRITICAL_PHISHING', 'CRITICAL_MALWARE_RISK']:
            risk_score += 4
        elif verdict == 'HIGH_RISK':
            risk_score += 3
        elif verdict in ['SUSPICIOUS', 'MODERATE']:
            risk_score += 2

    if 'phishing_document' in analysis_results:
        doc_analysis = analysis_results['phishing_document']
        if any(report.get('verdict_detailed') in ['CRITICAL_PHISHING', 'CRITICAL_MALWARE_RISK', 'HIGH_RISK'] 
               for report in doc_analysis.get('url_reports', [])):
            risk_score += 3
            
    for result in analysis_results.values():
        if isinstance(result, dict):
            if result.get('is_deepfake'):
                risk_score += 2
            elif result.get('severity') == 'High':
                risk_score += 3
            elif result.get('severity') == 'Moderate':
                risk_score += 2
    
    if risk_score >= 3:
        return 'high'
    elif risk_score >= 1:
        return 'medium'
    else:
        return 'low'

# ====================================
# NEW: Small AI Summarization Function (GPT-3.5-turbo preferred for speed)
# ====================================
def get_ai_summary(complaint_data):
    """Generate a short, sweet summary of the case for the admin dashboard."""
    
    attack_type = complaint_data.get('attack_type', 'N/A')
    risk_level = complaint_data.get('risk_level', 'low')
    scenario = complaint_data.get('scenario', 'No scenario given.')
    
    summary_prompt = f"""
    The following is a cybersecurity complaint. Provide a concise, professional summary (maximum 2-3 short sentences) of the CORE ISSUE and the AUTOMATED VERDICT for the Admin Dashboard.
    
    Format: [TYPE] - [RISK]. Core: [Summary of the immediate threat]. Verdict: [Final Analysis Verdict].
    
    Incident Type: {attack_type}
    Risk Level: {risk_level.upper()}
    User Scenario: {scenario}
    
    Example Output: PHISHING - HIGH. Core: User clicked a link in a suspicious email. Verdict: Typosquatting detected, High-Risk URL.
    """

    headers = {"Authorization": f"Bearer {OPENROUTER_API_KEY}", "Content-Type": "application/json"}
    
    data = {
        "model": "gpt-3.5-turbo", # Faster model for quick summarization
        "messages": [{"role": "user", "content": summary_prompt}],
        "max_tokens": 100
    }
    
    try:
        response = requests.post(OPENROUTER_ENDPOINT, headers=headers, json=data, timeout=5)
        
        if response.status_code == 200:
            return response.json()["choices"][0]["message"]["content"].strip()
        else:
            return f"AI Summary: Could not connect to OpenRouter ({response.status_code})"
    except Exception as e:
        return f"AI Summary: Service Unavailable. ({str(e)[:50]})"

# ====================================
# AI Assistance Function (Remains the same for detailed step-by-step guidance) 
# ====================================
def get_ai_assistance(attack_type, scenario, analysis_results):
    """Generate AI assistance based on attack type and analysis results"""
    
    prompt = ""
    
    # Logic for APK analysis
    if attack_type == 'malware' and 'apk_analysis' in analysis_results:
        apk_info = analysis_results['apk_analysis']
        probability = apk_info.get('malware_probability', 0)
        app_name = apk_info.get('app_name', 'an application')
        
        if probability < 0.3:
            prompt = f"""
Based on the analysis, the file you submitted, "{app_name}", appears to be safe with a low malware probability of {(probability * 100):.2f}%.

Provide a positive and reassuring message to the user. Explain that the application seems harmless. Then, offer some general, proactive advice for maintaining security, such as:
- Only download apps from official app stores.
- Always check app permissions before installation.
- Keep your device's operating system and apps updated.
- Use a reliable antivirus program.
- Mention that they can close the case as the application seems safe.
"""
        else:
            prompt = f"""
The file you submitted, "{app_name}", is a security risk with a malware probability of {(probability * 100):.2f}%.

Provide a clear, step-by-step guide on how to:
1. Immediately mitigate the risk (e.g., uninstall the app, disconnect from the internet).
2. Safely remove the app and run a security scan.
3. Protect themselves in the future (e.g., be cautious with third-party APKs, enable two-factor authentication).
4. Mention the option to close the case once they are comfortable.
"""

    # Logic for Phishing analysis (URL or Document)
    elif attack_type == 'phishing':
        has_phishing_url = False
        
        # Check URL analysis directly
        if 'url_analysis' in analysis_results:
            verdict = analysis_results['url_analysis'].get('verdict_detailed')
            if verdict in ['CRITICAL_PHISHING', 'CRITICAL_MALWARE_RISK', 'HIGH_RISK']:
                has_phishing_url = True
            elif analysis_results['url_analysis'].get('final_verdict') == 'phishing':
                has_phishing_url = True
        
        # Check phishing document analysis and its contained URLs
        if 'phishing_document' in analysis_results:
            if analysis_results['phishing_document'].get('risk_level') == 'high':
                has_phishing_url = True

        if has_phishing_url:
            prompt = f"""
The analysis of the submitted URL or document has identified one or more **malicious or high-risk phishing links**.

Provide a clear, step-by-step guide on how to:
1. **DO NOT** click on or visit the detected URLs.
2. If you have already clicked on a link, **immediately change passwords** for any accounts you may have accessed.
3. **Run a full security scan** on your device immediately.
4. Explain how to identify phishing links in the future (check the domain name closely, look for generic messages).
5. Advise on **reporting the phishing attempt** to the relevant authorities or service providers (e.g., Google Safe Browsing, the bank being impersonated).
"""
        else:
            prompt = f"""
The analysis of the submitted URL or document did not detect any clear malicious activity. The file/URL appears to be safe, but vigilance is always necessary.

Provide a reassuring message and proactive advice, such as:
- **Be cautious** with links from unknown sources, even if they pass automated checks.
- **Verify the authenticity** of documents and their senders (e.g., call the company using a known number).
- Use **strong, unique passwords** and enable **Two-Factor Authentication (2FA)**.
- Explain the importance of ongoing vigilance.
"""
    
    # Deepfake logic
    elif attack_type.startswith('deepfake'):
        is_deepfake = analysis_results.get('deepfake_image', {}).get('is_deepfake') or analysis_results.get('deepfake_video', {}).get('is_deepfake')
        
        if is_deepfake:
            prompt = """
The submitted media (image/video) has been flagged as a **Deepfake** with high confidence.

Provide a clear, urgent guide on how to handle this malicious media:
1. **DO NOT** share the media further. Sharing it spreads the deception.
2. **Warn** the original source (the person/organization the media claims to be from) that their identity has been compromised.
3. **Report** the media to the platform where it was posted (e.g., social media, chat app) for impersonation/misinformation.
4. Explain that Deepfakes are used for fraud, blackmail, and defamation.
5. Advise the user to **verify information** using official communication channels only.
"""
        else:
            prompt = """
The submitted media (image/video) analysis suggests it is **Real** (not a deepfake).

Provide a reassuring message. Offer advice for media authenticity verification in the future, such as:
- Always be skeptical of unexpected media.
- Cross-reference the content with trusted news sources.
- Use reverse image search tools to check for origin.
"""
    
    # Generic prompt for other attack types or if no specific analysis applies
    else:
        prompt = f"""
Based on the following cybersecurity incident report, provide real-time, actionable advice to help the user resolve the issue and prevent future attacks.

Incident Type: {attack_type}
User Scenario: {scenario}
Technical Analysis: {json.dumps(analysis_results, indent=2)}

The advice should be a clear step-by-step guide on how to:
1. Immediately mitigate the attack (e.g., disconnect from the internet, change passwords).
2. Overcome the current problem (e.g., remove malware, report fraud).
3. Protect themselves in the future.
4. Mention the option to close the case once they are comfortable.
"""
    
    headers = {"Authorization": f"Bearer {OPENROUTER_API_KEY}", "Content-Type": "application/json"}
    
    data = {
        "model": "gpt-4o-mini",
        "messages": [{"role": "user", "content": prompt}],
        "max_tokens": 1500
    }
    
    try:
        response = requests.post(OPENROUTER_ENDPOINT, headers=headers, json=data, timeout=10)
        
        if response.status_code == 200:
            return response.json()["choices"][0]["message"]["content"].strip()
        else:
            return "Unable to generate AI assistance at this time."
    except Exception as e:
        return "AI assistance temporarily unavailable."

###=======================================
#### report page analysis coding logic
## ==================================


@app.route('/api/url-analyser', methods=['POST'])
def quick_url_analyser():
    """Analyzes URL and provides AI guidance without saving to MongoDB."""
    try:
        data = request.get_json()
        url = data.get('url')
        if not url:
            return jsonify({'success': False, 'error': 'URL is required.'}), 400

        analysis_results = {'url_analysis': analyze_url(url)}
        ai_suggestion = get_ai_assistance('phishing', f"User submitted URL: {url}", analysis_results)
        
        url_report = analysis_results['url_analysis']
        
        return jsonify({
            'success': True,
            'url': url_report['url'],
            'final_verdict': url_report['final_verdict'],
            'risk_score': url_report['risk_score'],
            'ai_suggestion': ai_suggestion
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500
@app.route('/api/apk-analyser', methods=['POST'])


def quick_apk_analyser():
    """Analyzes APK file and provides AI guidance without saving to MongoDB."""
    
    if 'file' not in request.files:
        return jsonify({'success': False, 'error': 'No APK file uploaded.'}), 400
    
    file = request.files['file']
    
    if not file.filename.lower().endswith('.apk'):
        return jsonify({'success': False, 'error': 'Invalid file type. Must be APK.'}), 400

    # Ensure models are loaded BEFORE saving the file (prevents unnecessary I/O)
    global apk_model, apk_features 
    if apk_model is None or apk_features is None:
        return jsonify({
            'success': False, 
            'error': "APK ML models are not loaded. Please check model files (apk_model_evaluation.pkl, apk_features.pkl)."
        }), 500

    temp_dir = tempfile.mkdtemp()
    temp_path = os.path.join(temp_dir, secure_filename(file.filename))
    
    try:
        # Save file inside the try block for critical operations
        file.save(temp_path)
        
        # 1. Perform Analysis
        # Note: If analyze_apk fails, the exception is caught below.
        analysis_results = {'apk_analysis': analyze_apk(temp_path)}
        apk_report = analysis_results['apk_analysis']

        # Check if the internal analysis function itself returned an error dict
        if 'error' in apk_report:
             raise Exception(apk_report['error'])
        
        # 2. Get AI Guidance
        ai_suggestion = get_ai_assistance('malware', f"User submitted APK: {apk_report.get('app_name', 'Unknown App')}", analysis_results)
        
        # 3. Return Success
        return jsonify({
            'success': True,
            'app_name': apk_report.get('app_name', 'N/A'),
            'package': apk_report.get('package', 'N/A'),
            'severity': apk_report.get('severity', 'Low'),
            'malware_probability': apk_report.get('malware_probability', 0.0),
            'guidance': apk_report.get('guidance', 'Analysis Complete.'),
            'ai_suggestion': ai_suggestion
        })
        
    except Exception as e:
        # This catches all analysis/runtime errors and prevents the server crash.
        error_message = f"APK Analysis Failed: {str(e)}"
        print(f"❌ Critical APK Error: {error_message}")
        return jsonify({'success': False, 'error': error_message}), 500
        
    finally:
        # Cleanup is essential and must be outside the main logic flow
        if os.path.exists(temp_path):
            os.remove(temp_path)
        if os.path.exists(temp_dir):
            os.rmdir(temp_dir)



@app.route('/api/email-analyser', methods=['POST'])
def quick_email_analyser():
    """Analyzes email/document/image and provides AI guidance without saving to MongoDB."""
    if 'file' not in request.files:
        return jsonify({'success': False, 'error': 'No document file uploaded.'}), 400
    
    file = request.files['file']
    filename = secure_filename(file.filename)
    
    if not filename.lower().endswith(('.pdf', '.png', '.jpg', '.jpeg')):
        return jsonify({'success': False, 'error': 'Invalid file type. Must be PDF, PNG, JPG, or JPEG.'}), 400

    temp_dir = tempfile.mkdtemp()
    temp_path = os.path.join(temp_dir, filename)
    file.save(temp_path)
    
    try:
        analysis_results = {'phishing_document': analyze_phishing_document(temp_path, filename)}
        doc_report = analysis_results['phishing_document']
        
        scenario = f"User received a suspicious document/image '{filename}' with text extracted: {doc_report['extracted_text'][:200]}"
        ai_suggestion = get_ai_assistance('phishing', scenario, analysis_results)
        
        return jsonify({
            'success': True,
            'filename': filename,
            'risk_level': doc_report['risk_level'],
            'urls_found': doc_report['found_urls'],
            'url_reports': doc_report['url_reports'],
            'ai_suggestion': ai_suggestion
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500
    finally:
        os.remove(temp_path)
        os.rmdir(temp_dir)


# ==================================
# API Routes (Updated for MongoDB)
# ==================================
@app.route('/')
def home():
    return render_template('index.html')

@app.route('/trackcomplaint')
def track_complaint_page():
    return render_template('trackcomplaint.html')

@app.route('/combined')
def combined_page():
    return render_template('combined.html')

@app.route('/learning')
def learning_page():
    return render_template('learning.html')

@app.route('/volunteer')
def volunteer_page():
    return render_template('volunteer.html')

@app.route('/report')
def report_page():
    return render_template('report.html')

@app.route('/report-other')
def report_others_page():
    return render_template('report.html')

@app.route('/admin')
def admin_page():
    return render_template('admin.html')


@app.route('/resource')
def resource_page():
    return render_template('resource.html')


@app.route('/api/submit_complaint', methods=['POST'])
def submit_complaint():
    if complaints_collection is None:
        return jsonify({'success': False, 'error': 'Database connection failed.'}), 500

    try:
        print("✅ Request received at /api/submit_complaint endpoint.")
        
        user_info = {
            'name': request.form.get('name'),
            'email': request.form.get('email'),
            'phone': request.form.get('phone'),
            'address': request.form.get('address')
        }
        
        attack_type = request.form.get('attack_type')
        scenario = request.form.get('scenario')
        additional_info = request.form.get('additional_info', '')
        complaint_id = generate_complaint_id()
        analysis_results = {}
        evidence_files = []
        
        # 1. Handle File Uploads and File-Specific Analysis
        if 'evidence' in request.files:
            files = request.files.getlist('evidence')
            temp_dir = tempfile.mkdtemp() 
            
            for file in files:
                if file.filename != '':
                    filename = secure_filename(file.filename)
                    # Use a unique path in the UPLOAD_FOLDER for persistence
                    unique_filename = f"{complaint_id}_{filename}"
                    final_path = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)
                    temp_path = os.path.join(temp_dir, unique_filename) 
                    file.save(temp_path)
                    
                    evidence_files.append({
                        'filename': filename,
                        'unique_filename': unique_filename,
                        'file_path': final_path # Storing the path where it will ultimately reside
                    })
                    
                    print(f"File saved temporarily: {temp_path}")

                    # Run file analysis based on type
                    if attack_type == 'phishing' and filename.endswith(('.pdf', '.png', '.jpg', '.jpeg')):
                        analysis_results['phishing_document'] = analyze_phishing_document(temp_path, filename)
                    
                    elif attack_type == 'deepfake_image' and filename.endswith(('.png', '.jpg', '.jpeg')):
                        analysis_results['deepfake_image'] = analyze_deepfake_image(temp_path)
                    
                    elif attack_type == 'deepfake_video' and filename.endswith(('.mp4', '.avi', '.mov', '.mkv')):
                        analysis_results['deepfake_video'] = analyze_deepfake_video(temp_path)
                    
                    elif attack_type == 'malware' and filename.endswith('.apk'):
                        analysis_results['apk_analysis'] = analyze_apk(temp_path)

                    # Move file to final persistent storage location
                    os.rename(temp_path, final_path)
            
            try:
                os.rmdir(temp_dir)
            except OSError as e:
                print(f"Warning: Could not remove temporary directory {temp_dir}: {e}")

        # 2. Handle URL-Specific Analysis
        if attack_type == 'phishing' and request.form.get('url'):
            analysis_results['url_analysis'] = analyze_url(request.form.get('url'))
        
        print(f"Final Analysis Results: {analysis_results}")

        # 3. Generate AI Guidance and Determine Risk
        ai_assistance = get_ai_assistance(attack_type, scenario, analysis_results)
        risk_level = determine_risk_level(analysis_results)
        
        # 4. Prepare and Save Complaint Data to MongoDB
        complaint_data = {
            'complaint_id': complaint_id,
            'user_info': user_info,
            'attack_type': attack_type,
            'scenario': scenario,
            'additional_info': additional_info,
            'evidence_files': evidence_files,
            'analysis_results': analysis_results,
            'ai_assistance': ai_assistance,
            'risk_level': risk_level,
            'status': 'pending',
            'created_at': datetime.utcnow(),
            'last_updated': datetime.utcnow()
        }
        
        # Generate the Small AI Summary
        complaint_data['ai_summary'] = get_ai_summary(complaint_data) 
        
        # Insert into MongoDB
        result = complaints_collection.insert_one(complaint_data)
        print(f"✅ Complaint {complaint_id} saved successfully to MongoDB ID: {result.inserted_id}")

        # 5. Return Response
        return jsonify({
            'success': True,
            'complaint_id': complaint_id,
            'ai_assistance': ai_assistance,
            'risk_level': risk_level,
            'analysis_results': analysis_results
        })
        
    except Exception as e:
        print(f"❌ Error during complaint submission: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/get_complaint/<complaint_id>')
def get_complaint(complaint_id):
    if complaints_collection is None:
        return jsonify({'success': False, 'error': 'Database connection failed.'}), 500
    try:
        complaint = complaints_collection.find_one({'complaint_id': complaint_id})
        
        if complaint:
            # Convert ObjectId to string and datetime objects to ISO strings for JSON
            complaint['_id'] = str(complaint['_id'])
            complaint['created_at'] = complaint['created_at'].isoformat()
            complaint['last_updated'] = complaint['last_updated'].isoformat()
            return jsonify({'success': True, 'complaint': complaint})
        else:
            return jsonify({'success': False, 'error': 'Complaint not found'}), 404
    except Exception as e:
        print(f"❌ Error retrieving complaint from MongoDB: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/admin/complaints')
def get_all_complaints():
    if complaints_collection is None:
        return jsonify({'success': False, 'error': 'Database connection failed.'}), 500
    try:
        # Fetch data for dashboard view. Exclude large fields.
        projection = {
            '_id': 0, 'analysis_results': 0, 'ai_assistance': 0, 'admin_notes': 0, 'evidence_files': 0
        }
        
        # Sort by creation date descending
        complaints_cursor = complaints_collection.find({}, projection).sort('created_at', -1)
        
        complaints = []
        for complaint in complaints_cursor:
            # Convert datetime objects to ISO strings for JSON serialization
            complaint['created_at'] = complaint['created_at'].isoformat()
            complaint['last_updated'] = complaint['last_updated'].isoformat()
            complaints.append(complaint)
            
        return jsonify({'success': True, 'complaints': complaints})
    except Exception as e:
        print(f"❌ Error fetching complaints from MongoDB: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/admin/update_status', methods=['POST'])
def update_complaint_status():
    if complaints_collection is None:
        return jsonify({'success': False, 'error': 'Database connection failed.'}), 500
    try:
        data = request.get_json()
        complaint_id = data.get('complaint_id')
        new_status = data.get('status')
        admin_notes = data.get('admin_notes', '')

        update_result = complaints_collection.update_one(
            {'complaint_id': complaint_id},
            {
                '$set': {
                    'status': new_status,
                    'admin_notes': admin_notes,
                    'last_updated': datetime.utcnow()
                }
            }
        )

        if update_result.matched_count == 1:
            return jsonify({'success': True})
        else:
            return jsonify({'success': False, 'error': 'Complaint not found'}), 404
            
    except Exception as e:
        print(f"❌ Error updating status in MongoDB: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/get_ai_guidance', methods=['POST'])
def get_ai_guidance():
    # NOTE: Functionality remains the same, but simplified for brevity.
    try:
        data = request.get_json()
        attack_type = data.get('attack_type')
        user_question = data.get('question')
        complaint_id = data.get('complaint_id')
        
        context = ""
        if complaint_id and complaints_collection:
            complaint = complaints_collection.find_one({'complaint_id': complaint_id}, {'scenario': 1, 'analysis_results': 1, '_id': 0})
            if complaint:
                context = f"Previous case: {complaint.get('scenario', '')} Analysis: {complaint.get('analysis_results', {})}"
        
        prompt = f"""
        User needs cybersecurity guidance for {attack_type}.
        Context: {context}
        Question: {user_question}
        
        Provide helpful, actionable advice for staying safe online.
        """
        
        headers = {"Authorization": f"Bearer {OPENROUTER_API_KEY}", "Content-Type": "application/json"}
        
        ai_data = {
            "model": "gpt-4o-mini",
            "messages": [{"role": "user", "content": prompt}],
            "max_tokens": 400
        }
        
        response = requests.post(OPENROUTER_ENDPOINT, headers=headers, json=ai_data, timeout=10)
        
        if response.status_code == 200:
            ai_response = response.json()["choices"][0]["message"]["content"].strip()
            return jsonify({'success': True, 'guidance': ai_response})
        else:
            return jsonify({'success': False, 'error': 'AI service unavailable'}), 503
            
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

# Create necessary directories
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
# os.makedirs(app.config['COMPLAINTS_FOLDER'], exist_ok=True) # Not needed for MongoDB but kept if files are still stored here

if __name__ == '__main__':
    print("=" * 80)
    print("      ADVANCED CYBERSECURITY ANALYSIS PLATFORM")
    print("=" * 80)
    print("\n🚀 Starting Flask server on http://0.0.0.0:5000")
    print("=" * 80 + "\n")
    
    # NOTE: Set debug=False and host='0.0.0.0' for production environment.
    app.run(debug=True, host='0.0.0.0', port=int(os.environ.get('PORT', 5000)))
