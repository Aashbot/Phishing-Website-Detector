import requests
import tldextract
from bs4 import BeautifulSoup
from datetime import datetime
import re
from urllib.parse import urlparse
import whois
from cryptography import x509
from cryptography.hazmat.backends import default_backend

def get_final_url(url):
    try:
        response = requests.head(url, allow_redirects=True)
        return response.url
    except requests.RequestException:
        return None

def get_domain_from_url(url):
    try:
        if url:
            extracted = tldextract.extract(url)
            return f"{extracted.domain}.{extracted.suffix}"
        else:
            return None
    except tldextract.TLDExtractError:
        return None
    
# Function to check SFH (Server Form Handler)
def check_sfh(soup):
    forms = soup.find_all('form')
    
    # If no forms are found, return 1 (safe)
    if not forms:
        return 1

    for form in forms:
        action = form.get('action', '').strip()

        # Check if the action attribute is empty
        if not action or action.startswith(('http://', 'https://')):
            return -1
        

    return 0


# Function to check for Pop-up Windows with Forms
def check_popups(soup):
    popups = soup.find_all('script', text=re.compile(r'alert\('))
    
    for popup in popups:
        if "document.forms" in popup.text:
            return -1  # Popup window contains a form
    
    return 1 

# Function to check SSL final state and issuer's age
def check_ssl_final_state(url):
    try:
        # Check if the URL starts with "https://"
        if not url.startswith("https://"):
            return -1  # HTTPS not present

        # Send an HTTP GET request to the URL with SSL verification
        response = requests.get(url, verify=True)

        # Check if the request was successful
        if response.status_code == 200:
            # Extract the SSL certificate from the response
            cert = x509.load_pem_x509_certificate(response.content, default_backend())

            # Extract the certificate's notBefore date
            not_before = cert.not_valid_before

            # Calculate the age in years
            age_in_years = (datetime.now() - not_before).days / 365

            if age_in_years >= 0.5:
                return 1 
            else:
                return 0 
        else:
            return 0  # SSL not found or other issues
    except Exception as e:
        return 0 # SSL not found or other issues


# Function to check for Request URLs
def check_request_urls(soup):
    total_links = len(soup.find_all('a', href=True))
    external_links = sum(1 for link in soup.find_all('a', href=True) if link['href'].startswith(('http://', 'https://')))

    # Calculate the percentage of request URLs
    if total_links > 0:
        request_url_percentage = (external_links / total_links) * 100
        if request_url_percentage < 22:
            return 1
        elif 22 <= request_url_percentage < 65:
            return 0
    return 0


# Function to check URL length
def check_url_length(url):
    if len(url) < 54:
        return 1
    elif 54<= len(url) <= 75:
        return 0
    return -1

# Function to check Age of Domain
def check_age_of_domain(url):
    try:
        domain = re.search(r'https?://([^/]+)', url).group(1)
        domain_info = whois.whois(domain)
        creation_date = domain_info.creation_date
        if creation_date and (datetime.now() - creation_date).days < 365:
            return 0
    except Exception as e:
        pass
    return 1

# Function to check the presence of an IP address in the URL
def check_ip_address(url):
    parsed_url = urlparse(url)
    netloc = parsed_url.netloc
    if '/' in netloc:
        netloc = netloc.split('/')[0]
    if ':' in netloc:
        netloc = netloc.split(':')[0]
    if netloc.count('.') >= 4:
        return -1
    return 1

# Function to analyze the website and return features
def analyze_website(url):
    try:
        # Send an HTTP GET request to the URL
        response = requests.get(url)

        # Check if the request was successful
        if response.status_code == 200:
            # Parse the HTML content using BeautifulSoup
            soup = BeautifulSoup(response.text, 'html.parser')

            sfh = check_sfh(soup)
            popups = check_popups(soup)
            ssl = check_ssl_final_state(url)
            request_urls = check_request_urls(soup)
            url_length = check_url_length(url)
            age_of_domain = check_age_of_domain(url)
            ip_address = check_ip_address(url)

            features = [sfh, popups, ssl, request_urls, url_length, age_of_domain, ip_address]

            return features
        else:
            return [-1] * 7  # Return -1 for all features if the request fails
    except Exception as e:
        return [-1] * 7  # Return -1 for all features if an exception occurs
