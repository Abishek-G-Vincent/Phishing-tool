import requests
import re
import socket
from bs4 import BeautifulSoup
from datetime import datetime
from urllib.parse import urlparse
import tldextract  # Improved domain extraction
import whois

def extract_features(url):
    features = {}
    parsed_url = urlparse(url)
    domain = parsed_url.netloc
    ext = tldextract.extract(url)

    # Initialize variables
    soup = None
    whois_info = None  # Initialize whois_info to None

    # 1. Abnormal_URL - Suspicious keywords in URL
    suspicious_keywords = ['win', 'free', 'iphone', 'claim', 'offer', 'prize', 'free', 'click here']
    features['Abnormal_URL'] = 1 if any(keyword in domain for keyword in suspicious_keywords) else 0

    # 2. having_IP_Address - Check if domain is an IP address
    try:
        socket.inet_aton(domain)
        features['having_IP_Address'] = 1
    except socket.error:
        features['having_IP_Address'] = 0

    # 3. URL_Length - Length of URL
    features['URL_Length'] = len(url)

    # 4. Shortening_Service - Check for URL shortening services
    shortening_services = ('bit.ly', 'goo.gl', 'tinyurl.com', 'ow.ly', 'is.gd', 't.co')
    features['Shortening_Service'] = 1 if any(service in domain for service in shortening_services) else 0

    # 5. having_At_Symbol - Check for '@' symbol in URL
    features['having_At_Symbol'] = 1 if '@' in url else 0

    # 6. double_slash_redirecting - Check if the URL has double slashes
    features['double_slash_redirecting'] = 1 if '//' in parsed_url.path else 0

    # 7. Prefix_Suffix - Check for dash '-' in domain
    features['Prefix_Suffix'] = 1 if '-' in domain else 0

    # 8. having_Sub_Domain - Check if there is a subdomain
    features['having_Sub_Domain'] = 1 if ext.subdomain else 0

    # 9. SSLfinal_State - Check if the URL uses HTTPS
    features['SSLfinal_State'] = 1 if url.startswith('https') else 0

    # 10. Domain_registration_length - Check domain registration length via WHOIS
    try:
        whois_info = whois.whois(domain)
        expiration_date = whois_info.expiration_date
        if isinstance(expiration_date, list):
            expiration_date = expiration_date[0]
        features['Domain_registration_length'] = (expiration_date - datetime.now()).days if expiration_date else -1
    except Exception as e:
        features['Domain_registration_length'] = -1
        print(f"Error fetching WHOIS data: {e}")

    # 11. Favicon - Check for favicon
    try:
        response = requests.get(url, timeout=5)
        soup = BeautifulSoup(response.content, 'html.parser')
        features['Favicon'] = 1 if soup.find("link", rel="shortcut icon") else 0
    except Exception as e:
        features['Favicon'] = -1
        print(f"Error fetching Favicon: {e}")

    # 12. Port - Check if port is specified in the URL
    features['port'] = 1 if ':' in parsed_url.netloc else 0

    # 13. HTTPS_token - Check if 'https' is in the URL
    features['HTTPS_token'] = 1 if 'https' in parsed_url.scheme else 0

    # 14. Request_URL - Ratio of external resources
    try:
        if soup:
            total_links = len(soup.find_all('img'))
            external_links = len([img for img in soup.find_all('img') if urlparse(img.get('src', '')).netloc != domain])
            features['Request_URL'] = external_links / total_links if total_links else 0
        else:
            features['Request_URL'] = -1
    except Exception as e:
        features['Request_URL'] = -1
        print(f"Error fetching Request_URL: {e}")

    # 15. URL_of_Anchor - Ratio of external anchors
    try:
        if soup:
            total_anchors = len(soup.find_all('a'))
            external_anchors = len([a for a in soup.find_all('a') if urlparse(a.get('href', '')).netloc != domain])
            features['URL_of_Anchor'] = external_anchors / total_anchors if total_anchors else 0
        else:
            features['URL_of_Anchor'] = -1
    except Exception as e:
        features['URL_of_Anchor'] = -1
        print(f"Error fetching URL_of_Anchor: {e}")

    # 16. Links_in_tags - Count of anchor tags in the page
    features['Links_in_tags'] = len(soup.find_all('a')) if soup else 0

    # 17. SFH (Server Form Handler) - Check if there is a form with an action URL
    features['SFH'] = 1 if soup and soup.find('form', action=True) else 0

    # 18. Submitting_to_email - Check if there is any 'mailto' link in the page
    features['Submitting_to_email'] = 1 if 'mailto:' in str(soup) else 0

    # 19. Redirect - Check for meta redirect tags
    features['Redirect'] = 1 if soup and len(soup.find_all('meta', attrs={'http-equiv': 'refresh'})) else 0

    # 20. on_mouseover - Check if onmouseover event is present
    features['on_mouseover'] = 1 if soup and 'onmouseover' in str(soup) else 0

    # 21. RightClick - Check if right-click is disabled
    features['RightClick'] = 1 if soup and 'oncontextmenu' in str(soup) else 0

    # 22. popUpWindow - Check if a pop-up window is used in the page
    features['popUpWindow'] = 1 if soup and 'window.open' in str(soup) else 0

    # 23. Iframe - Check if the page contains iframe tags
    features['Iframe'] = 1 if soup and 'iframe' in str(soup) else 0

    # 24. Age_of_domain - Age of the domain based on WHOIS data
    try:
        if whois_info:
            creation_date = whois_info.creation_date
            if isinstance(creation_date, list):
                creation_date = creation_date[0]
            features['Age_of_domain'] = (datetime.now() - creation_date).days if creation_date else -1
        else:
            features['Age_of_domain'] = -1
    except:
        features['Age_of_domain'] = -1

    # 25. DNSRecord - Check if DNSSEC is enabled
    features['DNSRecord'] = 1 if whois_info and whois_info.get('dnssec') else 0

    # Placeholder features for external APIs (leave as -1 or a constant)
    features['Web_traffic'] = -1
    features['Page_Rank'] = -1
    features['Google_Index'] = -1
    features['Links_pointing_to_page'] = -1
    features['Statistical_report'] = -1

    return features


if __name__ == "__main__":
    test_url = "https://google.com/"
    extracted_features = extract_features(test_url)
    print(extracted_features)
