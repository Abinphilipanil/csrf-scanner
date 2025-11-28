import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin

CSRF_TOKEN_NAMES = [
    'csrf_token',
    'csrfmiddlewaretoken',
    '_token',
    'authenticity_token',
    '__requestverificationtoken'
]

def get_forms(url):
    try:
        headers = {'User-Agent': 'Mozilla/5.0'}
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        soup = BeautifulSoup(response.content, "html.parser")
        return soup.find_all("form"), soup
    except requests.exceptions.RequestException:
        return [], None

def has_meta_token(soup):
    meta = soup.find("meta", attrs={"name": lambda v: v and 'csrf' in v.lower()})
    return bool(meta)

def is_vulnerable(form, soup):
    if has_meta_token(soup):
        return False
    inputs = form.find_all("input")
    for input_tag in inputs:
        name = input_tag.attrs.get("name", "").lower()
        id_ = input_tag.attrs.get("id", "").lower()
        type_ = input_tag.attrs.get("type", "").lower()
        if type_ == "hidden" and (name in CSRF_TOKEN_NAMES or id_ in CSRF_TOKEN_NAMES):
            return False
    return True

def scan_csrf(url):
    print(f"[*] Scanning: {url}")
    forms, soup = get_forms(url)
    print(f"[*] Forms detected: {len(forms)}")
    vulnerable = 0

    for i, form in enumerate(forms, 1):
        action = form.attrs.get("action")
        full_action = urljoin(url, action) if action else url
        method = form.attrs.get("method", "get").lower()

        if method == "post":
            if is_vulnerable(form, soup):
                print(f"[!] Vulnerable Form #{i}")
                print(f"    Action: {full_action}")
                print("    No CSRF token detected.")
                vulnerable += 1
            else:
                print(f"[+] Form #{i} protected")
        else:
            print(f"[-] Form #{i} uses GET")

    print(f"\n[*] Scan Complete: {vulnerable} vulnerable form(s) found.")

if __name__ == "__main__":
    target = input("Enter URL to scan: ")
    scan_csrf(target)
