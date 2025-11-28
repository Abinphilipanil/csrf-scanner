# csrf-scanner
A Python-based tool to scan web forms for missing CSRF protection, including a demo HTML page illustrating CSRF risks.

# CSRF Scanner and Demonstration

This repository contains a simple CSRF (Cross-Site Request Forgery) form scanner and a local demonstration page that shows how a CSRF attack could potentially trigger unintended actions when no token-based protection is in place.

---

## 🚀 Features

- Detects HTML forms that use the POST method without CSRF protection
- Identifies hidden CSRF token fields by common framework names
- Detects meta-tag based CSRF tokens
- Demonstrates how a CSRF attack can submit unintended form requests (SAFE, local-only)

---

## ⚠️ Legal & Ethical Notice

This tool is strictly for:

- Educational use  
- Security research on **your own applications**  
- Testing environments where you **have explicit permission**

Unauthorized scanning or exploitation of third-party systems is illegal and unethical.

By using this tool, **you accept full responsibility** for your actions.

---

## 📂 Project Structure

