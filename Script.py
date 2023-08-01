import requests
import re
import validators
import email

def parse_email(email_file):
    with open(email_file, "rb") as f:
        email_message = email.message_from_bytes(f.read())

    return email_message

def analyze_email(email_message):
    message_id = email_message["Message-ID"]
    domain = email_message["From"].split("@")[-1]
    dmarc = email_message.get("Authentication-Results")
    recipient = email_message["To"]
    email_addresses = []

    for header, value in email_message.items():
        if header.lower() == "from":
            email_addresses.append(value)
        elif header.lower() == "to":
            email_addresses.append(value)

    return message_id, domain, dmarc, recipient, email_addresses

def extract_urls_from_email(email_message):

    if email_message.is_multipart():
        for part in email_message.get_payload():
            if part.get_content_type() == 'text/html':
                urls = re.findall('http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+', part.get_payload())
                return urls
    else:
        urls = re.findall('http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+', email_message.get_payload())
        return urls

def check_url_validity(url):
    valid = validators.url(url)
    if valid==True:
        try:
            response = requests.get(url)
            if response.status_code == 200:
                return True
            else:
                return False
        except:
            return False
    else:
        return False

def check_url_with_virustotal(url):
    params = {'apikey': VIRUSTOTAL_API_KEY, 'resource': url}
    response = requests.get('https://www.virustotal.com/vtapi/v2/url/report', params=params)
    if response.status_code == 200:
        return response.json()
    else:
        return "Could not fetch the report"

def main():
    email_file = "file.eml"
    email_message = parse_email(email_file)
    message_id, domain, dmarc, recipient, email_addresses = analyze_email(email_message)

    print(f"Message ID: {message_id}")
    print(f"Domain: {domain}")
    print(f"DMARC: {dmarc}")
    print(f"Recipient: {recipient}")
    print(f"Email addresses: {email_addresses}")

    urls = extract_urls_from_email(email_message)
    print(f"\nURLs found in the email:")
    for url in urls:
        print(f"URL: {url}")
        print(f"URL is valid (loads content): {check_url_validity(url)}")
        print(f"VirusTotal report: {check_url_with_virustotal(url)}")

    print(f"\nInteresting about the email structure:")
    print(f"Content type: {email_message.get_content_type()}")
    print(f"Multipart: {email_message.is_multipart()}")



VIRUSTOTAL_API_KEY = 

if __name__ == "__main__":
    main()


'''
NOTE : VIRUSTOTAL_API_KEY value in the line 84 to run the code 
also you need to have email and validators installed in your system. 
to install email and validator use:
1. pip install email
2. pip install validators

================================================

Question: Does the message ID align with the domain of the sender ?
Answer: Yes, the message ID 20220616164126.d2c12e83802c4fd5@mail.hellosign.com actually aligns 
with the domain of sender mail.hellosign.com.

Question: Is there valid DMARC (Authentication-Results) ? 
Answer: Yes, there is valid DMARC. and DMARC pass indicates 
that the message is successfully authenticated against the domain policies.

Question: Who was the Recipient ?
Answer: The recipient of the email was jmcginty@gmx.com.


Question: List all email addresses found in email ? 
Answer: 2 email id were found here, these are noreply@mail.hellosign.com and jmcginty@gmx.com


Question: Are the URLs in the email valid (do they load content) ? ***********
Answer: few of the url are loading content, and these are 
    1. http://www.w3.org/1999/xhtml
The other URLs, mostly pointing to the 'cdn.hellosign.com' domain, were unable to load content.


Question: what does Virus total show for them ?
Answer: The valid URL (http://www.w3.org/1999/xhtml) shows no detected threats according to VirusTotal.
It has been scanned by several antivirus engines, all of which returned a clean result. 
For the other URLs, we were unable to fetch the VirusTotal report.

Question: Is there anything interesting about the email structure?
Answer: the email contains multiple URLs pointing to 'cdn.hellosign.com' that certainly don't load any content. 
This actually indicate that the urls have been malformed, this can be possibly due to some encoding issues, 
or the resources they point to have been removed or it can be possible that it would be inaccessible for some reason. 
The usage of 'mail.hellosign.com' and 'mailgun.org' as domains in the DKIM records also 
indicates  the use of third-party mailing services which is very common for transactional emails. 


'''
