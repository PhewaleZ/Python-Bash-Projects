import requests
import json
from time import sleep
from os import getenv
from dotenv import load_dotenv


def scan_ip_APDB(target_IP: str) -> tuple:
    load_dotenv()
    API_key=getenv("ABUSELPDB_API_KEY")
    
    url = 'https://api.abuseipdb.com/api/v2/check'

    querystring = {
        'ipAddress': target_IP,
        'maxAgeInDays': '90',
            }

    headers = {
    'Accept': 'application/json',
    'Key': API_key
        }

    try:
        response = requests.request(method='GET', url=url, headers=headers, params=querystring)
    except requests.exceptions.Timeout:
        return (False, "Coudlnt communicate with abpdb API server")
    

def aggregate_APDB_results(rec_response: dict) -> dict:
    ...
def testing_function():
    load_dotenv()
    API_key=getenv("ABUSELPDB_API_KEY")
    url = 'https://api.abuseipdb.com/api/v2/check'

    target = "197.249.236.235"
    querystring = {
    'ipAddress': target,
    'maxAgeInDays': '90'
        }

    headers = {
    'Accept': 'application/json',
    'Key': API_key
        }
    print(f"The key is {API_key}")
    try:
        response = requests.request(method='GET', url=url, headers=headers, params=querystring)
        print(response)
        print("linebreak here")
        print(f"The status code is: {response.status_code}")
    except requests.exceptions.Timeout:
        print("timeout")
        return 1

    decodedResponse = json.loads(response.text)
    with open ("abpdb.json", "w") as file:
        json.dump(obj=decodedResponse, fp=file, indent=4)

    print("DONE")
    return 0
testing_function()