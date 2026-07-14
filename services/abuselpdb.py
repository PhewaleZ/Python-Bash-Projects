import requests
import json
from time import sleep
from os import getenv
from dotenv import load_dotenv


def scan_ip_APDB(target_IP: str, report_age=90) -> tuple:
    load_dotenv()
    API_key=getenv("ABUSELPDB_API_KEY")
    
    url = 'https://api.abuseipdb.com/api/v2/check'

    querystring = {
        'ipAddress': target_IP,
        'maxAgeInDays': report_age,
            }

    headers = {
    'Accept': 'application/json',
    'Key': API_key
        }


    count = 1
    while count <= 4:
        try:
            response = requests.request(method='GET', url=url, headers=headers, params=querystring, timeout=20)
        except requests.exceptions.Timeout:
            return (False, "Coudln't communicate with abpdb API server")
        abuselpdb_response = aggregate_APDB_results(rec_response=response)

        return (True, abuselpdb_response)


def error_check(rec_response) -> tuple:
    

def aggregate_APDB_results(rec_response) -> dict:
    rec_response = rec_response.json()
    data = rec_response["data"]
    abpdb_score = data["abuseConfidenceScore"]

    match abpdb_score:
        case x if 0<=abpdb_score<20:
            concern = "level 3"
        case x if 20<=abpdb_score<60:
            concern = "level 2"
        case x if 60<=abpdb_score:
            concern = "level 1"

    
    formatted_response = {
        "target_name": data["ipAddress"],
        "is_whitelist": data["isWhitelisted"],
        "is_tor":data["isTor"],
        "country_of_origin": data["countryCode"],
        "is_whitelisted":data["isWhitelisted"],
        "domain":data["domain"],
        "concern":{
            "abusel_score": data["abuseConfidenceScore"],
            "concern_value":concern
        },
        "isp_details":{
            "isp_name":data["isp"],
            "isp_type":data["usageType"]
        },
        "report_details":{
            "report_count":data["totalReports"],
            "reports":data.get("reports", None)
            }
    }

    return formatted_response

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