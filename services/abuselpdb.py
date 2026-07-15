import requests
import json
from time import sleep
from os import getenv
from dotenv import load_dotenv
from requests import Response

#The report_age parameter is used to determine how old the reports retrieved by abuselpdb API can, at max, be
def scan_ip_APDB(target_IP: str, report_age=90) -> tuple:
    load_dotenv()
    API_key=getenv("ABUSELPDB_API_KEY")
    if API_key is None:
        return (False, "The abuselpdb API key is None")

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
    #The variable flag indicates if the response status code is 200
    flag1 = False
    while count <= 4:
        try:
            response = requests.request(method='GET', url=url, headers=headers, params=querystring, timeout=20)

            if response.status_code == 200:
                flag1 = True
                break

            if response.status_code != 200:
                count +=1
                last_err = error_check(rec_response=response)
                last_err_dict = last_err[1]
                #If the first index, limit_reached is False then it means that the 429 status code was returned and continuing to send https requests is pointless
                if last_err[0] is True:
                    break
                else:
                    continue

        except requests.exceptions.Timeout:
            last_err_dict = {
        "status_code":504,
        "error_detail":"The request timed out"  
            }
            count += 1
            continue
    
    if flag1 is True:    
        abuselpdb_response = aggregate_APDB_results(rec_response=response)
        return (True, abuselpdb_response)
    
    if flag1 is False:
        return (False, last_err_dict)

#The abuselpdb api documentation states that a json with a consistent format will at the minimum, be returned
#A tuple is returned, the first index is the limit_reached flag
def error_check(rec_response: Response) -> tuple:
    limit_reached = False
    rec_response= rec_response.json()

    err_code = rec_response.get("errors", [{}])[0].get("status")

    #Per the abuselpdb api documentation a status code of 429 is returned when the daily limit has been reached
    if err_code == 429:
        err_detail = "The daily limit has been reached"
        limit_reached = True
    else:
        err_detail = rec_response.get("errors", [{}])[0].get("detail")

    err_response={
        "status_code":err_code,
        "error_detail":err_detail  
    }

    return (limit_reached,err_response)


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