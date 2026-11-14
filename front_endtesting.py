import requests
from ipaddress import IPv4Address
import json
import hashlib

def main():

    #Fill in releveant information
    http_body = {
        "username": "",
        "target_ip": "",
        "scan_engines": []
    }

    rec_response = make_request(target_endpoint="ipscans", body=http_body)
    print(f"The http status is: {rec_response.status_code}, information is: {rec_response.reason}")

    with open("testing1.json", "w") as file:
        json.dump(rec_response.json(), fp=file, indent=4)


def make_request(target_endpoint, body):
    response = requests.post(url=f"http://127.0.0.1:8000/{target_endpoint}",
                            json=body,
                            timeout=15,
                            headers={
                                 "accept": "application/json",
                                 #This should contain your key
                                 "X-API-KEY": ""}
                                 )

    return response

if __name__ == "__main__":
    main()