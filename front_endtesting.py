import requests
from ipaddress import IPv4Address
import json
import hashlib

def main():
    target_hash = hashlib.sha256(b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*").hexdigest()

    json_dict = {
        "username": "Phewale",
        "key": "password",
        "target_ip": "8.8.8.8",
        "report_age": 90,
        "scan_engines": ["virustotal"]
    }

    try:
        rec_response = make_request(target_endpoint="ipscans", le_dict=json_dict)
        print(f"The http status is: {rec_response.status_code}, information is: {rec_response.reason}")

        with open("testing1.json", "w") as file:
            json.dump(rec_response.json(), fp=file, indent=4)

    except json.decoder.JSONDecodeError:
        print("The json file is empty")
    except:
        print("An error has occured")
    

def make_request(target_endpoint, le_dict):
    response = requests.post(url=f"http://127.0.0.1:8000/{target_endpoint}",
                             json=le_dict, timeout=15, headers={"accept": "application/json"})

    return response

if __name__ == "__main__":
    main()