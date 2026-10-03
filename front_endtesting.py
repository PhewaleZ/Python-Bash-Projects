import requests
from ipaddress import IPv4Address
import json
import hashlib

def main():
    print("Take not that this is a testing bed to simplify the testing of the api wihtout using curl all the time")
    #name = input("what is name?: ")
    #key = input("What is the password: ")
    #target_type = input("What type of scan is it\n")
    #target_end = input("What is the target endpoint?: ")
    #target = input("Put the target here\n")

    target_hash = hashlib.sha256(b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*").hexdigest()

    json_dict = {
        "name": "Phewale",
        "key": "phewale",
        "scan_type" :"nothing",
        "target_domain": "google.com",
        "scan_engines": ["virustotal"]
    }

    try:
        rec_response = make_request(target_endpoint="domainscans", le_dict=json_dict)
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