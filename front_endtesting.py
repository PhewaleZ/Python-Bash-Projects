import requests
from ipaddress import IPv4Address
def main():
    print("Take not that this is a testing bed to simplify the testing of the api wihtout using curl all the time")
    #name = input("what is name?: ")
    #key = input("What is the password: ")
    #target_type = input("What type of scan is it\n")
    #target_end = input("What is the target endpoint?: ")
    #target = input("Put the target here\n")

    json_dict = {
        "name": "Phewale",
        "key": "phewale",
        "scan_type" :"recon_ip_scan",
        "ip_target": str(IPv4Address("8.8.8.8"))
    }

    rec_response = make_request(target_endpoint="ipscan", le_dict=json_dict,)

    print(rec_response.json())

def make_request(target_endpoint, le_dict):
    response = requests.post(url=f"http://127.0.0.1:8000/{target_endpoint}",
                             json=le_dict, timeout=15, headers={"accept": "application/json"})

    return response

if __name__ == "__main__":
    main()