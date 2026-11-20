from dotenv import load_dotenv
from os import getenv
import requests
import json
from ipaddress import IPv4Address, IPv6Address
import httpx
import asyncio

async def make_request(
    client: httpx.AsyncClient,
    API_KEY: str,
    is_own_ip: bool,
    target_ip: IPv4Address | IPv6Address
) -> tuple[bool, str | httpx.Response]:

    last_error = ''

    if is_own_ip is False:
        url = f"https://api.ipinfo.io/lite/{target_ip}?token={API_KEY}"
    else:
        url = f"https://api.ipinfo.io/lite/me?token={API_KEY}"

    for _ in range(4):
        try:
            response = await client.get(url=url, timeout=8)
            response.raise_for_status()

        except httpx.TimeoutException:
            last_error = "Could not communicate with the IPINFO server, TIMEOUT occurred."
            continue

        except httpx.ConnectError:
            last_error = "Could not connect to the IPINFO API server."
            continue

        except httpx.HTTPStatusError as e:
            match e.response.status_code:
                case 403:
                    return (False, "Access denied by IPINFO server")

                case 429:
                    return (False, "The IPINFO server has throttled this request")

                case 400 | 401 | 404:
                    return (False, f"The following error has occurred with the IPINFO API query: {str(e)}")

                case _:
                    last_error = (
                        f"IPINFO ERROR: HTTP {e.response.status_code}: "
                        f"{e.response.reason_phrase}"
                    )
                    continue

        except httpx.RequestError as e:
            last_error = f"IPINFO ERROR: {str(e)}"
            continue

        else:
            return (True, response)

    return (False, last_error)

    
def aggregate_results(rec_response: httpx._models.Response) -> dict:
    json_rec_response = rec_response.json()
    
    ipinfo_results={
        "IP Address": json_rec_response.get("ip"),
        "asn_code": json_rec_response.get("asn"),
        "as_name": json_rec_response.get("as_name"),
        "as_domain": json_rec_response.get("as_domain"),
        "country": json_rec_response.get("country"),
    }
    return ipinfo_results

async def Ipinfoscan(target_ip: IPv4Address| IPv6Address, httpxclient: httpx.AsyncClient) -> tuple[bool, str| dict ]:
    load_dotenv(override=True)
    API_KEY = getenv("IPINFO_API_KEY")
    
    if API_KEY is None:
        return (False, 'IPINFO API key is None')
    
    response_check = await make_request(API_KEY=API_KEY, is_own_ip=False, target_ip=target_ip, client=httpxclient)

    if response_check[0] is True:
        assert not isinstance(response_check[1], str)
        ipinfo_results = aggregate_results(rec_response=response_check[1])
        return (True, ipinfo_results)
    else:
        assert isinstance(response_check[1], str)
        return (False, response_check[1])


#NOTE: These 2 function are for testing
def testing_function():
    load_dotenv()
    API_key = getenv("IPINFO_API_KEY")

    url= f'https://api.ipinfo.io/lite/87.120.104.69?token={API_key}'

    try:
        response = requests.get(url=url, timeout=10)
    except:
        print("ERROR HAS OCCURED")
        return 1
    
    json_response = response.json()

    with open('errtesting.json', 'w') as f:
        json.dump(obj=json_response, fp=f, indent=4)

if __name__ == "__main__":
    async def stuff():
            async with asyncio.TaskGroup() as tg:
                async with httpx.AsyncClient() as client:
                    task1 = tg.create_task(Ipinfoscan(IPv4Address("8.8.8.8"), client))
                    task2 = tg.create_task(Ipinfoscan(IPv4Address("1.1.1.1"), client))

                    result1 = await task1
                    result2 = await task2

            results = [result1, result2]

            print(results, "\n")
            with open("asynctest1.json", "w") as file:
                json.dump(results, fp=file, indent=4 )
            

    asyncio.run(stuff())
