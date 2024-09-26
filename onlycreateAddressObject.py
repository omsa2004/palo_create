import requests
import json
import urllib3
import re
import os
from dotenv import find_dotenv, load_dotenv
import logging
from logging.handlers import RotatingFileHandler
from getpass import getpass

path = os.getcwd()

# Disable SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

username = input("Enter TACACS Username:")

if not username:
    print("you didn't enter a valid hostname")
if username:
    password = getpass(f"Enter Password of the user {username}: ")

logger = logging.getLogger('BlockIP')
logger.setLevel(logging.INFO)

handler = RotatingFileHandler(path+"/Logs/log.log", maxBytes=5000, backupCount=10)
handler.setLevel(logging.INFO)

formatter = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")

handler.setFormatter(formatter)
logger.addHandler(handler)




def login_firewall(ip_address, user, password):
    login_url = f'https://{ip_address}/api/?type=keygen'
    login_payload = {
        'user': user,
        'password': password
    }
    response = requests.post(login_url, data=login_payload, verify=False)
    if response.status_code == 200:
        logger.info("API Key generated successfully")
        clean = re.compile("<.*?>")
        return re.sub(clean,"",response.text)
    else:
        logger.error("Login Failed, Check user and password")
        return None


def create_address_object(ip_address, key, object_value, Address_device_group_name,preIP_name):
    create_address_url = f'https://{ip_address}/restapi/v10.1/Objects/Addresses?location=device-group&device-group={Address_device_group_name}&name={preIP_name}{object_value[0]}_{object_value[1]}'
    create_address_payload = json.dumps({
        "entry": {
        "@name": f'{preIP_name}{object_value[0]}_{object_value[1]}',
        "description": f'{preIP_name}{object_value[0]}_{object_value[1]}',
        "ip-netmask": f'{object_value[0]}/{object_value[1]}'
                }
    })
    headers = {
        'Content-Type': 'application/json',
        'X-PAN-KEY': key
    }

    response = requests.post(create_address_url, headers=headers, data=create_address_payload, verify=False)
    
    if response.status_code == 200:
        logger.info(f'Address {preIP_name}{object_value[0]}/{object_value[1]} has been created')
        
    else : 
        logger.warning(f'Failed to add {preIP_name}{object_value[0]}/{object_value[1]}: {response.json()["details"][0]["causes"][0]["description"]}')



def main():
    global createdAddresses
    createdAddresses = []
    with open("TobeBlocked.txt","r+") as f:
        lines = f.readlines()
        if lines:
            for  line in lines:
                try:
                    AddressObject_value = line.strip().split("/")
                    if len(AddressObject_value) ==1:
                        AddressObject_value.append("32")
                    create_address_object(firewall_ip, API_Key, AddressObject_value, Address_device_group_name,preIP_name)     
                except:
                    logger.warning(f"Line {line}, is not a valid IP")
            f.truncate(0)    
    
            
if __name__ == "__main__":

    firewall_ip = "panorama.bswhealth.org/"
    Address_device_group_name="Internet_Edge"
    preIP_name = 'Blacklisted-'
    API_Key = login_firewall(firewall_ip, username, password)
    if API_Key:
        main()


