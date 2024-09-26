import requests
import json
import urllib3
import re
from IPy import IP
import logging
from logging.handlers import RotatingFileHandler
from getpass import getpass

# Disable SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

username = input("Enter TACACS Username:")

if not username:
    print("you didn't enter a valid hostname")
if username:
    password = getpass(f"Enter Password of the user {username}: ")

logger = logging.getLogger('BlockIP')
logger.setLevel(logging.INFO)

handler = RotatingFileHandler("./Logs/log.log", maxBytes=5000, backupCount=10)
handler.setLevel(logging.INFO)
formatter = logging.Formatter("%(asctime)s - %(filename)s - %(levelname)s - %(message)s")

handler.setFormatter(formatter)
logger.addHandler(handler)


createdAddresses = []

# Creating the Token Key using the username and password provided. 
def login_firewall(ip_address, user, password):  
    login_url = f'https://{ip_address}/api/?type=keygen'
    login_payload = {
        'user': user,
        'password': password
    }
    response = requests.post(login_url, data=login_payload, verify=False)
    if response.status_code == 200:
        logger.info(f"{username} API Key generated successfully")
        clean = re.compile("<.*?>")
        return re.sub(clean,"",response.text)
    else:
        logger.error(f"{username} Login Failed, Check user and password")
        return None

#Creating the IPs from the TobeBlocked.txt File
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
        createdAddresses.append(f'{preIP_name}{object_value[0]}_{object_value[1]}')
        logger.info(f'Address {preIP_name}{object_value[0]}_{object_value[1]} has been created')
        
    else : 
        logger.warning(f'Failed to add {preIP_name}{object_value[0]}/{object_value[1]}: {response.json()["details"][0]["causes"][0]["description"]}')

#Adding the newly created addresses to the selected group. 
def add_to_address_group(ip_address, key,devicegroup, AddressGroup_name):
    add_to_group_url = f'https://{ip_address}/restapi/v10.1/Objects/AddressGroups?location=device-group&device-group={devicegroup}&name={AddressGroup_name}'
    add_to_group_payload = ""
    headers = {
    'Content-Type': 'application/json',
    'X-PAN-KEY': key
    }
    response = requests.get(add_to_group_url, headers=headers,data=add_to_group_payload, verify=False)
    if response.status_code == 200:
        existingAddresses = response.json()["result"]["entry"][0]['static']['member']
        try:
            existingTags = response.json()["result"]["entry"][0]['tag']['member']
            add_to_group_payload = json.dumps({
            "entry": {
                "@name": AddressGroup_name,
                "static": {
                "member": existingAddresses + createdAddresses
                },
                "tag": {
                    "member": existingTags
                }
            }
            })

        except:
            add_to_group_payload = json.dumps({
            "entry": {
                "@name": AddressGroup_name,
                "static": {
                "member": existingAddresses + createdAddresses
                }
            }
            })
        

        response = requests.put(add_to_group_url, headers=headers,data=add_to_group_payload, verify=False)
        if response.status_code == 200:
            return True
        else:
            logger.error(f"Failed to add created address to the device group {devicegroup}")
            return False
    else:
        logger.error("Failed to get existing addresses objects to group")
        return False

#loop through the TobeBlocked.txt file to get the IP list     
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
                    continue
            f.truncate(0)
        else:
            logger.info(f'No valid IP in the TobeBlocked.txt file')

        if createdAddresses != []:
            logger.info(createdAddresses)
            logger.info(f'Addresses above will be added to {AddressGroup_name}')
            for devicegroup in AddressGroup_device_group_name:
                if add_to_address_group(firewall_ip, API_Key, devicegroup,AddressGroup_name):
                    logger.info(f'Addresses added to {AddressGroup_name} on {devicegroup} device group')
                else:
                    logger.warning(f'Failed to add addresses to {AddressGroup_name} on {devicegroup} device group') 
    
#getting the username and password and device group names             
if __name__ == "__main__":
 
    firewall_ip = "panorama.bswhealth.org/"
    Address_device_group_name="Internet_Edge" #this is the device group where the Adresses will be created. 
    AddressGroup_device_group_name = ["MSEE-EFW","TPEE-EFW","MSDC-USREDGE","TPDC-USREDGE"] #this is the device group where the Adresses Group exist where the address will be added.
    AddressGroup_name = 'Blacklisted_Internet_IPs'  #This is the address group name where the Ip addresses will be added.
    preIP_name = 'Blacklisted-' # this is the word going to be added before the IP name when creating the IP if left blank address name and description will be only the IP. 
    API_Key = login_firewall(firewall_ip, username, password)
    if API_Key:
        main()

