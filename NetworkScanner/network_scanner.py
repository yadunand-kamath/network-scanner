""" Network Scanner Code """

import requests    # to make HTTP requests
import json        # library for handling JSON data

from boltiot import Bolt    # importing Bolt from boltiot module
import conf                 # config file

mybolt = Bolt(conf.bolt_api_key, conf.device_id)

import scapy.all as sc    # import scapy library

# Function to Scan the IP
def scan(ip):

    arp_request = sc.ARP(pdst = ip)
    broadcast = sc.Ether(dst = "ff:ff:ff:ff:ff:ff")
    x = broadcast/arp_request
    answered_list = sc.srp(x, timeout=1, verbose=False)[0]
    targets_list = []

    for element in answered_list:
        targets_dict = {"ip":element[1].psrc, "mac":element[1].hwsrc}
        targets_list.append(targets_dict)
    return targets_list

# Function to Print the Output Result
def result(results_list):

    print("IP\t\tMAC Address\n-------------------------------------")

    for target in results_list:
        print(target["ip"] + "\t" + target["mac"])

scan_target = input("Enter target IP:\n")
scan_result = scan(scan_target)
result(scan_result)

# Function to send output to Telegram
def telegram_message(message):

    url = "https://api.telegram.org/" + conf.telegram_bot_id + "/sendMessage"
    data = {"chat_id": conf.telegram_chat_id, "text": message}

    try:
        response = requests.request("POST", url, params=data)
        print("This is the Telegram URL")
        print(url)
        print("This is the Telegram response")
        print(response.text)
        telegram_data = json.loads(response.text)
        return telegram_data["ok"]

    except Exception as e:
        print("An error occurred in sending the alert message via Telegram")
        print(e)
        return False

message = "These are the details of the devices connected on the network:\n" + str(scan_result)

telegram_status = telegram_message(message)
print("This is the telegram status:\n", telegram_status)
