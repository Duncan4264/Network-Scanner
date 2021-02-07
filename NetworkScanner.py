#!/usr/bin/env python

#Import modules
import scapy.all as scapy
import argparse

# Function get get arguments passed after calling the script
def get_arguments():
    # Initialize the Argument Parser Module
    parser = argparse.ArgumentParser()
    # Add Argument --target user wishes to scan
    parser.add_argument("-t", "--target", dest="target", help="Target IP / IP Range")
    # add the parser arguments into a variable called options
    options = parser.parse_args()
    # Return the options variable housing parser arguments
    return options

# Function to scan an ip address
def scan(ip):
    # create an arp request variable in which sends arp request based off of given IP address
    arp_request = scapy.ARP(pdst=ip)
    # created a broadcast variable that ethers the mac address received
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    # create arp request broadcast variable that appends broadcast and arp request
    arp_request_broadcast = broadcast / arp_request
    # Create an answered list based off of the scapy srp using arp_request_broadcast variable
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]
    # Initialize new clients list
    clients_list = []
    # For each element in the answered list
    for element in answered_list:
        # Create a new dict with IP and Mac
        client_dict = {"ip": element[1].psrc, "mac": element[1].hwsrc}
        # Append dict to list
        clients_list.append(client_dict)
    # return clients list at end of scan
    return clients_list

# Function to print the results of the scan with results list parameter
def print_result(results_list):
    # Print the header
    print("IP\t\t\tMAC Address\n----------------------------------------------------------")
    # for each client in results list parameter
    for client in results_list:
        # print client IP two tabs and client mac
        print(client["ip"] + "\t\t" + client["mac"])

# Grab the options arguments
options = get_arguments()
# initialize variable to target argument as scan result
scan_result = scan(options.target)
# print scan results
print_result(scan_result)
