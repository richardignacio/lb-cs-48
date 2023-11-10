import datetime
import os
from pprint import pprint
import time

""" Global variables """

LOG_FILE = "arpspoof.log"

""" Functions """

"""
    Project Task 1: ARP Table Extraction
    1. Import required modules
    2. Define a function to extract the arp table
    3. There will be at least three variables:
        a. One to store the results of displaying the arp table
        b. Another for storing the lines from the arp table results
        c. Finally, one to store the mapping from IP to MAC addresses
    4. Iterate over the lines
        a. Filter out or filter in the relevant lines
        b. Extract the IP and MAC from each line
        c. Save the IP/MAC mapping
"""


def extract_arp_table():
    """Extract the arp table and save it"""
    arp_output = os.popen("arp -a").read()

    """
    arp_output looks like the following:
    
Interface: 192.168.7.122 --- 0x4
  Internet Address      Physical Address      Type
  192.168.7.1           4c-01-43-ee-a2-12     dynamic   
  192.168.7.65          38-f9-d3-2b-63-57     dynamic   
  192.168.7.112         08-00-27-d5-37-4e     dynamic   
  192.168.7.231         c4-91-0c-ab-88-09     dynamic   
  192.168.7.255         ff-ff-ff-ff-ff-ff     static    
  224.0.0.22            01-00-5e-00-00-16     static    
  224.0.0.251           01-00-5e-00-00-fb     static    
  224.0.0.252           01-00-5e-00-00-fc     static    
  231.7.168.192         01-00-5e-07-a8-c0     static    
  239.255.255.250       01-00-5e-7f-ff-fa     static    
  255.255.255.255       ff-ff-ff-ff-ff-ff     static    
    """

    arp_table = {}
    arp_lines = arp_output.splitlines()

    for line in arp_lines:
        if "dynamic" in line:
            fields = line.split()
            ip_address = fields[0]
            mac_address = fields[1]
            arp_table[ip_address] = mac_address

    return arp_table


"""
    Project Task 2: Identifying MAC Address Duplication
    1. Define a function with one parameter.
        a. The argument passed to this should be the variable that has the
            IP to MAC address mapping,
    2. Implement this algorithm to find a duplicate
        a. Iterate over the MAC addresses
        b. Create a variable to store iterated MAC addresses
        c. On each iteration compare the current MAC address with MAC addresses
            that have already been iterated to look for duplicates.
        d. Print an alert message if there is a duplicate.
        e. Add the current MAC address to the variable that stores iterated MAC addresses      
"""


def identify_duplicate_macs(arp_table):
    """ Iterate through MAC address to find duplicate MAC addresses"""

    macs_seen = []
    for mac in arp_table.values():
        if mac in macs_seen:
            print(f"Got a duplicate MAC address: {mac}")
            log_duplicate_mac(mac)
        else:
            macs_seen.append(mac)


"""
    Project Task 3: Logging Events
"""


def log_duplicate_mac(duplicate):
    """ Log duplicate MAC address to a log file """

    with open(LOG_FILE, "a") as log_file:
        timestamp = datetime.datetime.now()
        log_entry = f"{timestamp} arpspoof CRITICAL Found a duplicate MAC address: {duplicate}\n"
        log_file.write(log_entry)


def main():
    try:
        """
        Continuously detect arp spoofing attacks
        """
        print("Starting ARP Spoof Detector")
        while True:
            print("Detecting...")
            ip_mac_table = extract_arp_table()
            identify_duplicate_macs(ip_mac_table)
            time.sleep(0.5)

    except KeyboardInterrupt:
        print("Exiting ARP Spoof Detector")


# "Magic main"
if __name__ == '__main__':
    main()
