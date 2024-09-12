import socket
import os
import subprocess
import threading
import json
import sys
import nmap
import pyfiglet
import time
import re as r
from urllib.request import urlopen
from nmap import PortScanner
from datetime import datetime
from getmac import get_mac_address
from prettytable import PrettyTable
from datetime import date
from colorama import Fore  # For coloured writing
from apscheduler.schedulers.background import BackgroundScheduler


def presentation(to_write, font_type):
    if font_type == 'start':
        set_font = 'univers'
    elif font_type == 'end':
        set_font = 'broadway'
    elif font_type == 'subheading':
        set_font = 'bubble'
    else:
        set_font = 'graceful'
    ascii_banner = pyfiglet.figlet_format(to_write, set_font)
    if font_type == 'pause' or font_type == 'end':
        time.sleep(2)
    elif font_type == 'subheading':
        time.sleep(0.8)
    print(Fore.MAGENTA + ascii_banner)
    print(Fore.BLACK)
    if font_type == 'pause':
        time.sleep(2)
    elif font_type == 'end':
        time.sleep(1)


# Prints the name and IP of this device - you can use the IP
def name_and_ip():
    hostname = socket.gethostname()
    ip_address = socket.gethostbyname(hostname)
    print("Your Computer Name is:" + hostname + "\nYour Computer IP Address is:" + ip_address)


# The external IP gives details about the advice like location and service provider
def get_my_external_ip():
    d = str(urlopen('http://checkip.dyndns.com/').read())
    print(r.compile(r'Address: (\d+\.\d+\.\d+\.\d+)').search(d).group(1))


# A link to see the information given by the external IP
def ip_tracker_link():
    d = str(urlopen('http://checkip.dyndns.com/').read())
    g = r.compile(r'Address: (\d+\.\d+\.\d+\.\d+)').search(d).group(1)
    print('This is a link to IP-tracker connected to this device IP:\nhttps://www.ip-tracker.org/lookup.php?ip=' + g)


# Prints the MAC of Gateway and this device but has the capabilities to
def get_mac_of_this_device_or_from_an_ip():
    # MAC of gateway
    ip_mac = get_mac_address(ip="192.168.68.1")
    # My MAC
    mac = get_mac_address()
    print('Gateway MAC: ', ip_mac, '\nMy MAC: ', mac, '\n\nMy MAC Address information:\n\thttps://aruljohn.com/mac/' + mac[0:2] + mac[3:5] + mac[6:8] + mac[9:11] + mac[12:14] + mac[15:17])


# Prints the vendor
def vendor_from_mac():
    mac = str(urlopen('https://api.macvendors.com/' + get_mac_address()).read())
    print(mac[2:-1])


# Prints all IPs and MACs on the network
def all_ips_and_mac():
    internet_addresses = subprocess.check_output(("arp", "-a")).decode("ascii")
    dynamic_lines = []
    dynamic_internet_addresses = []
    dynamic_physical_addresses = []
    split_line_internet_address = internet_addresses.splitlines()
    for line in range(len(split_line_internet_address)):
        if (split_line_internet_address[line][46:53]) == 'dynamic':
            dynamic_lines.append(split_line_internet_address[line])
            dynamic_internet_addresses.append(split_line_internet_address[line][2:17])
            dynamic_physical_addresses.append(split_line_internet_address[line][24:41])
    print('These are the current dynamic addresses:\n\t\t Internet Address\t\t Physical Address')
    for new_one in range(len(dynamic_physical_addresses)):
        print('\t\t', dynamic_internet_addresses[new_one], '\t\t', dynamic_physical_addresses[new_one])


# Records all the MAC Addresses on the network
def network_scanner_with_logs():
    class Network(object):
        def __init__(self):
            hostname = socket.gethostname()
            ip_address = socket.gethostbyname(hostname)
            self.ip_default = ip_address

        def get_devices(self):
            """Return and creates a list of items that contain device information"""
            network_to_scan = self.ip_default + '/24'
            p_scanner = PortScanner()
            print('Scanning {}...'.format(network_to_scan))
            p_scanner.scan(hosts=network_to_scan, arguments='-sn')
            device_list = [(device, p_scanner[device]) for device in p_scanner.all_hosts()]
            return device_list

    class Device(object):
        def __init__(self, mac, ip, network_name, data=None):
            if data is None:
                data = {}
            self.mac = mac
            self.ip = ip
            self.network_name = network_name
            self.name = None
            self.allowed = None
            self.location = None
            device_check = self.device_known(data)
            if device_check:
                self.name = device_check['name']
                self.allowed = device_check['allowed']
                self.location = device_check['location']

        def device_known(self, data):
            """Return a str (given name of the device) or None # Checks whether the device is contained in the Dictionary (based on the mac address)"""
            mac = ''
            if self.mac in data:
                mac = self.mac
            elif self.mac.upper() in data:
                mac = self.mac.upper()
            if mac:
                name = '{} of {}'.format(data[mac]['type'], data[mac]['owner'])
                return {'name': name, 'allowed': data[mac]['allowed'], 'location': data[mac]['location']}
            return None

        def to_list(self):
            """Return a list [mac, ip, network_name, name, location, allowed]; Creates a list of device attributes as colored strings; green: allowed in the network; red: not allowed"""
            if self.allowed:
                color = g
            else:
                color = r
            mac = '{}{}{}'.format(color, self.mac, n)
            ip = '{}{}{}'.format(color, self.ip, n)
            network_name = '{}{}{}'.format(color, self.network_name, n)
            name = '{}{}{}'.format(color, self.name, n)
            location = '{}{}{}'.format(color, self.location, n)
            allowed = '{}{}{}'.format(color, self.allowed, n)
            return [mac, ip, network_name, name, location, allowed]

        def to_string(self):
            """Return a str Device information as a string with indentations for the log file"""
            return 'Log: {} \n\t Mac Address: {} \n\t Name in network: {} \n\t Given name: {} \n\t Allowed on network: {}'.format(datetime.now(), self.mac, self.network_name, self.name, self.allowed)

    # A selection of colors used to better visualize the strings in the terminal
    r = "\033[0;31;40m"  # red
    g = "\033[0;32;40m"  # green
    n = "\033[0m"  # normal

    def create_device_list(devices, data):
        """ Return a dictionary like {'known': [], 'unknown': []} Creates 2 lists from devices (class Device) and makes them available in a dictionary - 'known': list of known devices (mac address included in the data/device.json) - 'unknown': list of unknown devices (not included)"""
        known_devices = []
        unknown_devices = []
        for host, info in devices:
            device = Device(info['mac'], host, info['hostnames'][0]['name'], data)
            if device.name:
                known_devices.append(device)
            else:
                unknown_devices.append(device)
        return {'known': known_devices, 'unknown': unknown_devices}

    datapath = ''
    log_text = ''
    log_text += '\n\n'
    if __name__ == '__main__':
        datapath = 'data'
        try:
            with open("{}/Change.json".format('C:/Users/shira/PycharmProjects/Final project/data'), "r") as readFile:
                json_devices = json.load(readFile)
        except FileNotFoundError:
            json_devices = {}
            print('''No valid "data/Change.json" found. Please create one with the following format:
    {
        "00:00:00:00:00:00":
        {
          "type": "Device",
          "owner": "John Appleseed",
          "location": null,
          "allowed": true
        }
    }
                ''')
        network = Network()
        try:
            devices = network.get_devices()
        except KeyboardInterrupt:
            print('You stopped scanning. Scanning may take a while. If it takes too long, there may be a problem with the connection. Did you specify the correct network?')
            sys.exit()
        for host, info in devices:
            info['mac'] = get_mac_address(ip=host)
        data = create_device_list(devices, json_devices)
        table = PrettyTable()
        table.field_names = ["MAC ADDRESS", "IP", "NAME IN NETWORK", "NAME", 'LOCATION', 'ALLOWED']
        for device in data['known']:
            table.add_row(device.to_list())
            log_text += '{}\n'.format(device.to_string())
        print('Known Devices\n{}'.format(table))
        table = PrettyTable()
        table.field_names = ["MAC ADDRESS", "IP", "NAME IN NETWORK"]
        for device in data['unknown']:
            table.add_row(device.to_list()[:3])
            log_text += '{}\n'.format(device.to_string())
        print('Unknown Devices\n{}'.format(table))
    if not os.path.isdir(datapath):
        os.mkdir(datapath)
    with open("{}/{}.log".format(datapath, date.today()), "a") as appendFile:
        appendFile.write(log_text)
        print('You can find a log file with all devices in "data/{}.log"'.format(date.today()))


# Prints all past WI-FIs this device has connected to
def all_past_wifi():
    # getting metadata of the wi-fi network
    meta_data = subprocess.check_output(['netsh', 'wlan', 'show', 'profiles'])
    # decoding meta data from byte to string
    data = meta_data.decode('utf-8', errors="backslashreplace")
    # splitting data by line
    # string to list
    data = data.split('\n')
    # creating a list of wi-fi names
    names = []
    # traverse the list
    for i in data:
        # find "All User Profile" in each item as this item will have the wi-fi name
        if "All User Profile" in i:
            # if found split the item in order to get only the name
            i = i.split(":")
            # item at index 1 will be the wi-fi name
            i = i[1]
            # formatting the name - first and last character is useless
            i = i[1:-1]
            # appending the wi-fi name in the list
            names.append(i)

    # printing the wi-fi names
    print("All wifi that system has connected to are \n-----------------------------------------")
    for name in names:
        print(name)
    print('\n')


# The passwords of the past wi-fis
def passwords_of_all_wifi():
    command = subprocess.check_output(['netsh', 'wlan', 'show', 'profiles']).decode('utf-8').split('\n')
    profiles = [i.split(":")[1][1:-1] for i in command if "All User Profile" in i]
    for i in profiles:
        results = subprocess.check_output(['netsh', 'wlan', 'show', 'profile', i, 'key=clear']).decode('utf-8').split('\n')
        results = [b.split(":")[1][1:-1] for b in results if "Key Content" in b]
        try:
            print("{:<30}|  {:<}".format(i, results[0]))
        except IndexError:
            print("{:<30}|  {:<}".format(i, "\'This is an error message!\'"))


# scans 127.0.0.1 for open ports
def open_ports_on_network():
    ip_to_check = '127.0.0.1'
    # initialize the port scanner
    network_scan = nmap.PortScanner()
    # scan localhost for ports in range 21-443
    network_scan.scan(ip_to_check, '21-443')
    # run a loop to print all the found result about the ports
    for host in network_scan.all_hosts():
        print('Host : %s (%s)' % (host, network_scan[host].hostname()), '\nState : %s' % network_scan[host].state())
        for proto in network_scan[host].all_protocols():
            print('----------\nProtocol : %s' % proto)
            port_1 = network_scan[host][proto].keys()
            port_1 = sorted(port_1)
            for port in port_1:
                print('port :%s\t state : %s' % (port, network_scan[host][proto][port]['state']))


# check for open ports on the IP of this devoce
def open_ports_on_an_ip():
    def threader():
        while True:
            worker = q.get()
            portscan(worker)
            q.task_done()

    def portscan(port):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            con = s.connect((t_ip, port))
            with print_lock:
                print(port, 'is open')
            con.close()
        except:
            pass

    socket.setdefaulttimeout(0.25)
    print_lock = threading.Lock()
    target = socket.gethostbyname(socket.gethostname())
    t_ip = socket.gethostbyname(target)
    print('Starting scan on host: ', t_ip)
    q = Queue()
    start_time = time.time()
    for x in range(100):
        t = threading.Thread(target=threader)
        t.daemon = True
        t.start()
    for worker in range(1, 500):
        q.put(worker)
    q.join()
    print('Time taken:', time.time() - start_time)


# Repeats indefinitely
def repeat():
    # This can be replaced by any function to indefinitely repeat
    def task():
        network_scanner_with_logs()

    print('\n\tYou are about to enter an endless task')
    scheduler = BackgroundScheduler()
    scheduler.add_job(task, 'interval', seconds=5)
    scheduler.start()
    try:
        while True:
            time.sleep(1)
    except Exception:
        scheduler.shutdown()


presentation('This is my final code!', 'start')
while True:
    to_do = (input('\n\nWhat would you like to see today?\n\t1. Name and IP\n\t2. external IP\n\t3. Link for IP information\n\t4. My MAC & other MAC\n\t5. Find the vendor of the device\n\t6. All IP and MAC on this network\n\t7. All IP and MAC on this network & logged\n\t8. All past WI-FIs this device has connected to\n\t9. All past WI-FIs this device has connected to and their passwords\n\t10. Open ports on 127.0.0.1\n\t11. open ports on my IP\nIf you would like to see it all together press 0\nYou can always type \'exit\' to quit:'))
    if to_do == '1':
        presentation('Name and IP:', 'subheading')
        name_and_ip()
    elif to_do == '2':
        presentation('external IP:', 'subheading')
        get_my_external_ip()
    elif to_do == '3':
        presentation('Link for IP information:', 'subheading')
        ip_tracker_link()
    elif to_do == '4':
        presentation('My MAC & other MAC:', 'subheading')
        get_mac_of_this_device_or_from_an_ip()
    elif to_do == '5':
        presentation('Find vendor:', 'subheading')
        vendor_from_mac()
    elif to_do == '6':
        presentation('All IP and MAC on this network:', 'subheading')
        all_ips_and_mac()
    elif to_do == '7':
        presentation('All IP and MAC on this network & logged:', 'subheading')
        network_scanner_with_logs()
    elif to_do == '8':
        presentation('All past WI-FIs this device has connected to:', 'subheading')
        all_past_wifi()
    elif to_do == '9':
        presentation('All past WI-FIs this device has connected to and their passwords:', 'subheading')
        passwords_of_all_wifi()
    elif to_do == '10':
        presentation('Open ports on 127.0.0.1:', 'subheading')
        open_ports_on_network()
    elif to_do == '11':
        presentation('open ports on my IP:', 'subheading')
        open_ports_on_an_ip()
    elif to_do == '0':
        presentation('Part  1', 'pause')
        presentation('Name and IP:', 'subheading')
        name_and_ip()
        presentation('external IP:', 'subheading')
        get_my_external_ip()
        presentation('Link for IP information:', 'subheading')
        ip_tracker_link()
        presentation('My MAC & other MAC:', 'subheading')
        get_mac_of_this_device_or_from_an_ip()
        presentation('Find vendor:', 'subheading')
        vendor_from_mac()
        presentation('Part  2', 'pause')
        presentation('All IP and MAC on this network:', 'subheading')
        all_ips_and_mac()
        presentation('All IP and MAC on this network & logged:', 'subheading')
        network_scanner_with_logs()
        presentation('Part  3', 'pause')
        presentation('All past WI-FIs this device has connected to:', 'subheading')
        all_past_wifi()
        presentation('All past WI-FIs this device has connected to and their passwords:', 'subheading')
        passwords_of_all_wifi()
        presentation('Part  4', 'pause')
        presentation('Open ports on 127.0.0.1:', 'subheading')
        open_ports_on_network()
        presentation('open ports on my IP:', 'subheading')
        open_ports_on_an_ip()
        presentation('The end!!', 'end')
    elif to_do == 'exit':
        quit()
    else:
        break
    time.sleep(1.5)

repeat()
