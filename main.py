# InterfaceIPtoDNS ver. 1.0
# Script will generate CSV file with IP address inventory across all devices in the inventory file
# external modules used: netmiko (for Cisco ASA support), napalm
# pip install napalm, netmiko
# TODO: Multi-threading support
# ----------------------------------------------
# Inventory format: hostname;type;status
# type - cisco/cisco-asa/cisco-nx
# status - up/down (TODO: create status handler)
# ----------------------------------------------

from napalm import get_network_driver
from netmiko import ConnectHandler, NetMikoAuthenticationException, NetMikoTimeoutException
import ipaddress
import csv
from datetime import datetime

# Define credentials
USER_NAME = 'user'
PASSWORD = 'pass'


def asa_get_interfaces_ip(dev_name: str, username: str, password: str):
    result_dict = {}
    netmiko_device_param = {
        'device_type': 'cisco_asa',
        'ip': dev_name,
        'username': username,
        'password': password,
        'secret': password,
    }

    with ConnectHandler(**netmiko_device_param) as ssh:
        ssh.enable()
        result = ssh.send_command('show interface ip brief')

    for line in result.splitlines():
        items = line.split()
        if 'interface' not in items[0].replace("'", "").lower():    # Always skip first line
            try:
                ip_address = ipaddress.ip_address(items[1].replace("'", ""))
                if ip_address.version is 4 or 6:    # Check if IP address syntax is correct
                    if not ip_address.is_loopback:  # Exclude possible internal interfaces
                        ifname = items[0].replace("'", "")

                        dict_prefix = {'prefix_length': 0}
                        dict_ip = {ip_address.compressed: dict_prefix}
                        dict_ipver = {'ipv'+str(ip_address.version): dict_ip}
                        result_dict[ifname] = dict_ipver
            except ValueError:
                continue    # if not an IP address, than go to the next loop iteration

    return result_dict


def get_devices_from_file(filename='inventory.db'):

    devices = {}

    with open(filename, 'r') as file:
        for line in file:
            if line.split(';')[0][0] != '#':
                dict_name = line.split(';')[0].strip()

                inner_dict = {'name': line.split(';')[0].strip()}
                inner_dict.update({'type': line.split(';')[1].strip()})
                inner_dict.update({'status': line.split(';')[2].strip()})

                devices[dict_name] = inner_dict

    return devices


def get_devices_ip(devices_name: dict):
    driver_ios = get_network_driver('ios')
    driver_nxos = get_network_driver('nxos_ssh')
    devices_ip = {}

    for deviceName in devices_name:
        print('Working on: ' + str(deviceName))
        try:
            if devices_name[deviceName].get('type') == 'cisco-nx':
                device = driver_nxos(deviceName, USER_NAME, PASSWORD)
                device.open()
                devices_ip[deviceName] = device.get_interfaces_ip()
                device.close()
            elif devices_name[deviceName].get('type') == 'cisco':
                device = driver_ios(deviceName, USER_NAME, PASSWORD)
                device.open()
                devices_ip[deviceName] = device.get_interfaces_ip()
                device.close()
            elif devices_name[deviceName].get('type') == 'cisco-asa':
                devices_ip[deviceName] = asa_get_interfaces_ip(deviceName, USER_NAME, PASSWORD)

        except NetMikoAuthenticationException:
            print('\x1b[1;30;41m' + 'Authentication failure: ' + deviceName + '\x1b[0m')
            continue
        except NetMikoTimeoutException:
            print('\x1b[1;30;41m' + 'Unable to connect: ' + deviceName + '\x1b[0m')
            continue

    return devices_ip


def format_interface_name(interface_name: str):
    # Shorten interface name
    if 'gigabitethernet' in interface_name.lower():
        interface_name = interface_name.lower().replace('gigabitethernet', 'g')
    elif 'fastethernet' in interface_name.lower():
        interface_name = interface_name.lower().replace('fastethernet', 'f')
    elif 'ethernet' in interface_name.lower():
        interface_name = interface_name.lower().replace('ethernet', 'e')
    elif 'vlan' in interface_name.lower():
        interface_name = interface_name.lower().replace('vlan', 'v')
    elif 'tunnel' in interface_name.lower():
        interface_name = interface_name.lower().replace('tunnel', 'tu')
    elif 'loopback' in interface_name.lower():
        interface_name = interface_name.lower().replace('loopback', 'lo')
    elif 'port-channel' in interface_name.lower():
        interface_name = interface_name.lower().replace('port-channel', 'po')
    elif 'management' in interface_name.lower():
        interface_name = interface_name.lower().replace('management', 'm')
    elif 'dialer' in interface_name.lower():
        interface_name = interface_name.lower().replace('dialer', 'dl')

    # Replace unsupported DNS characters with an underscore
    if '/' in interface_name:
        interface_name = interface_name.replace('/', '_')
    if ':' in interface_name:
        interface_name = interface_name.replace(':', '_')
    if '.' in interface_name:
        interface_name = interface_name.replace('.', '_')

    return interface_name


startTime = datetime.now()  # Save script start time
devices_dict = get_devices_ip(get_devices_from_file('inventory.db'))


with open('output.csv', 'w+', newline='') as myfile:
    wr = csv.writer(myfile, quoting=csv.QUOTE_NONE)
    wr.writerow(['Hostname', 'IP address'])

    for device_name in devices_dict:
        for int_name in devices_dict[device_name]:
            for ip_ver in devices_dict[device_name][int_name]:
                if 'ipv4' in ip_ver:
                    for ip_addr in devices_dict[device_name][int_name][ip_ver]:
                        print(device_name.split('.')[0] + '-' + format_interface_name(int_name)
                              + '.kfins.ru' + ',' + ip_addr)
                        wr.writerow([device_name.split('.')[0] + '-' + format_interface_name(int_name), ip_addr])

print('Overall elapsed time: ' + str(datetime.now() - startTime))   # Print script execution time on the end
