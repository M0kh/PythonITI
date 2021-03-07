import socket
import re
import ipaddress
import time
import sys
import os
import nmap  #pip3 install python-nmap
import csv
import struct
import textwrap
import yagmail  #pip3 install yagmail[all]
import iptc #pip install --upgrade python-iptables

print("""  __  __           _      _       _                    __ 
 |  \/  |         | |    | |     | |                  / _|
 | \  / |   __ _  | | __ | |__   | |   ___    _   _  | |_ 
 | |\/| |  / _` | | |/ / | '_ \  | |  / _ \  | | | | |  _|
 | |  | | | (_| | |   <  | | | | | | | (_) | | |_| | | |  
 |_|  |_|  \__,_| |_|\_\ |_| |_| |_|  \___/   \__,_| |_|  
                                                          
                                                          """)

IPRegex = re.compile("^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$")
if os.name == 'nt':
    if not os.path.exists('C://Scan'):
        os.makedirs('C://Scan')
        os.chdir('C://Scan')
else:
    if not os.path.exists('//tmp//Scan'): 
        os.makedirs('//tmp//Scan')
        os.chdir('//tmp//Scan')

def sniffer():  #Packet sniffer
    print("Sniffing the traffic, CTRL+C to stop")
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)  #Get currently connected interface IP address
    s.connect(("8.8.8.8", 80))
    InterfaceAddress = s.getsockname()[0]
    print("Interface IP: " + InterfaceAddress)
    time.sleep(2)
    
    pcap = Pcap('capture.pcap')
    conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
    
    while True:
        try:
            raw_data, addr = conn.recvfrom(65535)
            pcap.write(raw_data)
            eth = Ethernet(raw_data)
            ipv4 = IPv4(eth.data)
            print('IPv4 Packet:')
            print('Source: {}, Destination: {}'.format(ipv4.src, ipv4.target))

            SplitInterfaceAddress = InterfaceAddress.split(".")
            SplitSourceAddress = ipv4.src.split(".")
            if int(SplitInterfaceAddress[0]) == int(SplitSourceAddress[0]):
                continue
            elif int(SplitInterfaceAddress[1]) == int(SplitSourceAddress[1]):
                continue
            elif int(SplitInterfaceAddress[2]) == int(SplitSourceAddress[2]):
                continue
            else:
                print("Interface Subnet Mismatch Detected, Interface IP: " + InterfaceAddress + ", Source IP: " + ipv4.src)
                f = open("Mismatch Alert.txt", "a")
                f.write("Interface Subnet Mismatch Detected, Interface IP: " + InterfaceAddress + ", Source IP: " + ipv4.src +'\n')
                f.close()
        except KeyboardInterrupt:
            options()
class IPv4:
    def __init__(self, raw_data):
        version_header_length = raw_data[0]
        self.version = version_header_length >> 4
        self.header_length = (version_header_length & 15) * 4
        self.ttl, self.proto, src, target = struct.unpack('! 8x B B 2x 4s 4s', raw_data[:20])
        self.src = self.ipv4(src)
        self.target = self.ipv4(target)
        self.data = raw_data[self.header_length:]

    # Returns properly formatted IPv4 address
    def ipv4(self, addr):
        return '.'.join(map(str, addr))

class Ethernet:
    def __init__(self, raw_data):
        dest, src, prototype = struct.unpack('! 6s 6s H', raw_data[:14])
        self.proto = socket.htons(prototype)
        self.data = raw_data[14:]
        
class Pcap:
    def __init__(self, filename, link_type=1):
        self.pcap_file = open(filename, 'wb')
        self.pcap_file.write(struct.pack('@ I H H i I I I', 0xa1b2c3d4, 2, 4, 0, 0, 65535, link_type))
    def write(self, data):
        ts_sec, ts_usec = map(int, str(time.time()).split('.'))
        length = len(data)
        self.pcap_file.write(struct.pack('@ I I I I', ts_sec, ts_usec, length, length))
        self.pcap_file.write(data)
    def close(self):
        self.pcap_file.close()



def BlockIP(ip):  #Block connected IPs
    chain = iptc.Chain(iptc.Table(iptc.Table.FILTER), "INPUT")
    rule = iptc.Rule()
    rule.in_interface = "eth0"
    rule.src = ip
    target = iptc.Target(rule, "DROP")
    rule.target = target
    chain.insert_rule(rule)

def Listener():  #Port Listener
    print("Listening to ports, CTRL+C to stop")
    ip =''
    for port in range(10):
        try:
            ListenSocket = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
            ListenSocket.settimeout(2)
            ListenSocket.bind((ip,port))
        except socket.error:
            ListenSocket.close()
            print("Port {} is used".format(port))
            continue
        except KeyboardInterrupt:
            print("Stopping the listener.")
            options()
        try:
            ListenSocket.listen(2)
            conn, addr = ListenSocket.accept()
            print("IP " + str(addr[0]) + " Connected") #Block this IP
            BlockIP(str(addr[0]))
            f = open("Blocked IPs.txt", "a")
            f.write(str(addr[0])+', ')
            f.close()
        except socket.timeout:
            ListenSocket.close()
            print("No incoming connections after 2 seconds on port {}".format(port))
        except KeyboardInterrupt:
            print("Stopping the listener.")
            options()
    try:
        if os.stat("Blocked IPs.txt").st_size == 0:
            print("No IPs were connected to the ports")
        else:
            def email():  #Sending email with the results
                print("Do you want to send an email with the list of blocked IPs? Note: You will have to supply an email and a password.")
                print("1- Yes")
                print("2- No")
                print("Type the number of your choice\n")
                choice = input()
                if choice == "1":
                    sender = input("Please enter the email that will be used to send the attachement: ")
                    reciever = input("Please enter the email that will receive the attachement (can be the same email): ")
                    subject = input("Please enter the email subject: ")
                    try:
                        yag = yagmail.SMTP(sender)
                        contents = ['Here is the list of the blocked IPs', 'Blocked IPs.txt']
                        yag.send(reciever, subject, contents)
                    except socket.timeout:
                        print("An error occured, please re-enter the email addresses")
                        email()
                elif choice == "2":
                    print("Done")
                else:
                    print("Error: Wrong Input, Please Reselect")
                    email()
            email()
    except FileNotFoundError:
        print("No IPs were connected to the ports")
        options()
        
def nmapTCP(ip):  #Nmap TCP
    print("Scanning Open Ports")
    try:
        nm = nmap.PortScanner()
        f = open(ip+" TCP Ports.txt", "r")
        ports=str(f.read())
        nm.scan(ip, ports[:-1], arguments='-sC -sV')
        print("Scanning Command: " + nm.command_line())
        f = open(ip+" nmap tcp scan.csv", "a")
        f.write(nm.csv())
        f.close()
        f = open(ip+" nmap tcp scan.csv")
        csv_f = csv.reader(f, delimiter=';',quotechar=' ')
        for row in csv_f:
            print(' '.join(row))
    except FileNotFoundError:
        print("No Open TCP ports were found.")

    except KeyboardInterrupt:
        print("Stopping the scan.")
        options()
        
    print("Scanning Complete")

def nmapUDP(ip):  #Nmap UDP
    print("Scanning Open Ports")
    try:
        nm = nmap.PortScanner()
        f = open(ip+" UDP Ports.txt", "r")
        ports=str(f.read())
        nm.scan(ip, ports[:-1], arguments='-sC -sV -sU')
        print("Scanning Command: " + nm.command_line())
        f = open(ip+" nmap udp scan.csv", "a")
        f.write(nm.csv())
        f.close()
        f = open(ip+" nmap udp scan.csv")
        csv_f = csv.reader(f, delimiter=';',quotechar=' ')
        for row in csv_f:
            print(' '.join(row))     
    except FileNotFoundError:
        print("No Open UDP ports were found.")
    except KeyboardInterrupt:
        print("Stopping the scan.")
        options()
        
    print("Scanning Complete")

def SingleTCPScan(ip):  #Single IP TCP Scan
    if os.name == 'nt':
        os.chdir('C://Scan')
        if not os.path.exists(ip):
            os.makedirs(ip)
            os.chdir(ip)
        print("The results will be saved in C:\Scan\ " + str(ip))
    else:
        os.chdir('//tmp//Scan')
        if not os.path.exists(ip):
            os.makedirs(ip)
            os.chdir(ip)
        print("The results will be saved in /tmp/Scan/" + str(ip))
    print("Scanning Ports")
    for port in range(1,65535):
        try:
            ScanSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            socket.setdefaulttimeout(0.1)
            Connection = ScanSocket.connect_ex((ip,port))
            if(Connection == 0):
                print ('Port ' + str(port) + ' Open')
                f = open(ip+" TCP Ports.txt", "a")
                f.write(str(port)+',')
                f.close()
            ScanSocket.close()
        except KeyboardInterrupt:
            print("Stopping the scan.")
            options()
    nmapTCP(ip)
    
def SingleUDPScan(ip):  #Single IP UDP Scan
    if os.name == 'nt':
        os.chdir('C://Scan')
        if not os.path.exists(ip):
            os.makedirs(ip)
            os.chdir(ip)
        print("The results will be saved in C:\Scan\ " + str(ip))
    else:
        os.chdir('//tmp//Scan')
        if not os.path.exists(ip):
            os.makedirs(ip)
            os.chdir(ip)
        print("The results will be saved in /tmp/Scan/" + str(ip))
    print("Scanning Ports")
    for port in range(1,65535):
        ScanSocket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        ScanSocket.settimeout(2)
        data = "Hello".encode()
        ScanSocket.sendto(data,(ip,port))
        try:
            print("Port:" + str(port))
            rdata, addr = ScanSocket.recv(1024)
            print("received message: %s" %rdata)
            f = open(ip+" UDP Ports.txt", "a")
            f.write(str(port)+',')
            f.close()

        except KeyboardInterrupt:
            print("Stopping the scan.")
            options()
        except:
            ScanSocket.close()
            print("Connection timed out")
    nmapUDP(ip)

def SingleScan(ip):  #Single IP scanning method
    print("How do you want to scan?")
    print("1- TCP")
    print("2- UDP")
    print("Type the number of your choice\n")
    ScanChoice = input()
    if ScanChoice == "1":
        SingleTCPScan(ip)
    if ScanChoice == "2":
        SingleUDPScan(ip)

def MultiTCPScan(ip1, ip2):  #Multi IP TCP Scan
    if os.name == 'nt':
        os.chdir('C://Scan')
        if not os.path.exists(ipaddress.IPv4Address(ip1).compressed+' - '+ipaddress.IPv4Address(ip2).compressed):
            os.makedirs(ipaddress.IPv4Address(ip1).compressed+' - '+ipaddress.IPv4Address(ip2).compressed)
            os.chdir(ipaddress.IPv4Address(ip1).compressed+' - '+ipaddress.IPv4Address(ip2).compressed)
        print("The results will be saved in C:\Scan\ " + str(ipaddress.IPv4Address(ip1).compressed)+' - '+str(ipaddress.IPv4Address(ip2).compressed))
    else:
        os.chdir('//tmp//Scan')
        if not os.path.exists(ipaddress.IPv4Address(ip1).compressed+' - '+ipaddress.IPv4Address(ip2).compressed):
            os.makedirs(ipaddress.IPv4Address(ip1).compressed+' - '+ipaddress.IPv4Address(ip2).compressed)
            os.chdir(ipaddress.IPv4Address(ip1).compressed+' - '+ipaddress.IPv4Address(ip2).compressed)
        print("The results will be saved in /tmp/Scan/" + str(ipaddress.IPv4Address(ip1).compressed)+' - '+str(ipaddress.IPv4Address(ip2).compressed))

    for IPs in range(int(ip1), int(ip2)+1):
        ScanningIP = ipaddress.IPv4Address(IPs).compressed
        print("Scanning: " + str(ScanningIP))
        print("Scanning Ports")
        time.sleep(1)
        for port in range(1,65535):
            try:
                ScanSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                socket.setdefaulttimeout(0.1)
                Connection = ScanSocket.connect_ex((ScanningIP,port))
                if(Connection == 0):
                    print ('Port ' + str(port) + ' Open')
                    f = open(ScanningIP+" TCP Ports.txt", "a")
                    f.write(str(port)+',')
                    f.close()
                ScanSocket.close() 
            except KeyboardInterrupt:
                print("Stopping the scan.")
                options()
            except:
                ScanSocket.close()
        nmapTCP(ScanningIP)

def MultiUDPScan(ip1, ip2):  #Multi IP UDP Scan
    if os.name == 'nt':
        os.chdir('C://Scan')
        if not os.path.exists(ipaddress.IPv4Address(ip1).compressed+' - '+ipaddress.IPv4Address(ip2).compressed):
            os.makedirs(ipaddress.IPv4Address(ip1).compressed+' - '+ipaddress.IPv4Address(ip2).compressed)
            os.chdir(ipaddress.IPv4Address(ip1).compressed+' - '+ipaddress.IPv4Address(ip2).compressed)
        print("The results will be saved in C:\Scan\ " + str(ipaddress.IPv4Address(ip1).compressed)+' - '+str(ipaddress.IPv4Address(ip2).compressed))
    else:
        os.chdir('//tmp//Scan')
        if not os.path.exists(ipaddress.IPv4Address(ip1).compressed+' - '+ipaddress.IPv4Address(ip2).compressed):
            os.makedirs(ipaddress.IPv4Address(ip1).compressed+' - '+ipaddress.IPv4Address(ip2).compressed)
            os.chdir(ipaddress.IPv4Address(ip1).compressed+' - '+ipaddress.IPv4Address(ip2).compressed)
        print("The results will be saved in /tmp/Scan/" + str(ipaddress.IPv4Address(ip1).compressed)+' - '+str(ipaddress.IPv4Address(ip2).compressed))

    for IPs in range(int(ip1), int(ip2)+1):
        ScanningIP = ipaddress.IPv4Address(IPs).compressed
        print("Scanning: " + str(ScanningIP))
        print("Scanning Ports")
        time.sleep(1)
        for port in range(1,65535):
            ScanSocket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            ScanSocket.settimeout(2)
            data = "Hello".encode()
            ScanSocket.sendto(data,(ScanningIP,port))
            try:
                print("Port:" + str(port))
                rdata, addr = ScanSocket.recvfrom(1024)
                print("received message: %s" %rdata)
                f = open(ScanningIP+" UDP Ports.txt", "a")
                f.write(str(port)+',')
                f.close()
            except KeyboardInterrupt:
                print("Stopping the scan.")
                options()
            except:
                ScanSocket.close()
                print("Connection timed out")
        nmapUDP(ScanningIP)

def MultiScan(ip1, ip2):  #Multi IP scanning method
    print("How do you want to scan?")
    print("1- TCP")
    print("2- UDP")
    print("Type the number of your choice\n")
    ScanChoice = input()
    if ScanChoice == "1":
        MultiTCPScan(ip1, ip2)
    if ScanChoice == "2":
        MultiUDPScan(ip1, ip2)

def CheckIP():  #Validating single IP input
    ip = input("Enter the IP address\n")
    if re.match(IPRegex, ip):
        SingleScan(ip)
    else:
        print("please enter a correct ip")
        CheckIP()

def CheckIPs():  #Validating IP range input
    ipStart = input("Enter the starting range of the IP address\n")
    if re.match(IPRegex, ipStart):
        print("")
    else:
        print("please enter a correct starting IP address")
        CheckIPs()
    
    ipEnd = input("Enter the end range of the IP address\n")
    if re.match(IPRegex, ipEnd):
        print("")
    else:
        print("please enter a correct ending IP address")
        CheckIPs()
    ipStartAddress = ipaddress.IPv4Address(ipStart)
    ipEndAddress = ipaddress.IPv4Address(ipEnd)
    print("IPs that will be scanned:")
    for IPs in range(int(ipStartAddress), int(ipEndAddress)+1):
        print(ipaddress.IPv4Address(IPs))
    MultiScan((ipStartAddress), (ipEndAddress))

def options():
    try:
        print("Please choose an option")
        print("1- Scan a Single IP")
        print("2- Scan a range of IPs")
        print("3- Listen to ports and block any IP that connects")
        print("4- Sniff the traffic")
        print("5- Exit")
        print("Type the number of your choice\n")
        choice = input()
        if choice == "1":
            CheckIP()
        elif choice == "2":
            CheckIPs()
        elif choice == "3":
            Listener()
        elif choice == "4":
            sniffer()
        elif choice == "5":
            print("Goodbye :D")
            exit()
        else:
            print("Error: Wrong Input, Please Reselect")
            options()
    except KeyboardInterrupt:
        options()
options()
