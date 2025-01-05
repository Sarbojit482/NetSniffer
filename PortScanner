#!/usr/bin/python3

import nmap

scanner=nmap.PortScanner()

print("welcome to simple nmap scanning tool!!")
print("- - - - - - - - - - - - - - - - - - - - - - - ")

ip_addr=input("please enter the Ip Address to scan:")
print("The IP entered is:",ip_addr)

print("Type of  IP entered is:",type(ip_addr))
resp=input("""\n please Enter the type of Scan you want to Perform:
	1.SYN Scan
	2.UDP Scan
	3.Comprehnsiv Scan\n""")
	
print("You have selected :", resp)

resp_dict={'1':['-sV -sS -vV','tcp'], '2':['-sV -sU -vV','udp'],'3':['-sV -sS -vv -O -A  -sC','tcp']}

if resp not in resp_dict.key():

	print("please Enter a valid option!")
	
else:

	print("Nmap Version",scnner.nmap_version())
scanner.scan(ip_adder,"1-1024",resp_dict[resp][0])

if scanner[ip_adder].state()=='up':

	print("\n  Host is up.Scan Result:")

for proto in scanner[ip_addr].all_protocols():

	print("\n Protocol:{}".format(proto))
	
		print("OpenPorts:{}".format(','.join(map(str,
scanner[ip_addr][proto].keys()))))

for port,info in scanner[ip_addr][proto].items():

	print("\nPort:{}\nService:{}\nState:{}".format(port,info['name'],info['state']))
