#!/usr/bin/env python3
import os
from colorama import init, Fore, Back

init(autoreset=True)

def banner():
	print(Fore.GREEN + """  
 _   _      _ __     ___                 
| \ | | ___| |\ \   / (_)_ __   ___ _ __ 
|  \| |/ _ \ __\ \ / /| | '_ \ / _ \ '__|
| |\  |  __/ |_ \ V / | | |_) |  __/ |   
|_| \_|\___|\__| \_/  |_| .__/ \___|_|   
                        |_|                                     
 <<<<=>>>> Author: ACW360 <<<<=>>>>""" + "\n")
banner()         

def information_gathering():
	banner()
	def nmap():
		os.system("apt install nmap ")
		os.system("sudo apt install nmap")
		os.system("clear")
		print(Fore.GREEN + "You can run the command nmap -h from anywhere in the terminal to see its help options.\n")
		
	def whatweb():
		os.system("pip install dnspython")
		os.system("pip install colorama")
		os.system("pip install whatweb")
		os.system("clear")
		print(Fore.GREEN + "You can run the command whatweb -h from anywhere in the terminal to see its help options.\n")
		
	def shodan():
		os.system("pip install setuptools")
		os.system("pip install shodan")
		os.system("clear")
		print(Fore.GREEN + "You can run the command shodan -h from anywhere in the terminal to see its help options.\n")
	
	
	def wafw00f():
		os.system("pip install wafw00f")
		os.system("clear")
		print(Fore.GREEN + "You can run the command whatweb -h from anywhere in the terminal to see its help options.\n")
		
	def sublist3r():
		os.system("pip install sublist3r")
		os.system("clear")
		print(Fore.GREEN + "You can run the command wafw00f -h from anywhere in the terminal to see its help options.\n")
		
	def urlscan():
		os.system("pip install urlscan")
		os.system("clear")
		print(Fore.GREEN + "You can run the command urlscan -h from anywhere in the terminal to see its help options.\n")
	
	def httpx():
		os.system("pip install httpx")
		os.system("pip install httpx")
		os.system("clear")
		print(Fore.GREEN + "You can run the command httpx -h from anywhere in the terminal to see its help options.\n")
		
	def arjun():
		os.system("pip install arjun")
		os.system("clear")
		print(Fore.GREEN + "You can run the command arjun -h from anywhere in the terminal to see its help options.\n")
		
	def xsstrike():
		os.system("pip install xsstrike")
		os.system("clear")
		print(Fore.GREEN + "You can run the command xsstrike -h from anywhere in the terminal to see its help options.\n")
	
	is_running = True
	while is_running:
		print(Fore.GREEN + "1. Nmap")
		print(Fore.GREEN + "2. Whatweb")
		print(Fore.GREEN + "3. Shodan")
		print(Fore.GREEN + "4. Wafw00f")
		print(Fore.GREEN + "5. Sublist3r")
		print(Fore.GREEN + "6. Urlscan")
		print(Fore.GREEN + "7. Httpx")
		print(Fore.GREEN + "8. Arjun")
		print(Fore.GREEN + "9. Xsstrike")
		print(Fore.GREEN + "10. Exit")
		
		user_input = input("==>>>")
		
		if user_input == "1":
			nmap()
		elif user_input == "2":
		   	whatweb()
		elif user_input == "3":
		   	shodan()
		elif user_input == "4":
		   	wafw00f()
		elif user_input == "5":
		   	sublist3r()
		elif user_input == "6":
		   	urlscan()
		elif user_input == "7":
		   	httpx()
		elif user_input == "8":
		   	arjun()
		elif user_input == "9":
		   	xsstrike()
		elif user_input == "10":
		   	is_running = False
		else:
		   	print(Fore.RED + "Invalid choice!")
		   	
	    	
	   

def vulnerability_scanning():
	banner()
	def nmap():
		os.system("apt install nmap")
		os.system("sudo apt install nmap")
		os.system("clear")
		print(Fore.GREEN + "You can run the command nmap -h from anywhere in the terminal to see its help options.\n")
		
	def wapiti():
		os.system("pip install wapiti3")
		os.system("clear")
		print(Fore.GREEN + "You can run the command wapiti -h from anywhere in the terminal to see its help options.\n")
		
	def dnstwist():
		os.system("pip install dnstwist")
		os.system("clear")
		print(Fore.GREEN + "You can run the command dnstwist -h from anywhere in the terminal to see its help options.\n")
	
	def urlscan():
		os.system("pip install urlscan")
		os.system("clear")
		print(Fore.GREEN + "You can run the command  urlscan -h from anywhere in the terminal to see its help options.\n")
	
	def nikto():
		os.system("sudo apt install nikto")
		os.system("clear")
		print(Fore.GREEN + "You can run the command  nikto -h from anywhere in the terminal to see its help options.\n")
	
	is_running = True
	while is_running:
		print(Fore.GREEN + "1. Nmap")
		print(Fore.GREEN + "2. Wapiti3")
		print(Fore.GREEN + "3. Dnstwist")
		print(Fore.GREEN + "4. Urlscan")
		print(Fore.GREEN + "5. Nikto")
		print(Fore.GREEN + "6. Exit")
		
		user_input = input("==>>>")
		
		if user_input == "1":
			nmap()
		elif user_input == "2":
			wapiti()
		elif user_input == "3":
			dnstwist()
		elif user_input == "4":
			urlscan()
		elif user_input == "5":
			nikto()
		elif user_input == "6":
			is_running = False
		else:
			print(Fore.RED + "Invalid option!")
	
def exploitation_tools():
	banner()
	def sqlmap():
		os.system("pip install sqlmap")
		os.system("clear")
		print(Fore.GREEN + "You can run the command sqlmap -h from anywhere in the terminal to see its help options.\n")
		
	def metasploit():
		os.system("sudo apt install metasploit-framework")
		os.system("clear")
		print(Fore.GREEN + "You can run the command msfconsole from anywhere in the terminal to see its help options.\n")
	
	def routersploit():
		os.system("pip install routersploit")
		os.system("clear")
		print(Fore.GREEN + "You can run the command routersploit -h from anywhere in the terminal to see its help options.\n")
	
	is_running = True
	while is_running:
		print(Fore.GREEN + "1. Sqlmap")
		print(Fore.GREEN + "2. Metasploit")
		print(Fore.GREEN + "3. Routersploit")
		print(Fore.GREEN + "4. Exit")
		
		user_input = input("==>>>")
		
		if user_input == "1":
			sqlmap()
		elif user_input == "2":
			metasploit()
		elif user_input == "3":
			routersploit()
		elif user_input == "4":
			is_running = False
		else:
			print(Fore.RED + "Invalid option")
		

def password_attack():
	banner()
	def online():
		banner()
		def hydra():
			os.system("sudo apt install hydra")
			os.system("clear")
			print(Fore.GREEN + "You can run the command hydra -h from anywhere in the terminal to see its help options.\n")
		
		def medusa():
			os.system("sudo apt install medusa")
			os.system("clear")
			print(Fore.GREEN + "You can run the command medusa -h from anywhere in the terminal to see its help options.\n")
		
		def patator():
			os.system("sudo apt install patator")
			os.system("clear")
			print(Fore.GREEN + "You can run the command patator -h from anywhere in the terminal to see its help options.\n")
		
		def ncrack():
			os.system("sudo apt install ncrack")
			os.system("clear")
			print(Fore.GREEN + "You can run the command ncrack -h from anywhere in the terminal to see its help options.\n")
		
		def brutespray():
			os.system("sudo apt install brutespray")
			os.system("clear")
			print(Fore.GREEN + "You can run the command brutespray -h from anywhere in the terminal to see its help options.\n")
		
		def crunch():
			os.system("sudo apt install crunch")
			os.system("clear")
			print(Fore.GREEN + "You can run the command crunch -h from anywhere in the terminal to see its help options.\n")
		
		Tool_menu = True
		while Tool_menu:
			print(Fore.GREEN + "1. Hydra")
			print(Fore.GREEN + "2. Medusa")
			print(Fore.GREEN + "3. Patator")
			print(Fore.GREEN + "4. Ncrack")
			print(Fore.GREEN + "5. Brutespray")
			print(Fore.GREEN + "6. Crunch")
			print(Fore.GREEN + "7. Exit")
			
			user_input = input("==>>>")
			
			if user_input == "1":
				hydra()
			elif user_input == "2":
				medusa()
			elif user_input == "3":
				patator()
			elif user_input == "4":
				ncrack()
			elif user_input == "5":
				brutespray()
			elif user_input == "6":
				crunch()
			elif user_input == "7":
				Tool_menu = False
			else:
				print(Fore.RED + "Invalid option")
	
	def offline():
		banner()
		def hashcat():
			os.system("sudo apt install hashcat")
			os.system("clear")
			print(Fore.GREEN + "You can run the command hashcat -h from anywhere in the terminal to see its help options.\n")
		
		def john():
			os.system("sudo apt install john")
			os.system("clear")
			print(Fore.GREEN + "You can run the command john -h from anywhere in the terminal to see its help options.\n")
		
		def ophcrack():
			os.system("sudo apt install ophcrack")
			os.system("clear")
			print(Fore.GREEN + "You can run the command john -h from anywhere in the terminal to see its help options.\n")
		
		def rarcrack():
			os.system("sudo apt install rarcrack")
			os.system("clear")
			print(Fore.GREEN + "You can run the command rarcrack --help from anywhere in the terminal to see its help options.\n")
		
		def fcrackzip():
			os.system("sudo apt install fcrackzip")
			os.system("clear")
			print(Fore.GREEN + "You can run the command fcrackzip -h from anywhere in the terminal to see its help options.\n")
		
		def crunch():
			os.system("sudo apt install crunch")
			os.system("clear")
			print(Fore.GREEN + "You can run the command crunch -h from anywhere in the terminal to see its help options.\n")
		
		tool_menu = True
		while tool_menu:
			print(Fore.GREEN + "1. Hashcat")
			print(Fore.GREEN + "2. John_the_ripper")
			print(Fore.GREEN + "3. Ophcrack")
			print(Fore.GREEN + "4. RarCrack")
			print(Fore.GREEN + "5. Fcrackzip")
			print(Fore.GREEN + "6. Crunch")
			print(Fore.GREEN + "7. Exit")
			
			user_input = input("==>>>")
			
			if user_input == "1":
				hashcat()
			elif user_input == "2":
				john()
			elif user_input == "3":
				ophcrack()
			elif user_input == "4":
				rarcrack()
			elif user_input == "5":
				fcrackzip()
			elif user_input == "6":
				crunch()
			elif user_input == "7":
				tool_menu = False
			else:
				print(Fore.RED + "Invalid option")
	
	menu = True
	while menu:
		print(Fore.GREEN + "1. Online")
		print(Fore.GREEN + "2. Offline")
		print(Fore.GREEN + "3. Exit")
		
		user_input = input("==>>>")
		
		if user_input == "1":
		   	online()
		elif user_input == "2":
		   	offline()
		elif user_input == "3":
		   	menu = False
		else:
		   	print(Fore.RED + "Invalid option")
		   		

def wireless_attacks():
	banner()
	def aircrack():
		os.system("sudo apt install aircrack-ng")
		os.system("clear")
		print(Fore.GREEN + "You can run the command aircrack-ng --help from anywhere in the terminal to see its help options.\n")
		
	def wifite():
		os.system("sudo apt install wifite")
		os.system("clear")
		print(Fore.GREEN + "You can run the command wifite --help from anywhere in the terminal to see its help options.\n")
		
	def reaver():
		os.system("sudo apt install reaver")
		os.system("clear")
		print(Fore.GREEN + "You can run the command reaver --help from anywhere in the terminal to see its help options.\n")
	
	def pixiewps():
		os.system("sudo apt install pixiewps")
		os.system("clear")
		print(Fore.GREEN + "You can run the command pixiewps --help from anywhere in the terminal to see its help options.\n")
		
	def bettercap():
		os.system("sudo apt install bettercap")
		os.system("clear")
		print(Fore.GREEN + "You can run the command bettercap --help from anywhere in the terminal to see its help options.\n")
	
	def kismet():
		os.system("sudo apt install kismet")
		os.system("clear")
		print(Fore.GREEN + "You can run the command kismet --help from anywhere in the terminal to see its help options.\n")
	
	def hostapd():
		os.system("sudo apt install hostapd-wpe")
		os.system("clear")
		print(Fore.GREEN + "You can run the command hostapd-wpe --help from anywhere in the terminal to see its help options.\n")
	
	def mdk4():
		os.system("sudo apt install mdk4")
		os.system("clear")
		print(Fore.GREEN + "You can run the command mdk4 --help from anywhere in the terminal to see its help options.\n")
	
	def cowpatty():
		os.system("sudo apt install cowpatty")
		os.system("clear")
		print(Fore.GREEN + "You can run the command cowpatty --help from anywhere in the terminal to see its help options.\n")
	
	def fern_wifi_cracker():
		os.system("sudo apt install fern-wifi-cracker")
		os.system("clear")
		print(Fore.GREEN + "You can run the command fern-wifi-cracker --help from anywhere in the terminal to see its help options.\n")
	
	def scapy():
		os.system("pip install scapy")
		os.system("clear")
		print(Fore.GREEN + "You can run the command scapy --help from anywhere in the terminal to see its help options.\n")
	
	def wifi_honey():
		os.system("pip install wifi-honey")
		os.system("clear")
		print(Fore.GREEN + "You can run the command wifi-honey --help from anywhere in the terminal to see its help options.\n")
		
	Tool_menu = True
	while Tool_menu:
		print(Fore.GREEN + "1. Aircrack-ng")
		print(Fore.GREEN + "2. Wifite")
		print(Fore.GREEN + "3. Reaver")
		print(Fore.GREEN + "4. Pixiewps")
		print(Fore.GREEN + "5. Bettercap")
		print(Fore.GREEN + "6. Kismet")
		print(Fore.GREEN + "7. Hostapd")
		print(Fore.GREEN + "8. Mdk4")
		print(Fore.GREEN + "9. Cowpatty")
		print(Fore.GREEN + "10. Fern_wifi_cracker")
		print(Fore.GREEN + "11. Scapy")
		print("12. Exit")
		
		user_input = input("==>>>")
		
		if user_input == "1":
			aircrack()
		elif user_input == "2":
			wifite()
		elif user_input == "3":
			reaver()
		elif user_input == "4":
			pixiewps()
		elif user_input == "5":
			bettercap()
		elif user_input == "6":
			kismet()
		elif user_input == "7":
			hostapd()
		elif user_input == "8":
			mdk4()
		elif user_input == "9":
		   	cowpatty()
		elif user_input == "10":
		   	fern_wifi_cracker()
		elif user_input == "11":
		   	scapy()
		elif user_input == "12":
		   	Tool_menu = False
		else:
		   	print(Fore.RED + "Invalid choice!")
	    	
		
		

def sniffing_and_spoofing_mitm():
	banner()
	def wireshark():
		os.system("sudo apt install wireshark")
		os.system("clear")
		print(Fore.GREEN + "You can run the command wireshark --help from anywhere in the terminal to see its help options.\n")
	
	def tshark():
		os.system("sudo apt install tshark")
		os.system("clear")
		print(Fore.GREEN + "You can run the command tshark --help from anywhere in the terminal to see its help options.\n")
		
	def ettercap():
		os.system("sudo apt install ettercap-graphical")
		os.system("clear")
		print(Fore.GREEN + "You can run the command ettercap --help from anywhere in the terminal to see its help options.\n")
	
	def bettercap():
		os.system("sudo apt install bettercap")
		os.system("clear")
		print(Fore.GREEN + "You can run the command bettercap --help from anywhere in the terminal to see its help options.\n")
	
	def dsniff():
		os.system("sudo apt install dsniff")
		os.system("clear")
		print(Fore.GREEN + "You can run the command dsniff --help from anywhere in the terminal to see its help options.\n")
	
	def mitmf():
		os.system("sudo apt install mitmf")
		os.system("clear")
		print(Fore.GREEN + "You can run the command mitmf --help from anywhere in the terminal to see its help options.\n")
	
	def responder():
		os.system("sudo apt install responder")
		os.system("clear")
		print(Fore.GREEN + "You can run the command responder --help from anywhere in the terminal to see its help options.\n")
	
	def nmap():
		os.system("sudo apt install nmap")
		os.system("clear")
		print(Fore.GREEN + "You can run the command nmap --help from anywhere in the terminal to see its help options.\n")
	
	def scapy():
		os.system("pip install scapy")
		os.system("clear")
		print(Fore.GREEN + "You can run the command scapy --help from anywhere in the terminal to see its help options.\n")
	
	def pypcap():
		os.system("pip install pypcap")
		os.system("clear")
		print(Fore.GREEN + "You can run the command pypcap --help from anywhere in the terminal to see its help options.\n")
	
	def mitmproxy():
		os.system("pip install mitmproxy")
		os.system("clear")
		print(Fore.GREEN + "You can run the command mitmproxy --help from anywhere in the terminal to see its help options.\n")
	
	def faker():
		os.system("pip install faker")
		os.system("clear")
		print(Fore.GREEN + "You can run the command faker --help from anywhere in the terminal to see its help options.\n")
	
	Tool_menu = True
	while Tool_menu:
		print(Fore.GREEN + "1 Wireshark")
		print(Fore.GREEN + "2. Tshark")
		print(Fore.GREEN + "3. Ettercap")
		print(Fore.GREEN + "4. Bettercap")
		print(Fore.GREEN + "5. Dsniff")
		print(Fore.GREEN + "6. Mitmf")
		print(Fore.GREEN + "7. Responder")
		print(Fore.GREEN + "8. Nmap")
		print(Fore.GREEN + "9. Scapy")
		print(Fore.GREEN + "10. Pypcap")
		print(Fore.GREEN + "11. Mitmproxy")
		print(Fore.GREEN + "12. Faker")
		print(Fore.GREEN + "13. Exit")
		
		user_input = input("==>>>")
		
		if user_input == "1":
			wireshark()
		elif user_input == "2":
			tshark()
		elif user_input == "3":
			ettercap()
		elif user_input == "4":
			bettercap()
		elif user_input == "5":
			dsniff()
		elif user_input == "6":
			mitmf()
		elif user_input == "7":
			responder()
		elif user_input == "8":
			nmap()
		elif user_input == "9":
			scapy()
		elif user_input == "10":
			pypcap()
		elif user_input == "11":
			mitmproxy()
		elif user_input == "12":
				faker()
		elif user_input == "13":
				Tool_menu = False
		else:
				print(Fore.GREEN + "Invalid choice")
				
				
		
def web_application_attack():
	banner()
	def zapproxy():
		os.system("sudo apt install zaproxy")
		os.system("clear")
		print(Fore.GREEN + "You can run the command zapproxy --help from anywhere in the terminal to see its help options.\n")
	
	def nikto():
		os.system("sudo apt install nikto")
		os.system("clear")
		print(Fore.GREEN + "You can run the command nikto --help from anywhere in the terminal to see its help options.\n")
	
	def wfuzz():
		os.system("sudo apt install wfuzz")
		os.system("clear")
		print(Fore.GREEN + "You can run the command wfuzz --help from anywhere in the terminal to see its help options.\n")
	
	def skipfish():
		os.system("sudo apt install skipfish")
		os.system("clear")
		print(Fore.GREEN + "You can run the command skipfish --help from anywhere in the terminal to see its help options.\n")
		
	def burpsuite():
		os.system("sudo apt install burpsuite")
		os.system("clear")
		print(Fore.GREEN + "You can run the command burpsuite --help from anywhere in the terminal to see its help options.\n")
	
	def whatweb():
		os.system("sudo apt install whatweb")
		os.system("clear")
		print(Fore.GREEN + "You can run the command whatweb --help from anywhere in the terminal to see its help options.\n")
	
	def dirb():
		os.system("sudo apt install dirb")
		os.system("clear")
		print(Fore.GREEN + "You can run the command dirb --help from anywhere in the terminal to see its help options.\n")
	
	def gobuster():
		os.system("sudo apt install gobuster")
		os.system("clear")
		print(Fore.GREEN + "You can run the command gobuster --help from anywhere in the terminal to see its help options.\n")
		
	def hydra():
		os.system("sudo apt install hydra")
		os.system("clear")
		print(Fore.GREEN + "You can run the command hydra --help from anywhere in the terminal to see its help options.\n")
	
	def sqlmap():
		os.system("sudo apt install sqlmap")
		os.system("clear")
		print(Fore.GREEN + "You can run the command sqlmap --help from anywhere in the terminal to see its help options.\n")
	
	def arjun():
		os.system("sudo apt install arjun")
		os.system("clear")
		print(Fore.GREEN + "You can run the command arjun --help from anywhere in the terminal to see its help options.\n")
	
	tool_menu = True
	while tool_menu:
		print(Fore.GREEN + "1. Zapproxy")
		print(Fore.GREEN + "2. Nikto")
		print(Fore.GREEN + "3. Wfuzz")
		print(Fore.GREEN + "4. Skipfish")
		print(Fore.GREEN + "5. Burpsuite")
		print(Fore.GREEN + "6. Whatweb")
		print(Fore.GREEN + "7. Dirb")
		print(Fore.GREEN + "8. Gobuster")
		print(Fore.GREEN + "9. Hydra")
		print(Fore.GREEN + "10. Sqlmap")
		print(Fore.GREEN + "11. Arjun")
		print(Fore.GREEN + "12. Exit")
		
		user_input = input("==>>>")
		
		if user_input == "1":
			zapproxy()
		elif user_input == "2":
			nikto()
		elif user_input == "3":
			wfuzz()
		elif user_input == "4":
			skipfish()
		elif user_input == "5":
			burpsuite()
		elif user_input == "6":
			whatweb()
		elif user_input == "7":
			dirb()
		elif user_input == "8":
			gobuster()
		elif user_input == "9":
			hydra()
		elif user_input == "10":
			sqlmap()
		elif user_input == "11":
			arjun()
		elif user_input == "12":
			tool_menu = False
		else:
			print(Fore.RED + "Invalid choice!")		


def forensics_steganography():
	banner()
	def binwalk():
		os.system("sudo apt install binwalk")
		os.system("clear")
		print(Fore.GREEN + "You can run the command binwalk --help from anywhere in the terminal to see its help options.\n")
	
	def exiftool():
		os.system("sudo apt install exiftool")
		os.system("clear")
		print(Fore.GREEN + "You can run the command exiftool --help from anywhere in the terminal to see its help options.\n")
	
	def foremost():
		os.system("sudo apt install foremost")
		os.system("clear")
		print(Fore.GREEN + "You can run the command foremost --help from anywhere in the terminal to see its help options.\n")
	
	def scalpel():
		os.system("sudo apt install scalpel")
		os.system("clear")
		print(Fore.GREEN + "You can run the command scalpel --help from anywhere in the terminal to see its help options.\n")
	
	def steghide():
		os.system("sudo apt install steghide")
		os.system("clear")
		print(Fore.GREEN + "You can run the command steghide --help from anywhere in the terminal to see its help options.\n")
	
	def zsteg():
		os.system("sudo apt install zsteg")
		os.system("clear")
		print(Fore.GREEN + "You can run the command zsteg --help from anywhere in the terminal to see its help options.\n")
	
	def binutils():
		os.system("sudo apt install binutils")
		os.system("clear")
		print(Fore.GREEN + "You can run the command binutils --help from anywhere in the terminal to see its help options.\n")
	
	def volatility():
		os.system("sudo apt install volatility")
		os.system("clear")
		print(Fore.GREEN + "You can run the command volatility --help from anywhere in the terminal to see its help options.\n")
	
	def sleuthkit():
		os.system("sudo apt install autopsy sleuthkit")
		os.system("clear")
		print(Fore.GREEN + "You can run the command sleuthkit --help from anywhere in the terminal to see its help options.\n")
	
	def stepic():
		os.system("pip install stepic")
		os.system("clear")
		print(Fore.GREEN + "You can run the command stepic --help from anywhere in the terminal to see its help options.\n")
	
	def stegano():
		os.system("pip install stegano")
		os.system("clear")
		print(Fore.GREEN + "You can run the command stegano --help from anywhere in the terminal to see its help options.\n")
	
	def pyexiftool():
		os.system("pip install pyexiftool")
		os.system("clear")
		print(Fore.GREEN + "You can run the command pyexiftool --help from anywhere in the terminal to see its help options.\n")
	
	tool_menu = True
	while tool_menu:
		print(Fore.GREEN + "1. Binwalk")
		print(Fore.GREEN + "2. Exiftool")
		print(Fore.GREEN + "3. Foremost")
		print(Fore.GREEN + "4. Scalpel")
		print(Fore.GREEN + "5. Steghide")
		print(Fore.GREEN + "6. Zsteg")
		print(Fore.GREEN + "7. Binutils")
		print(Fore.GREEN + "8. Volatility")
		print(Fore.GREEN + "9. Sleuthkit")
		print(Fore.GREEN + "10. Stepic")
		print(Fore.GREEN + "11. Stegano")
		print(Fore.GREEN + "12. Pyexiftool")
		print(Fore.GREEN + "13. Exit")
		
		user_input = input("==>>>")
		
		if user_input == "1":
			binwalk()
		elif user_input == "2":
			exiftool()
		elif user_input == "3":
			foremost()
		elif user_input == "4":
			scalpel()
		elif user_input == "5":
			steghide()
		elif user_input == "6":
			zsteg()
		elif user_input == "7":
			binutils()
		elif user_input == "8":
			volatility()
		elif user_input == "9":
			sleuthkit()
		elif user_input == "10":
			stepic()
		elif user_input == "11":
			stegano()
		elif user_input == "12":
			pyexiftool()
		elif user_input == "13":
			tool_menu = False
		else:
			print(Fore.RED + "Invalid choice!")
	
def malware_analysis():
	banner()
	def radare2():
		os.system("sudo apt install radare2")
		os.system("clear")
		print(Fore.GREEN + "You can run the command radare2 --help from anywhere in the terminal to see its help options.\n")
	
	def cutter():
		os.system("sudo snap install cutter --classic")
		os.system("clear")
		print(Fore.GREEN + "You can run the command cutter --help from anywhere in the terminal to see its help options.\n")
	
	def gdb():
		os.system("sudo apt install gdb")
		os.system("clear")
		print(Fore.GREEN + "You can run the command gdb --help from anywhere in the terminal to see its help options.\n")
	
	def apktool():
		os.system("sudo apt install apktool")
		os.system("clear")
		print(Fore.GREEN + "You can run the command apktool --help from anywhere in the terminal to see its help options.\n")
	
	def dex2jar():
		os.system("sudo apt install dex2jar")
		os.system("clear")
		print(Fore.GREEN + "You can run the command dex2jar --help from anywhere in the terminal to see its help options.\n")
	
	def peframe():
		os.system("sudo apt install peframe")
		os.system("clear")
		print(Fore.GREEN + "You can run the command peframe --help from anywhere in the terminal to see its help options.\n")
	
	def clamav():
		os.system("sudo apt install clamav")
		os.system("clear")
		print(Fore.GREEN + "You can run the command clamav --help from anywhere in the terminal to see its help options.\n")
	
	def yara():
		os.system("sudo apt install yara")
		os.system("clear")
		print(Fore.GREEN + "You can run the command yara --help from anywhere in the terminal to see its help options.\n")
	
	def malwoverview():
		os.system("pip install malwoverview")
		os.system("clear")
		print(Fore.GREEN + "You can run the command malwoverview --help from anywhere in the terminal to see its help options.\n")
	
	def volatility():
		os.system("sudo apt install volatility")
		os.system("clear")
		print(Fore.GREEN + "You can run the command volatility --help from anywhere in the terminal to see its help options.\n")
	
	def oletools():
		os.system("pip install oletools")
		os.system("clear")
		print(Fore.GREEN + "You can run the command oletools --help from anywhere in the terminal to see its help options.\n")
	
	Tool_menu = True
	while Tool_menu:
		print(Fore.GREEN + "1. Radare2")
		print(Fore.GREEN + "2. Cutter")
		print(Fore.GREEN + "3. Gdb")
		print(Fore.GREEN + "4. Apktool")
		print(Fore.GREEN + "5. Dex2jar")
		print(Fore.GREEN + "6. Peframe")
		print(Fore.GREEN + "7. Clamav")
		print(Fore.GREEN + "8. Yara")
		print(Fore.GREEN + "9. malwoverview")
		print(Fore.GREEN + "10. Volatility")
		print(Fore.GREEN + "11. Oletools")
		print(Fore.GREEN + "12. Exit")
		
		user_input = input("==>>>")
		
		if user_input == "1":
			radare2()
		elif user_input == "2":
			cutter()
		elif user_input == "3":
			gdb()
		elif user_input == "4":
			apktool()
		elif user_input == "5":
			dex2jar()
		elif user_input == "6":
			peframe()
		elif user_input == "7":
			clamav()
		elif user_input == "8":
			yara()
		elif user_input == "9":
			malwoverview()
		elif user_input == "10":
			volatility()
		elif user_input == "11":
			oletools()
		elif user_input == "12":
			Tool_menu = False
		else:
			print(Fore.RED + "Invalid choice!")				
	
def recon_and_osint_tools():
	banner()
	def nmap():
		os.system("sudo apt install nmap")
		os.system("clear")
		print(Fore.GREEN + "You can run the command nmap --help from anywhere in the terminal to see its help options.\n")
	
	def whatweb():
		os.system("sudo apt install whatweb")
		os.system("clear")
		print(Fore.GREEN + "You can run the command whatweb --help from anywhere in the terminal to see its help options.\n")
	
	def theharvester():
		os.system("sudo apt install theharvester")
		os.system("clear")
		print(Fore.GREEN + "You can run the command theharvester --help from anywhere in the terminal to see its help options.\n")
	
	def dnsenum():
		os.system("sudo apt install dnsenum")
		os.system("clear")
		print(Fore.GREEN + "You can run the command dnsenum --help from anywhere in the terminal to see its help options.\n")
	
	def dnsrecon():
		os.system("sudo apt install dnsrecon")
		os.system("clear")
		print(Fore.GREEN + "You can run the command dnsrecon --help from anywhere in the terminal to see its help options.\n")
	
	def maltego():
		os.system("sudo apt install maltego")
		os.system("clear")
		print(Fore.GREEN + "You can run the command maltego  --help from anywhere in the terminal to see its help options.\n")
	
	def recon_ng():
		os.system("sudo apt install recon-ng")
		os.system("clear")
		print(Fore.GREEN + "You can run the command recon-ng  --help from anywhere in the terminal to see its help options.\n")
	
	def amass():
		os.system("sudo apt install amass")
		os.system("clear")
		print(Fore.GREEN + "You can run the command amass  --help from anywhere in the terminal to see its help options.\n")
	
	def sublist3r():
		os.system("sudo apt install sublist3r")
		os.system("clear")
		print(Fore.GREEN + "You can run the command sublist3r  --help from anywhere in the terminal to see its help options.\n")
	
	def wafw00f():
		os.system("sudo apt install wafw00f")
		os.system("clear")
		print(Fore.GREEN + "You can run the command wafw00f  --help from anywhere in the terminal to see its help options.\n")
	
	def spiderfoot():
		os.system("sudo apt install spiderfoot")
		os.system("clear")
		print(Fore.GREEN + "You can run the command spiderfoot  --help from anywhere in the terminal to see its help options.\n")
	
	Tool_menu = True 
	while Tool_menu:
		print(Fore.GREEN + "1. Nmap")
		print(Fore.GREEN + "2. Whatweb")
		print(Fore.GREEN + "3. Theharvester")
		print(Fore.GREEN + "4. Dnsenum")
		print(Fore.GREEN + "5. Dnsrecon")
		print(Fore.GREEN + "6. Maltego")
		print(Fore.GREEN + "7. Recon-ng")
		print(Fore.GREEN + "8. Amass")
		print(Fore.GREEN + "9. Sublist3r")
		print(Fore.GREEN + "10. Wafw00f")
		print(Fore.GREEN + "11. Spiderfoot")
		print(Fore.GREEN + "12. Exit")
		
		user_input = input("==>>>")
		
		if user_input == "1":
			nmap()
		elif user_input == "2":
			whatweb()
		elif user_input == "3":
			theharvester()
		elif user_input == "4":
			dnsenum()
		elif user_input == "5":
			dnsrecon()
		elif user_input == "6":
			maltego()
		elif user_input == "7":
			recon_ng()
		elif user_input == "8":
			amass()
		elif user_input == "9":
			sublist3r()
		elif user_input == "10":
			wafw00f()
		elif user_input == "11":
			spiderfoot()
		elif user_input == "12":
			Tool_menu = False
		else:
			print(Fore.GREEN + "Invalid choice")
	

def subdomain_enumeration():
	banner()
	def sublist3r():
		os.system("sudo apt install sublist3r")
		os.system("clear")
		print(Fore.GREEN + "You can run the command sublist3r  --help from anywhere in the terminal to see its help options.\n")
	
	def amass():
		os.system("sudo apt install amass")
		os.system("clear")
		print(Fore.GREEN + "You can run the command sublist3r  --help from anywhere in the terminal to see its help options.\n")
	
	def knockpy():
		os.system("sudo apt install knockpy")
		os.system("clear")
		print(Fore.GREEN + "You can run the command knockpy  --help from anywhere in the terminal to see its help options.\n")
	
	def subfinder():
		os.system("sudo apt install subfinder")
		os.system("clear")
		print(Fore.GREEN + "You can run the command subfinder  --help from anywhere in the terminal to see its help options.\n")
	
	def assetfinder():
		os.system("sudo apt install assetfinder")
		os.system("clear")
		print(Fore.GREEN + "You can run the command assetfinder  --help from anywhere in the terminal to see its help options.\n")
	
	Tool_menu = True
	while Tool_menu:
		print(Fore.GREEN + "1. Sublist3r")
		print(Fore.GREEN + "2. Amass")
		print(Fore.GREEN + "3. Knockpy")
		print(Fore.GREEN + "4. Subfinder")
		print(Fore.GREEN + "5. Assetfinder")
		print(Fore.GREEN + "6. Exit")
		
		user_input = input("==>>>")
		
		if user_input == "1":
			sublist3r()
		elif user_input == "2":
			amass()
		elif user_input == "3":
			knockpy()
		elif user_input == "4":
			subfinder()
		elif user_input == "5":
			assetfinder()
		elif user_input == "6":
			Tool_menu = False
		else:
			print(Fore.RED + "Invalid choice")

def phishing_tools():
	banner()
	def set():
		os.system("sudo apt install set")
		os.system("clear")
		print(Fore.GREEN + "You can run the command setoolkit --help from anywhere in the terminal to see its help options.\n")
	
	def hiddeneye():
		os.system("pip install hiddeneye")
		os.system("clear")
		print(Fore.GREEN + "You can run the command hiddeneye --help from anywhere in the terminal to see its help options.\n")
		
	def zphisher():
		os.system("pip install zphisher")
		os.system("clear")
		print(Fore.GREEN + "You can run the command zphisher --help from anywhere in the terminal to see its help options.\n")
	
	def blackeye():
		os.system("pip install blackeye")
		os.system("clear")
		print(Fore.GREEN + "You can run the command blackeye --help from anywhere in the terminal to see its help options.\n")
	
	def shellphish():
		os.system("pip install shellphish")
		os.system("clear")
		print(Fore.GREEN + "You can run the command shellphish --help from anywhere in the terminal to see its help options.\n")
	
	Tool_menu = True
	while Tool_menu:
		print(Fore.GREEN + "1. Setoolkit")
		print(Fore.GREEN + "2. Hiddeneye")
		print(Fore.GREEN + "3. Zphisher")
		print(Fore.GREEN + "4. Blackeye")
		print(Fore.GREEN + "5. Shellphish")
		print(Fore.GREEN + "6. Exit")
		
		user_input = input("==>>>")
		
		if user_input == "1":
			set()
		elif user_input == "2":
			hiddeneye()
		elif user_input == "3":
			zphisher()
		elif user_input == "4":
			blackeye()
		elif user_input == "5":
			shellphish()
		elif user_input == "6":
			Tool_menu = False
		else:
			print(Fore.RED + "Invalid choice")
	
def backdoor():
	def metasploit():
		banner()
		os.system("sudo apt install metasploit-framewor")
		os.system("clear")
		print(Fore.GREEN + "You can run the command msfconsole from anywhere in the terminal to see its help options.\n")
		
	def netcat():
		os.system("sudo apt install netcat")
		os.system("clear")
		print(Fore.GREEN + "You can run the command netcat --help from anywhere in the terminal to see its help options.\n")
	
	def socat():
		os.system("sudo apt install socat")
		os.system("clear")
		print(Fore.GREEN + "You can run the command socat --help from anywhere in the terminal to see its help options.\n")
	
	def powershell():
		os.system("sudo apt install powershell-empire")
		os.system("clear")
		print(Fore.GREEN + "You can run the command powershell --help from anywhere in the terminal to see its help options.\n")
	
	def weevely():
		os.system("sudo apt install weevely")
		os.system("clear")
		print(Fore.GREEN + "You can run the command weevely --help from anywhere in the terminal to see its help options.\n")
	
	def cryptcat():
		os.system("sudo apt install cryptcat")
		os.system("clear")
		print(Fore.GREEN + "You can run the command cryptcat --help from anywhere in the terminal to see its help options.\n")
	
	Tool_menu = True
	while Tool_menu:
		print(Fore.GREEN + "1. Metasploit")
		print(Fore.GREEN + "2. Netcat")
		print(Fore.GREEN + "3. Socat")
		print(Fore.GREEN + "4. Powershell-Empire")
		print(Fore.GREEN + "5. Weevely")
		print(Fore.GREEN + "6. Cryptcat")
		print(Fore.GREEN + "7. Exit")
		
		user_input = input("==>>>")
		
		if user_input == "1":
			metasploit()
		elif user_input == "2":
			netcat()
		elif user_input == "3":
			socat()
		elif user_input == "4":
			powershell()
		elif user_input == "5":
			weevely()
		elif user_input == "6":
			cryptcat()
		elif user_input == "7":
			Tool_menu = False
		else:
			print(Fore.GREEN + "Invalid choice")
			
	
def api_security_testing():
	banner()
	def zapproxy():
		os.system("sudo apt install zapproxy")
		os.system("clear")
		print(Fore.GREEN + "You can run the command zapproxy --help from anywhere in the terminal to see its help options.\n")
	
	def burpsuite():
		os.system("sudo apt install burpsuite")
		os.system("clear")
		print(Fore.GREEN + "You can run the command burpsuite --help from anywhere in the terminal to see its help options.\n")
	
	def mitmproxy():
		os.system("sudo apt install mitmproxy")
		os.system("clear")
		print(Fore.GREEN + "You can run the command mitmproxy --help from anywhere in the terminal to see its help options.\n")
	
	def crapi():
		os.system("pip install crapi")
		os.system("clear")
		print(Fore.GREEN + "You can run the command crapi --help from anywhere in the terminal to see its help options.\n")
	
	def arjun():
		os.system("pip install arjun")
		os.system("clear")
		print(Fore.GREEN + "You can run the command arjun --help from anywhere in the terminal to see its help options.\n")
		
	Tool_menu = True
	while Tool_menu:
		print(Fore.GREEN + "1. Zapproxy")
		print(Fore.GREEN + "2. Burpsuite")
		print(Fore.GREEN + "3. mitmproxy")
		print(Fore.GREEN + "4. Crapi")
		print(Fore.GREEN + "5. Arjun")
		print(Fore.GREEN + "6. Exit")
		
		user_input = input("==>>>")
		
		if user_input == "1":
			zapproxy()
		elif user_input == "2":
			burpsuite()
		elif user_input == "3":
			mitmproxy()
		elif user_input == "4":
			crapi()
		elif user_input == "5":
			arjun()
		elif user_input == "6":
			Tool_menu = False
		else:
			print(Fore.GREEN + "Invalid choice")
		

def hash_cracking():
	banner()
	def hashcat():
		os.system("sudo apt install hashcat")
		os.system("clear")
		print(Fore.GREEN + "You can run the command hashcat --help from anywhere in the terminal to see its help options.\n")
	
	def john():
		os.system("sudo apt install John")
		os.system("clear")
		print(Fore.GREEN + "You can run the command john --help from anywhere in the terminal to see its help options.\n")
	
	def rainbowcrack():
		os.system("sudo apt install rainbowcrack")
		os.system("clear")
		print(Fore.GREEN + "You can run the command rainbowcrack --help from anywhere in the terminal to see its help options.\n")
	
	def hashid():
		os.system("pip install hashid")
		os.system("clear")
		print(Fore.GREEN + "You can run the command hashid --help from anywhere in the terminal to see its help options.\n")
	
	def passlib():
		os.system("pip install passlib")
		os.system("clear")
		print(Fore.GREEN + "You can run the command passlib --help from anywhere in the terminal to see its help options.\n")
	
	Tool_menu = True
	while Tool_menu:
		print(Fore.GREEN + "1. Hashcat")
		print(Fore.GREEN + "2. John")
		print(Fore.GREEN + "3. rainbowcrack")
		print(Fore.GREEN + "4. Hashid")
		print(Fore.GREEN + "5. passlib")
		print(Fore.GREEN + "6. Exit")
		
		user_input = input("==>>>")
		
		if user_input == "1":
			hashcat()
		elif user_input == "2":
			john()
		elif user_input == "3":
			rainbowcrack()
		elif user_input == "4":
			hashid()
		elif user_input == "5":
			passlib()
		elif user_input == "6":
			Tool_menu = False
		else:
			print(Fore.GREEN + "Invalid choice")

def packet_crafting_analysis():
	banner()
	def scapy():
		os.system("sudo apt install scapy")
		os.system("clear")
		print(Fore.GREEN + "You can run the command scapy --help from anywhere in the terminal to see its help options.\n")
	
	def hping3():
		os.system("sudo apt install hping3")
		os.system("clear")
		print(Fore.GREEN + "You can run the command hping3 --help from anywhere in the terminal to see its help options.\n")
	
	def nmap():
		os.system("sudo apt install nmap")
		os.system("clear")
		print(Fore.GREEN + "You can run the command nmap --help from anywhere in the terminal to see its help options.\n")
	
	def ostinato():
		os.system("sudo apt install ostinato")
		os.system("clear")
		print(Fore.GREEN + "You can run the command ostinato --help from anywhere in the terminal to see its help options.\n")
	
	
	def netcat():
		os.system("sudo apt install netcat")
		os.system("clear")
		print(Fore.GREEN + "You can run the command netcat --help from anywhere in the terminal to see its help options.\n")
	
	def packetsender():
		os.system("sudo apt install packetsender")
		os.system("clear")
		print(Fore.GREEN + "You can run the command packetsender --help from anywhere in the terminal to see its help options.\n")
	
	def bittwist():
		os.system("sudo apt install bittwist")
		os.system("clear")
		print(Fore.GREEN + "You can run the command bittwist --help from anywhere in the terminal to see its help options.\n")
	
	def ettercap():
		os.system("sudo apt install ettercap-graphical")
		os.system("clear")
		print(Fore.GREEN + "You can run the command ettercap --help from anywhere in the terminal to see its help options.\n")
	
	def yersinia():
		os.system("sudo apt install yersinia")
		os.system("clear")
		print(Fore.GREEN + "You can run the command yersinia --help from anywhere in the terminal to see its help options.\n")
	
	def pypacker():
		os.system("pip install pypacker")
		os.system("clear")
		print(Fore.GREEN + "You can run the command pypacker --help from anywhere in the terminal to see its help options.\n")
	
	Tool_menu = True
	while Tool_menu:
		print(Fore.GREEN + "1. Scapy")
		print(Fore.GREEN + "2. Hping3 ")
		print(Fore.GREEN + "3. Nmap")
		print(Fore.GREEN + "4. Ostinato")
		print(Fore.GREEN + "5. Netcat")
		print(Fore.GREEN + "6. Packetsender")
		print(Fore.GREEN + "7. Bittwist")
		print(Fore.GREEN + "8. Eettercap")
		print(Fore.GREEN + "9. Yersinia")
		print(Fore.GREEN + "10. Pypacker")
		print(Fore.GREEN + "11. Exit")
		
		user_input = input("==>>>")
		
		if user_input == "1":
			scapy()
		elif user_input == "2":
			hping3()
		elif user_input == "3":
			nmap()
		elif user_input == "4":
			ostinato()
		elif user_input == "5":
			netcat()
		elif user_input == "6":
			packetsender()
		elif user_input == "7":
			bittwist()
		elif user_input == "8":
			ettercap()
		elif user_input == "9":
			yersinia()
		elif user_input == "10":
			pypacker()
		elif user_input == "11":
			Tool_menu = False
		else:
			print(Fore.GREEN + "Invalid choice")
	
def social_enginering():
	banner()
	def set():
		os.system("sudo apt install set")
		os.system("clear")
		print(Fore.GREEN + "You can run the command setoolkit --help from anywhere in the terminal to see its help options.\n")
	
	def hiddeneye():
		os.system("pip install hiddeneye")
		os.system("clear")
		print(Fore.GREEN + "You can run the command hiddeneye --help from anywhere in the terminal to see its help options.\n")
		
	def zphisher():
		os.system("pip install zphisher")
		os.system("clear")
		print(Fore.GREEN + "You can run the command zphisher --help from anywhere in the terminal to see its help options.\n")
	
	def blackeye():
		os.system("pip install blackeye")
		os.system("clear")
		print(Fore.GREEN + "You can run the command blackeye --help from anywhere in the terminal to see its help options.\n")
	
	def shellphish():
		os.system("pip install shellphish")
		os.system("clear")
		print(Fore.GREEN + "You can run the command shellphish --help from anywhere in the terminal to see its help options.\n")
	
	def ghost_phisher():
		os.system("sudo apt install ghost-phisher")
		os.system("clear")
		print(Fore.GREEN + "You can run the command ghost-phisher --help from anywhere in the terminal to see its help options.\n")
	
	def beef():
		os.system("sudo apt install beef-xss")
		os.system("clear")
		print(Fore.GREEN + "You can run the command beef --help from anywhere in the terminal to see its help options.\n")
	
	
	Tool_menu = True
	while Tool_menu:
		print(Fore.GREEN + "1. Setoolkit")
		print(Fore.GREEN + "2. Hiddeneye")
		print(Fore.GREEN + "3. Zphisher")
		print(Fore.GREEN + "4. Blackeye")
		print(Fore.GREEN + "5. Shellphish")
		print(Fore.GREEN + "6. Ghost-phisher")
		print(Fore.GREEN + "7. Beef-xss")
		print(Fore.GREEN + "8. Exit")
		
		user_input = input("==>>>")
		
		if user_input == "1":
			set()
		elif user_input == "2":
			hiddeneye()
		elif user_input == "3":
			zphisher()
		elif user_input == "4":
			blackeye()
		elif user_input == "5":
			shellphish()
		elif user_input =="6":
			ghost_phisher()
		elif user_input == "7":
			beef()
		elif user_input == "8":
			Tool_menu = False
		else:
			print(Fore.RED + "Invalid choice")
	

def tor_and_anonymity_tools():
	banner()
	def tor():
		os.system("sudo apt install tor")
		os.system("clear")
		print(Fore.GREEN + "You can run the command tor --help from anywhere in the terminal to see its help options.\n")
	
	def torsocks():
		os.system("sudo apt install torsocks")
		os.system("clear")
		print(Fore.GREEN + "You can run the command torsocks --help from anywhere in the terminal to see its help options.\n")
	
	def proxychains():
		os.system("sudo apt install proxychains")
		os.system("clear")
		print(Fore.GREEN + "You can run the command proxychains --help from anywhere in the terminal to see its help options.\n")
	
	def torbrowser():
		os.system("sudo apt install torbrowser-launcher")
		os.system("clear")
		print(Fore.GREEN + "You can run the command proxychains --help from anywhere in the terminal to see its help options.\n")
	
	def i2p():
		os.system("sudo apt install i2p")
		os.system("clear")
		print(Fore.GREEN + "You can run the command i2p --help from anywhere in the terminal to see its help options.\n")
	
	def macchanger():
		os.system("sudo apt install macchanger")
		os.system("clear")
		print(Fore.GREEN + "You can run the command macchanger --help from anywhere in the terminal to see its help options.\n")
	
	def privoxy():
		os.system("sudo apt install privoxy")
		os.system("clear")
		print(Fore.GREEN + "You can run the command privoxy --help from anywhere in the terminal to see its help options.\n")
		
	def nyx():
		os.system("sudo apt install nyx")
		os.system("clear")
		print(Fore.GREEN + "You can run the command nyx --help from anywhere in the terminal to see its help options.\n")
		
	def openvpn():
		os.system("sudo apt install openvpn")
		os.system("clear")
		print(Fore.GREEN + "You can run the command openvpn --help from anywhere in the terminal to see its help options.\n")
	
	def wireguard():
		os.system("sudo apt install wireguard")
		os.system("clear")
		print(Fore.GREEN + "You can run the command wireguard --help from anywhere in the terminal to see its help options.\n")
	
	Tool_menu = True
	while Tool_menu:
		print(Fore.GREEN + "1. Tor")
		print(Fore.GREEN + "2. Torsocks")
		print(Fore.GREEN + "3. Proxychains")
		print(Fore.GREEN + "4. Torbrowser")
		print(Fore.GREEN + "5. I2p")
		print(Fore.GREEN + "6. Macchanger")
		print(Fore.GREEN + "7. Privoxy")
		print(Fore.GREEN + "8. Nyx")
		print(Fore.GREEN + "9. Openvpn")
		print(Fore.GREEN + "10. Wireguard")
		print(Fore.GREEN + "11. Exit")
		
		user_input = input("==>>>")
		
		if user_input == "1":
			tor()
		elif user_input == "2":
			torsocks()
		elif user_input == "3":
			proxychains()
		elif user_input == "4":
			torbrowser()
		elif user_input == "5":
			i2p()
		elif user_input == "6":
			macchanger()
		elif user_input == "7":
			privoxy()
		elif user_input == "8":
			nyx()
		elif user_input == "9":
			openvpn()
		elif user_input == "10":
			wireguard()
		elif user_input == "11":
			Tool_menu = False
		else:
			print(Fore.GREEN + "Invalid choice")
	
def extra_tools():
	banner()
	def fuxploider():
		os.system("pip install fuxploider")
		os.system("clear")
		print(Fore.GREEN + "You can run the command fuxploider --help from anywhere in the terminal to see its help options.\n")
	
	def urlcrazy():
		os.system("pip install urlcrazy")
		os.system("clear")
		print(Fore.GREEN + "You can run the command urlcrazy --help from anywhere in the terminal to see its help options.\n")
	
	def photon():
		os.system("pip install photon")
		os.system("clear")
		print(Fore.GREEN + "You can run the command pip install photon --help from anywhere in the terminal to see its help options.\n")
	
	def osint_spy():
		os.system("pip install osint-spy")
		os.system("clear")
		print(Fore.GREEN + "You can run the command osint-spy --help from anywhere in the terminal to see its help options.\n")
	
	def h8mail():
		os.system("pip install h8mail")
		os.system("clear")
		print(Fore.GREEN + "You can run the command h8mail --help from anywhere in the terminal to see its help options.\n")
	
	def emailharvester():
		os.system("pip install emailharvester")
		os.system("clear")
		print(Fore.GREEN + "You can run the command emailharvester --help from anywhere in the terminal to see its help options.\n")
	
	def dmitry_py():
		os.system("pip install dmitry-py")
		os.system("clear")
		print(Fore.GREEN + "You can run the command dmitry-py --help from anywhere in the terminal to see its help options.\n")
	
	def xlinkfinder():
		os.system("pip install xlinkfinder")
		os.system("clear")
		print(Fore.GREEN + "You can run the command xlinkfinder --help from anywhere in the terminal to see its help options.\n")
	
	def pentest_tools():
		os.system("pip install pentest-tools")
		os.system("clear")
		print(Fore.GREEN + "You can run the command pentest-tools --help from anywhere in the terminal to see its help options.\n")
	
	tool_menu = True
	while tool_menu:
		print(Fore.GREEN + "1 Fuxploider")
		print(Fore.GREEN + "2. Urlcrazy")
		print(Fore.GREEN + "3. Photon")
		print(Fore.GREEN + "4. Osint-spy")
		print(Fore.GREEN + "5. H8mail")
		print(Fore.GREEN + "6. Emailharvester")
		print(Fore.GREEN + "7. Dmitry_py")
		print(Fore.GREEN + "8. Xlinkfinder")
		print(Fore.GREEN + "9. Pentest-tools")
		print(Fore.GREEN + "10. Exit")
		
		user_input = input("==>>>")
		
		if user_input == "1":
			fuxploider()
		elif user_input == "2":
			urlcrazy()
		elif user_input == "3":
			photon()
		elif user_input == "4":
			osint_spy()
		elif user_input == "5":
			h8mail()
		elif user_input == "6":
			emailharvester()
		elif user_input == "7":
			dmitry_py()
		elif user_input == "8":
			xlinkfinder()
		elif user_input == "9":
			pentest_tools()
		elif user_input == "10":
			tool_menu = False
		else:
			print(Fore.RED + "Invalid choice")
		

is_running = True

#Tool menu 
while is_running:
    print(Fore.GREEN + "1. Information_gathering")
    print(Fore.GREEN + "2. Vulnerability_scanning")
    print(Fore.GREEN + "3. Exploitation_tools")	
    print(Fore.GREEN + "4. Password_attack")
    print(Fore.GREEN + "5. Wireless_attack")
    print(Fore.GREEN + "6. Sniffing_and_spoofing_mitm")
    print(Fore.GREEN + "7. Web_application_attack")
    print(Fore.GREEN + "8. forensics_steganography")
    print(Fore.GREEN + "9. Malware_analysis")
    print(Fore.GREEN + "10. Recon_and_osint_tools")
    print(Fore.GREEN + "11. Subdomain_enumeration")
    print(Fore.GREEN + "12. Phishing_tools")
    print(Fore.GREEN + "13. Backdoor")
    print(Fore.GREEN + "14. Api_security_testing")
    print(Fore.GREEN + "15. Hash_cracking")
    print(Fore.GREEN + "16. Packet_crafting_analysis")
    print(Fore.GREEN + "17. Social_enginering")
    print(Fore.GREEN + "18. Tor_&_Anonymity_tools")
    print(Fore.GREEN + "19. Extra_tools")
    print(Fore.GREEN + "20. Exit")
    
    #user input, Choose your favorite
    user_input = input("==>>>")
    
    if user_input == "1":
	    information_gathering()
    elif user_input == "2":
	    vulnerability_scanning()
    elif user_input == "3":
	    exploitation_tools()
    elif user_input == "4":
	    password_attack()
    elif user_input == "5":
	    wireless_attacks()
    elif user_input == "6":
    	sniffing_and_spoofing_mitm()
    elif user_input == "7":
    	 web_application_attack()
    elif user_input == "8":
	    forensics_steganography()
    elif user_input == "9":
    	malware_analysis()
    elif user_input == "10":
    	recon_and_osint_tools()
    elif user_input == "11":
	    subdomain_enumeration()
    elif user_input == "12":
    	phishing_tools()
    elif user_input == "13":
    	backdoor()
    elif user_input == "14":
    	api_security_testing()
    elif user_input == "15":
    	hash_cracking()
    elif user_input == "16":
    	packet_crafting_analysis()
    elif user_input == "17":
    	social_enginering()
    elif user_input == "18":
     	tor_and_anonymity_tools()
    elif user_input == "19":
    	 extra_tools()
    elif user_input == "20":
    	is_running = False
    else:
    	print(Fore.RED + "Invalid option please choose a number between (1 to 20")
  
