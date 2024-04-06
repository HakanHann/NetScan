from scapy.all import ARP, Ether, srp
import os, sys, time, logging, threading


BLUE, RED, WHITE, GREEN, YELLOW, MAGENTA, END = '\33[94m', '\033[91m', '\33[97m', '\033[1;32m', '\033[93m', '\033[95m', '\033[0m'

def language_selection():
    while True:
        lang_choice = input("Please select language / Lütfen dil seçiniz (en/tr): ").strip().lower()
        if lang_choice == 'english' or lang_choice == 'en':
            return 'en'
        elif lang_choice == 'türkçe' or lang_choice == 'tr':
            return 'tr'
        else:
            print("Invalid selection / Geçersiz seçim")

selected_language = language_selection()

def shutdown():
    print('\n\n{}Thanks for dropping by.'
          '\nCatch ya later!{}'.format(GREEN, END))
    os._exit(0)

try:
    
    if os.geteuid() != 0:
        print("\n{}ERROR: Please run as root." .format(RED))
        os._exit(1)
except:
    pass

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

try:
   
    from scapy.config import conf  
    conf.ipv6_enabled = False
    from scapy.all import *
    from urllib.request import urlopen, Request
    from urllib.error import URLError
except KeyboardInterrupt:
    shutdown()
except:
    os._exit(1)

def scanningAnimation(text):
    try:
        i = 0
        while stopAnimation is not True:
            tempText = list(text)
            if i >= len(tempText):
                i = 0
            tempText[i] = tempText[i].upper()
            tempText = ''.join(tempText)
            sys.stdout.write(MAGENTA + tempText + '\r' + END)
            sys.stdout.flush()
            i += 1
            time.sleep(0.1)
    except:
        os._exit(1)

def checkInternetConnection():
    try:
        urlopen('https://github.com', timeout=3)
        return True
    except URLError as err:
        return False
    except KeyboardInterrupt:
        shutdown()

def exit_program():
    print("\nExiting program...")
    os._exit(0)

def check_exit():
    while True:
        choice = input("Press 'e' to exit: ").strip().lower()
        if choice == 'e':
            exit_program()

if selected_language == 'en':
    input_prompt = ('{}NetScan{}> {}Enter Gateway IP (e.g. 192.168.1.1): '.format(BLUE, WHITE, RED, END))
    network_devices_message = "Current devices on the network:"
    ip_header = "IP"
    mac_header = "MAC"
    scanning_text = "Scanning Network"
else:  
    input_prompt = ('{}NetScan{}> {}Gateway IP adresini girin (örn: 192.168.1.1): '.format(BLUE, WHITE, RED, END))
    network_devices_message = "Ağdaki mevcut cihazlar:"
    ip_header = "IP"
    mac_header = "MAC"
    scanning_text = "Ağ Taranıyor"

target_ip = input(input_prompt)

target_ip_with_subnet = f"{target_ip}/24"

arp = ARP(pdst=target_ip_with_subnet)

ether = Ether(dst="ff:ff:ff:ff:ff:ff")

packet = ether/arp

stopAnimation = False
animation_thread = threading.Thread(target=scanningAnimation, args=(scanning_text,))
animation_thread.start()

result = srp(packet, timeout=3, verbose=0)[0]

stopAnimation = True
animation_thread.join()

clients = []

for sent, received in result:
    clients.append({'ip': received.psrc, 'mac': received.hwsrc})

print(network_devices_message)
print(f"{BLUE}{ip_header}{' '*18}{mac_header}{END}")
for client in clients:
    print(f"{YELLOW}{client['ip']}{' '*(15-len(client['ip']))}{RED}{client['mac']}{' '*(20-len(client['mac']))}{END}")  # IP ve MAC arasındaki boşluğu ve MAC'i ayarla

exit_thread = threading.Thread(target=check_exit)
exit_thread.start()
