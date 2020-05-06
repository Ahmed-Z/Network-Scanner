from scapy.all import *
import subprocess

class Arpscan:
    def __init__(self):
        cmd = subprocess.check_output('ip r | grep default',shell = True, stderr=None).split()
        self.gateway = str(cmd[2].decode('utf-8'))
    
    def get_mac(self,mac):
        mac = mac.upper().replace(':','')[0:6]
        with open("mac-vendor.txt","r") as f:
            for line in f :
                if mac in line:
                    return line[7:]
        return 'Unknown'                    
        
    def scan(self,ip):
        arp_request = ARP(pdst=ip)
        broadcast = Ether(dst='ff:ff:ff:ff:ff:ff')
        arp_request_broadcast = broadcast/arp_request
        answered_list = srp(arp_request_broadcast,timeout=1,verbose=False)[0]
        print("IP Address"+2*'\t'+'MAC Address'+ 3*'\t' + 'Company Name')
        print(75*"-")
        n=0
        for element in answered_list:
            mac_company = self.get_mac(element[1].src).strip()
            print(element[0].pdst + 2*'\t' + element[1].src + 2*'\t' + mac_company)
            n+=1
        print('\n' + str(n) + ' Devices were discovered.' )

    def start(self):
        ip = self.gateway+'/24'
        self.scan(ip)

scanner = Arpscan()
scanner.start()