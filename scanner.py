from scapy.all import *
from multiprocessing import Process
from datetime import datetime
import ipaddress
import time

MONLIST_PACKIT = b"\x17\x00\x03\x2a" + b"\x00" * 44


def ssleep(duration):
    """
    高精度休眠函数，可以精确到纳秒级别
    :param duration: 休眠时长，timedelta对象
    """
    end_time = time.time() + duration
    while time.time() < end_time:
        pass


# Function to send NTP requests within a given range of IP addresses
def send_ntp_requests(ip_range_start, ip_range_end, process_id):
    current_ip = ip_range_start
    packets_sent = 0

    while current_ip <= ip_range_end:
        address = str(current_ip)
        send(IP(dst=address) / UDP(sport=123, dport=123) / Raw(load=MONLIST_PACKIT), verbose=0)
        current_ip += 1
        packets_sent += 1
        ssleep(0.01)

    print(f'Process {process_id}: Finished sending requests')


def sniffer():
    sniff(filter="udp port 123", store=0, prn=analyser)


# Analyse incoming packets
def analyser(packet):
    if len(packet) > 200 and packet.haslayer(IP):
        ip_src = packet.getlayer(IP).src
        print(datetime.now().strftime("%H:%M:%S\t\t"), ip_src)

        with open('monlist.txt', 'r', encoding='utf-8') as file:
            existing_ips = set(line.strip() for line in file)

        if ip_src not in existing_ips:
            with open('monlist.txt', 'a', encoding='utf-8') as outputFile:
                outputFile.write(ip_src + '\n')


# Function to divide the IP range into `i` parts
def divide_ip_range(start_ip, end_ip, i):
    total_ips = int(end_ip) - int(start_ip) + 1
    ips_per_process = total_ips // i
    ranges = []

    for n in range(i):
        range_start = ipaddress.IPv4Address(int(start_ip) + n * ips_per_process)
        if n == i - 1:  # Last process takes remaining IPs
            range_end = end_ip
        else:
            range_end = ipaddress.IPv4Address(int(range_start) + ips_per_process - 1)
        ranges.append((range_start, range_end))

    return ranges


if __name__ == '__main__':
    scan_count = 0
    # Start sniffer process
    sniffer_process = Process(target=sniffer)
    sniffer_process.start()

    # 单进程发包间隔0.01   (大约80pps)，扫描端口11次，成功9次
    # 单进程发包间隔0.001  (大约150-180pps)，扫描端口21次，成功16次
    # 单进程发包间隔0      (大约500-600pps)，扫描端口6次，成功0次

    while True:
        scan_count += 1
        num_processes = 1
        # start_ip = ipaddress.IPv4Address('124.217.0.0')
        # end_ip = ipaddress.IPv4Address('124.219.255.255')
        # start_ip = ipaddress.IPv4Address('121.0.0.0')
        # end_ip = ipaddress.IPv4Address('122.225.255.255')

        start_ip = ipaddress.IPv4Address('120.0.35.0')
        end_ip = ipaddress.IPv4Address('130.0.0.0')

        # Divide the IP range
        ip_ranges = divide_ip_range(start_ip, end_ip, num_processes)

        # Create and start processes for sending requests
        processes = []
        for process_id, (range_start, range_end) in enumerate(ip_ranges):
            p = Process(target=send_ntp_requests,
                        args=(range_start, range_end, process_id))
            processes.append(p)
            p.start()

        # Wait for all processes to finish
        for p in processes:
            p.join()
        print(f'scanned {scan_count} times')
