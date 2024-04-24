import pyshark.config
import pyshark.tshark
import pyshark.tshark.tshark
import logging
from scapy.all import sniff
from scapy.utils import PcapWriter
from datetime import datetime
from time import sleep
from os import path, makedirs, listdir, system
from threading import Event, Thread
from collections import Counter
from yara_py import Yara_Py
from configuration import Configuration
import pyshark

class Sniffer:
    def __init__(self, sniffing_active: Event, shutdown_signal: Event, yara_rules_path, yara_logs_path, pcap_dir="./pcap/", log_dir="./logs/"):
        self.sniffing_active = sniffing_active
        self.shutdown_signal = shutdown_signal
        self.pcap_path = ""
        self.log_path = ""
        self.temp_log_path = ""
        self.current_pcap_dir = ""
        self.root_pcap_dir = pcap_dir
        self.yara_skener = Yara_Py(yara_rules_path, yara_logs_path)

        self.set_pcap_path(pcap_dir)
        self.set_log_path(log_dir)

        # self.pkt_dump = PcapWriter(self.pcap_path, append=True, sync=True)

    def set_log_path(self, log_dir):
        log_dir = path.dirname(log_dir)
        log_dir = self.check_valid_dir_path(log_dir)
        log_path = log_dir + datetime.now().strftime("%Y-%m-%d") + ".log"
        self.log_path = log_path
        self.check_and_create_paths(log_path)

    def set_pcap_path(self, pcap_dir):
        pcap_dir = path.dirname(pcap_dir)
        pcap_dir = self.check_valid_dir_path(pcap_dir)
        pcap_dir += datetime.now().strftime("%Y%m%d") + "/"
        pcap_path = pcap_dir + datetime.now().strftime("%H%M%S") + ".pcap"
        self.pcap_path = pcap_path
        self.current_pcap_dir = pcap_dir
        self.check_and_create_paths(pcap_dir)

    def check_valid_dir_path(self, dir_path):
        if not dir_path.endswith("/"):
            dir_path += "/"
        return dir_path

    def check_and_create_paths(self, file_path):
        folder_path = path.dirname(file_path)
        if not path.exists(folder_path):
            makedirs(folder_path)

        if not path.exists(file_path):
            with open(file_path, 'w'):
                pass

    def start_sniffing(self):
        self.sniffing_active.set()
        Thread(target=self.sniff_packets).start()

    def stop_sniffing(self):
        self.sniffing_active.clear()
        self.shutdown_signal.set()
        merge_pcap_thread = Thread(target=self.merge_pcap_files)
        merge_pcap_thread.start()
        merge_pcap_thread.join()
    
    def check_day_change(self):
        if self.current_pcap_dir != self.root_pcap_dir + datetime.now().strftime("%Y%m%d") + "/":
            merge_pcap_thread = Thread(target=self.merge_pcap_files)
            merge_pcap_thread.start()
            merge_pcap_thread.join()

    def packet_callback(self, packet):
        with open(self.temp_log_path, 'a') as temp_log:
            temp_log.write(f"{datetime.now()} - {packet.summary()}\n")

        # self.pkt_dump.write(packet)
        pkt_dump = PcapWriter(self.pcap_path, append=True, sync=True)
        pkt_dump.write(packet)
        pkt_dump.close()
        yara_scan_thread = Thread(target=self.scan_packet)
        yara_scan_thread.start()
        yara_scan_thread.join()

    def merge_pcap_files(self):
        # use mergecap to merge pcap files
        pcap_files_path = path.abspath(self.current_pcap_dir)
        merge_files_path = pcap_files_path + "/merged.pcap"
        if path.exists(merge_files_path):
            system(f'rm {merge_files_path}')

        pcap_files = listdir(self.current_pcap_dir)

        if len(pcap_files) > 1:
            pcap_files_string = ""
            for pcap_file in pcap_files:
                pcap_files_string += f"{pcap_files_path}/{pcap_file} "
            system(f'mergecap -w {merge_files_path} {pcap_files_string}')

            for pcap_file in pcap_files:
                system(f'rm {pcap_files_path}/{pcap_file}')

    def sniff_packets(self):
        while not self.shutdown_signal.is_set() and self.sniffing_active.is_set():
            self.temp_log_path = path.dirname(self.log_path) + '/temporary_packets.log'
            if not path.exists(self.temp_log_path):
                with open(self.temp_log_path, 'w'):
                    pass
            
            self.set_pcap_path(self.root_pcap_dir)
            self.check_day_change()
            sniff(filter="inbound", timeout=5, prn=self.packet_callback, store=0, iface="ens33")
            # self.detect_attacks(path.abspath(self.pcap_path))
            detect_attack_thread = Thread(target=self.detect_attacks, args=(self.pcap_path,))
            detect_attack_thread.start()
            detect_attack_thread.join()

            with open(self.temp_log_path, 'r') as temp_log:
                logs = temp_log.read()

            if logs:
                with open(self.log_path, 'a') as final_log:
                    final_log.write(logs)

                open(self.temp_log_path, 'w').close()

            sleep(5)

    def check_packet(self, packet, excluded_ips=[]):
        try:
            return 'IP' in packet and packet.ip.src not in excluded_ips
        except AttributeError:
            return False

    def detect_attacks(self, pcap_file):
        cap = pyshark.FileCapture(pcap_file)
        cap.set_debug(log_level=logging.ERROR)

        # Dictionary to store packet counts per source IP for DDoS detection
        source_ips = {}
        excluded_ips = ['192.168.1.100', '66.22.221.93']

        # Threshold for identifying DDoS traffic
        ddos_threshold = 100

        src_ips = (packet.ip.src for packet in cap if self.check_packet(packet, excluded_ips))
        source_ips_count = Counter(src_ips)
            
        # if len(source_ips) > 0:
        #     for ip, count in source_ips.items():
        #         if count > ddos_threshold:
        #             print(f"Potential DDoS attack detected from {ip} with {count} packets")

        # check for potential DDoS attacks
        for ip, count in source_ips_count.items():
            if count > ddos_threshold:
                print(f"Potential DDoS attack detected from {ip} with {count} packets")

        cap.close()

    def scan_packet(self):
        self.yara_skener.set_file_path(self.pcap_path)
        self.yara_skener.scan()

    def is_sniffing_active(self):
        return self.sniffing_active.is_set()