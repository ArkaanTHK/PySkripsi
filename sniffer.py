import logging
from configuration import get_value
import pyshark
import pyshark.config
import pyshark.tshark
import pyshark.tshark.tshark

from time import sleep
from os import path, makedirs, listdir, system, remove

from scapy.all import sniff
from scapy.utils import PcapWriter

from yara_py import Yara_Py
from datetime import datetime
from collections import Counter
from threading import Event, Thread

class Sniffer:
    def __init__(self, sniffing_active: Event, shutdown_signal: Event) -> None:
        self.sniffing_active = sniffing_active
        self.shutdown_signal = shutdown_signal
        self.pcap_path = ""
        self.log_path = ""
        self.temp_log_path = ""
        self.current_pcap_dir = ""
        self.root_pcap_dir = ""
        self.yara_skener = Yara_Py(get_value("YARA_RULES_FOR_APPLICATION_PATH"), get_value("YARA_LOGS_FOR_APPLICATION_PATH"))

        self.set_pcap_path(get_value("PCAP_DIR"))
        self.set_log_path(get_value("LOG_DIR"))

    def set_log_path(self, log_dir) -> None:
        log_dir = path.dirname(log_dir)
        log_dir = self.check_valid_dir_path(log_dir)
        log_path = log_dir + datetime.now().strftime("%Y-%m-%d") + ".log"
        self.log_path = log_path
        self.check_and_create_paths(log_path)

    def set_pcap_path(self, pcap_dir) -> None:
        pcap_dir = path.dirname(pcap_dir)
        pcap_dir = self.check_valid_dir_path(pcap_dir)
        pcap_dir += datetime.now().strftime("%Y%m%d") + "/"
        pcap_path = pcap_dir + datetime.now().strftime("%H%M%S") + ".pcap"
        self.pcap_path = pcap_path
        self.current_pcap_dir = pcap_dir
        self.check_and_create_paths(pcap_dir)

    def check_valid_dir_path(self, dir_path) -> str:
        if not dir_path.endswith("/"):
            dir_path += "/"
        return dir_path

    def check_and_create_paths(self, file_path) -> None:
        folder_path = path.dirname(file_path)
        if not path.exists(folder_path):
            makedirs(folder_path)

        if not path.exists(file_path):
            with open(file_path, 'w'):
                pass

    def check_configurations(self) -> None:
        if get_value("PCAP_DIR") != self.root_pcap_dir:
            self.set_pcap_path(get_value("PCAP_DIR"))
        
        if get_value("LOG_DIR") != self.log_path:
            self.set_log_path(get_value("LOG_DIR"))
        
        if get_value("YARA_RULES_FOR_APPLICATION_PATH") != self.yara_skener.yara_rules_path:
            self.yara_skener.set_yara_rules_path(get_value("YARA_RULES_FOR_APPLICATION_PATH"))

        if get_value("YARA_LOGS_FOR_APPLICATION_PATH") != self.yara_skener.yara_logs_path:
            self.yara_skener.set_yara_logs_path(get_value("YARA_LOGS_FOR_APPLICATION_PATH"))

    def start_sniffing(self) -> None:
        self.check_configurations()
        self.sniffing_active.set()
        Thread(target=self.sniff_packets).start()

    def stop_sniffing(self) -> None:
        self.sniffing_active.clear()
        self.shutdown_signal.set()
        merge_pcap_thread = Thread(target=self.merge_pcap_files)
        merge_pcap_thread.start()
        merge_pcap_thread.join()
    
    def check_day_change(self) -> None:
        if self.current_pcap_dir != self.root_pcap_dir + datetime.now().strftime("%Y%m%d") + "/":
            merge_pcap_thread = Thread(target=self.merge_pcap_files)
            merge_pcap_thread.start()
            merge_pcap_thread.join()

    def packet_callback(self, packet) -> None:
        with open(self.temp_log_path, 'a') as temp_log:
            temp_log.write(f"{datetime.now()} - {packet.summary()}\n")

        pkt_dump = PcapWriter(self.pcap_path, append=True, sync=True)
        pkt_dump.write(packet)
        pkt_dump.close()

    def merge_pcap_files(self) -> None:
        '''
        This method will merge all pcap files in the current pcap directory into a single pcap file using mergecap executables when the program stopped or on day change.
        The merged pcap file will be saved as 'merged.pcap'.
        '''
        pcap_files_path = path.abspath(self.current_pcap_dir)
        merge_files_path = pcap_files_path + "/merged.pcap"
        
        if path.exists(merge_files_path):
            system(f'mv {merge_files_path} {merge_files_path}.bak')

        pcap_files = listdir(self.current_pcap_dir)

        if len(pcap_files) > 1:
            pcap_files_string = ""
            for pcap_file in pcap_files:
                pcap_files_string += f"{pcap_files_path}/{pcap_file} "

            system(f'mergecap -w {merge_files_path} {pcap_files_string}')

            for pcap_file in pcap_files:
                remove(f'{pcap_files_path}/{pcap_file}')

    def sniff_packets(self) -> None:
        '''
        This method will sniff packets from all interfaces with 5 seconds interval.
        The packet result will be written into a pcap file and log file.
        After 5 seconds, the pcap file will be scanned for potential attacks.
        '''
        while not self.shutdown_signal.is_set() and self.sniffing_active.is_set():
            self.temp_log_path = path.dirname(self.log_path) + '/temporary_packets.log'
            if not path.exists(self.temp_log_path):
                with open(self.temp_log_path, 'w'):
                    pass
            
            self.set_pcap_path(self.root_pcap_dir)
            self.check_day_change()
            sniff(timeout=5, prn=self.packet_callback, store=0)
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

    def check_packet(self, packet, excluded_ips=[]) -> bool:
        try:
            return 'IP' in packet and packet.ip.src not in excluded_ips
        except AttributeError:
            return False

    def detect_attacks(self, pcap_file: str) -> None:
        '''
        This method will detect potential DDoS attacks from the pcap file.
        It will also scan the pcap file for potential attacks using Yara rules.
        '''
        cap = pyshark.FileCapture(pcap_file)
        cap.set_debug(log_level=logging.ERROR)

        # Dictionary to store packet counts per source IP for DDoS detection
        excluded_ips = ['192.168.1.100', '66.22.221.93']

        # Threshold for identifying DDoS traffic
        ddos_threshold = 100

        src_ips = (packet.ip.src for packet in cap if self.check_packet(packet, excluded_ips))
        source_ips_count = Counter(src_ips)
            
        # check for potential DDoS attacks
        for ip, count in source_ips_count.items():
            if count > ddos_threshold:
                print(f"Potential DDoS attack detected from {ip} with {count} packets")

        # create temporary pcap for yara scan
        temp_pcap = pcap_file.replace(".pcap", "_temp.pcap")
        temp_cap = pyshark.FileCapture(pcap_file, display_filter="http", output_file=temp_pcap)
        temp_cap.load_packets()
        temp_cap.close()

        self.yara_skener.set_file_path(temp_pcap)
        self.yara_skener.scan()

        # remove temporary pcap file
        remove(temp_pcap)

        cap.close()

    def is_sniffing_active(self) -> bool:
        return self.sniffing_active.is_set()