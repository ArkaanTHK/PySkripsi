from scapy.all import sniff
from scapy.utils import PcapWriter
from datetime import datetime
from time import sleep
from os import path, makedirs
from threading import Event, Thread

class Sniffer:
    def __init__(self, sniffing_active: Event, shutdown_signal: Event, pcap_path="./pcap/captured_packets.pcap", log_path="./logs/final_packets.log"):
        self.sniffing_active = sniffing_active
        self.shutdown_signal = shutdown_signal
        self.pcap_path = ""
        self.log_path = ""
        self.temp_log_path = ""

        self.set_pcap_path(pcap_path)
        self.set_log_path(log_path)

        self.pkt_dump = PcapWriter(pcap_path, append=True, sync=True)

    def set_log_path(self, log_path):
        self.log_path = log_path
        self.check_and_create_paths(log_path)

    def set_pcap_path(self, pcap_path):
        self.pcap_path = pcap_path
        self.check_and_create_paths(pcap_path)

    def check_and_create_paths(self, file_path):
        # check the folder exists or not. If not, create it recursively
        # the path can be a file or a folder
        folder_path = path.dirname(file_path)
        print(folder_path)
        if not path.exists(folder_path):
            makedirs(folder_path)

        # check the file exists or not. If not, create it
        if not path.exists(file_path):
            with open(file_path, 'w'):
                pass

    def start_sniffing(self):
        self.sniffing_active.set()
        Thread(target=self.sniff_packets).start()

    def stop_sniffing(self):
        self.sniffing_active.clear()
        self.shutdown_signal.set()
    
    def packet_callback(self, packet):
        with open(self.temp_log_path, 'a') as temp_log:
            temp_log.write(f"{datetime.now()} - {packet.summary()}\n")

        self.pkt_dump.write(packet)

    def sniff_packets(self):
        while not self.shutdown_signal.is_set() and self.sniffing_active.is_set():
            self.temp_log_path = path.dirname(self.log_path) + '/temporary_packets.log'
            if not path.exists(self.temp_log_path):
                with open(self.temp_log_path, 'w'):
                    pass

            sniff(timeout=5, prn=self.packet_callback, store=0)
            
            with open(self.temp_log_path, 'r') as temp_log:
                logs = temp_log.read()

            if logs:
                with open(self.log_path, 'a') as final_log:
                    final_log.write(logs)

                open(self.temp_log_path, 'w').close()

            sleep(5)

    def is_sniffing_active(self):
        return self.sniffing_active.is_set()
