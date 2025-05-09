from PyQt5.QtWidgets import (QApplication, QMainWindow, QVBoxLayout, QPushButton, QTextEdit,
                             QLineEdit, QLabel, QWidget, QHBoxLayout, QListWidget, QMessageBox, 
                             QTableWidget, QTableWidgetItem, QHeaderView)              # Arayüz bileşenleri

from PyQt5.QtCore import QThread, pyqtSignal        # Arkaplan işlemleri, sinyal
from PyQt5.QtGui import QIcon                       # Görsel özellik
from collections import defaultdict                 # Varsayılan bir değer atanmış sözlük oluşturur.

#Bu bileşenler PyQt5 tabanlı bir masaüstü GUI uygulaması geliştirmek için kullanılıyor. 🚀

import time         # DDoS ataklarını anlamak için time kullanılacak
import sys
import os
import pydivert     # Windows için bir ağ paketi yakalama
import socket       # IP adres çözümleme
import logging      # log tutacak


logging.basicConfig(
    filename="firewall_logs.txt",
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
    
)

def log_to_file(message, level="info"):

    if level=="info":
        logging.info(message)
    elif level=="warning":
        logging.warning(message)
    elif level=="error":
        logging.error(message)
        

class FirewallWorker(QThread):
    log_signal = pyqtSignal(str,str,str)
    rules_signal = pyqtSignal(str)
    
    PROTOCOL_MAP ={
        1: "ICMP",  # Internet Kontrol Mesaj Protokolü
        2: "IGMP",  # Internet Grup Yönetim Protokolü
        6: "TCP",   # Transfer Kontrol Protokolü
        8: "EGP",   # Exterior Gateway Protocol
        9: "IGP",   # Interior Gateway Protocol
        17: "UDP",  # User Datagram Protocol
        41: "IPv6", # IPv6 
        50: "ESP (Encapsulation Security Payload)", #Güvenlik Protokolü
        51: "AH (Authentication Header)",   # Kimlik Doprulama 
        58: "ICMPv6",   #IPv6 için ICMO
        89: "OSPF (Open Shortest Path First)",  # Yönlendirme Protokolü
        103: "PIM",
        112: "VRRP (Virtual Router Redundancy Protocol)",   # Sanal Yönlendirici Protokolü
        132: "SCTP (Stream Control Transmission Protocol)", # Akış Kontrol Transfer Protokolü   
        135: "UDP-Lite",
        137: "MPLS-in-IP",  # MPLS verilerini IP içinde taşıma
        143: "EtherIP",     # Ethernet over IP
        170: "RSVP",
        179: "BGP",
        255: "Experimental (Reserved)", # Deneysel veya rezerve edilmiş
    }

    def __init__(self,rules,website_filter):        # Tanımlamalar
        super().__init__()
        self.rules=rules
        self.website_filter=website_filter
        self.running = True                         # Çalışmasını kontrol eder.
        self.traffic_tracker=defaultdict(list)      # Trafik kontrolü (IP adresine gelen zaman damgalarını saklıyor)
        self.blacklist=set()                        # Banlanan IP's
        self.whitelist=["127.0.0.1","::1"]          # Temiz IP's (bilgisayarımızın varsayılan IP adresleri)



        def resolve_url_to_ip(self,url):            # URL'nin IP adresini çözümlemek için kullanılır.(DNS)
            try:
                return socket.gethostbyname(url)    # URL'nin IP adresini döndürür.
            except socket.gaierror:
                return None
            

            
        def get_protocol_name(self,protocol):
            
            if isinstance(protocol,tuple):
                protocol=protocol[0]
            return self.PROTOCOL_MAP.get(protocol,f"Unknow ({protocol})n") # Protokolün ismini döndür
        
        def run(self):
            try:
                with pydivert.WinDivert("tcp or udp") as w:
                    for packet in w:
                        if not self.running:
                            break
                        
                        src_ip=packet.src_addr
                        dst_ip=packet.dst_addr
                        protocol=self.get_protocol_name(packet.protocol)
                        current_time=time.time()
                        
                        if src_ip in self.whitelist:
                            w.send(packet)
                            continue
                        
                        if src_ip in self.blacklist:
                            self.rules_signal.emit(f"IP in blacklist: {src_ip}")
                            continue
                        
                        
                        if dst_ip in self.website_filter:
                            self.rules_signal.emit(f"Engellendi:{dst_ip}(Website)")
                            continue
                        
                        self.traffic_tracker[src_ip].append(current_time)
                        
                        short_window = [ts for ts in self.traffic_tracker[src_ip] if current_time - ts <=1]     # 1 saniyelik zaman dilimi kontrolü
                        long_window = [ts for ts in self.traffic_tracker[src_ip] if current_time - ts <=10]     # 10 saniyelik zaman dilimi kontrolü
                        short_count=len(short_window)
                        long_count=len(long_window)
                        
                        
                        if short_count > 10000 or long_count >50000:
                            self.rules_signal.emit(f"DDoS tespit edildi: {src_ip} (1s:{short_count}, 10s{long_count})")
                            self.blacklist.add(src_ip)
                            log_to_file(f"DDoS tespit edildi ve engellendi: {src_ip}",level="warning")
                            continue
                        
                        self.log_signal.emit(src_ip,dst_ip,protocol)
                        log_to_file(f"Paket: {src_ip}:{packet,src_port} -> {dst_ip}:{packet.dst_port}")
                        blocked = False
                        
                        for rule in self.rules:
                            if "tcp" in rule and protocol.lower() =="tcp":
                                self.rules_signal.emit("TCP paketi engellendi.")
                                blocked=True
                                break
                            elif "udp" in rule and protocol.lower() =="udp":
                                self.rules_signal.emit("UDP paketi engellendi.")
                                blocked=True
                                break
                            
                            if rule in f"{packet.src_addr}:{packet.src_port}" or rule in f"{packet.dst_addr}:{packet.dst_port}":
                                self.rules_signal.emit(f"Paket engellendi: {rule}")
                                log_to_file(f"Kural engellendi:{rule}",level="warning")
                                blocked=True
                                break
                            
                        
                        if not blocked:
                            w.send(packet)
            except Exception as e:
                self.rules_signal.emit(f"Hata:{str(e)}")

        def stop(self):
            self.running = False
            

class FirewallGUI(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Firewall")
        self.setWindowIcon(QIcon("icon.ico"))
        screen= QApplication.primaryScreen()
        screen_size = screen.size()
        self.resize(screen_size.width()//2,screen_size.height()//2)
        self.main_widget = QWidget()
        self.setCentralWidget(self.main_widget)
        layout = QVBoxLayout()
        
        self.start_button = QPushButton("Firewall Başlat")
        self.start_button.clicked.connect(self.start_firewall)
        self.stop_button = QPushButton("Firewall Durdur")
        self.stop_button.setEnabled(False)
        self.stop_button.clicked.connect(self.stop_firewall)
        
        rule_layout = QHBoxLayout()
        self.rule_label = QLabel("Kurallar")
        self.rule_list = QListWidget()
        self.rule_input = QLineEdit()
        self.rule_input.setPlaceholderText("Port veya IP kuralı girin: (ör. 192.168.1.1:80)....")
        self.add_rule_button = QPushButton("Kural Ekle")
        self.add_rule_button.clicked.connect(self.add_rule)
        rule_layout.addWidget(self.rule_input)
        rule_layout.addWidget(self.add_rule_button)
        self.delete_rule_button = QPushButton("Seçili Kuralı Sil")
        self.delete_rule_button.clicked.connect(self.delete_rule)
        
        
        self.network_label = QLabel("Ağ Trafiği")
        self.log_area = QTableWidget()  # Tablo oluşturuyor
        self.log_area.setColumnCount(3)
        self.log_area.setHorizontalHeaderLabels(["Kaynak","Hedef","Protocol"])
        self.log_area.setEditTriggers(QTableWidget.NoEditTriggers)
        
        header = self.log_area.horizontalHeader()
        header.setSectionResizeMode(QHeaderView.Stretch)
        
        
        self.rules_label = QLabel("Uygulanan Kurallar:")
        self.rules_area = QTextEdit()
        self.rules_area.setReadOnly(True)
        
        self.web_label = QLabel("Engellenen Siteler :")
        self.web_list = QListWidget()

        website_layout = QHBoxLayout()
        self.website_input = QLineEdit()
        self.website_input.setPlaceholderText("Engellenmek istenen site girin: (ör. www.example.com)...")
        self.add_website_button = QPushButton("Website Ekle")
        self.add_website_button.clicked.connect(self.add_website)
        website_layout.addWidget(self.website_input)
        website_layout.addWidget(self.add_website_button)


        
        layout.addWidget(self.start_button)
        layout.addWidget(self.stop_button)
        layout.addWidget(self.rule_label)
        layout.addWidget(self.rule_list)
        layout.addLayout(rule_layout)
        layout.addWidget(self.delete_rule_button)
        layout.addWidget(self.network_label)
        layout.addWidget(self.log_area)
        layout.addWidget(self.rules_label)
        layout.addWidget(self.rules_area)
        layout.addWidget(self.web_label)
        layout.addWidget(self.web_list)
        layout.addLayout(website_layout)
        
        self.main_widget.setLayout(layout)
        
        
        self.firewall_worker = None
        self.rules = []
        self.website_filter = set()
        
        
        
        
    def add_to_traffic_table(self,src,dst,protocol):
        row_position = self.log_area.rowCount()
        self.log_area.insertRow(row_position)
        self.log_area.setItem(row_position,0,QTableWidgetItem(src))
        self.log_area.setItem(row_position,1,QTableWidgetItem(dst))
        self.log_area.setItem(row_position,2,QTableWidgetItem(protocol))
        
        
    def add_rule(self):
        rule = self.rule_input.text()
        if rule:
            self.rules.append(rule)
            self.rule_list.addItem(rule)
            self.rule_input.clear()
            self.rules_area.append(f"Kural eklendi: {rule}")
        else:
            QMessageBox.warning(self,"Uyarı","Geçerli bir kural girin!")
            
            
    def delete_rule(self):
        selected_item = self.rule_list.currentItem()
        if selected_item:
            rule = selected_item.text()
            self.rules.remove(rule)
            self.rule_list.takeItem(self.rule_list.row(selected_item))
            self.rules_area.append(f"Kural silindi: {rule}")
        else:
            QMessageBox.warning(self,"Uyarı","Silmek için bir kural seçin!")
            
    
    def start_firewall(self):
        if not self.firewall_worker:
            self.firewall_worker = FirewallWorker(self.rules,self.website_filter)
            self.firewall_worker.log_signal.connect(self.add_to_traffic_table)
            self.firewall_worker.rules_signal.connect(self.rules_area.append)
            self.firewall_worker.start()
            self.start_button.setEnabled(False)
            self.stop_button.setEnabled(True)
            
    
    def add_website(self):
        url = self.website_input.text()
        if url:
            ip = self.firewall_worker.resolve_url_to_ip(url)
            if ip:
                self.website_filter.add(ip)
                self.web_list.addItem(f"{url} ({ip})")
                self.website_input.clear()
                self.rules_area.append(f"Web sitesi filtresine eklendi: {url} ({ip})")
            else:
                QMessageBox.warning(self,"Uyarı","URL'nin IP adresini bulamadım.")
        else:
            QMessageBox.warning(self,"Uyarı","Bir URL girin!")
            
            
        
    def stop_firewall(self):
        if self.firewall_worker:
            self.firewall_worker.stop()
            self.firewall_worker.quit()
            self.firewall_worker.wait()
            self.firewall_worker = None
            self.start_button.setEnabled(True)
            self.stop_button.setEnabled(False)
            self.rules_area.append("Firewall Durduruldu")
    
            

if __name__ =="__main__":
    app=QApplication(sys.argv)
    gui=FirewallGUI()
    gui.show()
    sys.exit(app.exec_())
    