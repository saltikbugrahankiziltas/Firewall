from PyQt5.QtWidgets import (QApplication, QMainWindow, QVBoxLayout, QPushButton, QTextEdit,
                             QLineEdit, QLabel, QWidget, QHBoxLayout, QListWidget, QMessageBox, 
                             QTableWidget, QTableWidgetItem, QHeaderView)                       # Arayüz bileşenleri

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
