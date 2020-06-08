from PyQt5 import QtWidgets
from PyQt5.QtWidgets import QMessageBox, QApplication, QGridLayout, QMainWindow, QLabel, QWidget, QAction, QTableWidget,QTableWidgetItem,QVBoxLayout ,QHBoxLayout,QGroupBox
from PyQt5.QtGui import QIcon
from PyQt5.QtCore import pyqtSlot, QSize, Qt
from PyQt5 import QtGui

from IPy import IP
import ipinfo
import sys
import socket
import struct
import textwrap
import urllib.request as urllib2
import json
import codecs

TAB_1 = '\t - '
TAB_2 = '\t\t - '
TAB_3 = '\t\t\t - '
TAB_4 = '\t\t\t\t - '
L = '\n'
DATA_TAB_1 = '\t   '
DATA_TAB_2 = '\t\t   '
DATA_TAB_3 = '\t\t\t   '
DATA_TAB_4 = '\t\t\t\t   '



# Unpack Ethernet Frame
def ethernet_frame(data):
    dest_mac, src_mac, proto = struct.unpack('! 6s 6s H', data[:14])
    return get_mac_addr(dest_mac), get_mac_addr(src_mac), socket.htons(proto), data[14:]

    # Format MAC Address
def get_mac_addr(bytes_addr):
    bytes_str = map('{:02x}'.format, bytes_addr)
    mac_addr = ':'.join(bytes_str).upper()
    return mac_addr

# Unpack IPv4 Packets Recieved
def ipv4_Packet(data):
    version_header_len = data[0]
    version = version_header_len >> 4
    header_len = (version_header_len & 15) * 4
    ttl, proto, src, target = struct.unpack('! 8x B B 2x 4s 4s', data[:20])
    return version, header_len, ttl, proto, ipv4(src), ipv4(target), data[header_len:]

# Returns Formatted IP Address
def ipv4(addr):
    return '.'.join(map(str, addr))


# Unpacks for any ICMP Packet
def icmp_packet(data):
    icmp_type, code, checksum = struct.unpack('! B B H', data[:4])
    return icmp_type, code, checksum, data[4:]

# Unpacks for any TCP Packet
def tcp_seg(data):
    (src_port, destination_port, sequence, acknowledgenment, offset_reserv_flag) = struct.unpack('! H H L L H', data[:14])
    offset = (offset_reserv_flag >> 12) * 4
    flag_urg = (offset_reserved_flag & 32) >> 5
    flag_ack = (offset_reserved_flag & 32) >>4
    flag_psh = (offset_reserved_flag & 32) >> 3
    flag_rst = (offset_reserved_flag & 32) >> 2
    flag_syn = (offset_reserved_flag & 32) >> 1
    flag_fin = (offset_reserved_flag & 32) >> 1

    return src_port, dest_port, sequence, acknowledgement, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, data[offset:]


# Unpacks for any UDP Packet
def udp_seg(data):
    src_port, dest_port, size = struct.unpack('! H H 2x H', data[:8])
    return src_port, dest_port, size, data[8:]

# Formats the output line
def format_output_line(prefix, string, size=80):
    size -= len(prefix)
    if isinstance(string, bytes):
        string = ''.join(r'\x{:02x}'.format(byte) for byte in string)
        if size % 2:
            size-= 1
            return '\n'.join([prefix + line for line in textwrap.wrap(string, size)])



class MyWindow(QMainWindow):
    
    def __init__(self):
        
        super(MyWindow,self).__init__()
        
        self.initUI()
    

    def initUI(self):

        self.w = QtWidgets.QWidget()

        self.v_box = QtWidgets.QVBoxLayout()



        self.b1 = QtWidgets.QPushButton(self)
        self.b1.setText("Start sniffing !")
        self.b1.clicked.connect(self.sniffer)
        self.tabb()
        self.table.cellClicked.connect(self.cell_was_clicked) 
        
        self.v_box.addWidget(self.b1)

        self.v_box.addWidget(self.table)



        #self.v_box.addLayout(self.h_box)

        self.w.setLayout(self.v_box)
        self.w.resize(437,600)
        
        self.w.show()

    def tabb(self):


        self.table = QtWidgets.QTableWidget(self)  # Create a table
        self.table.setColumnCount(4)     #Set 4 columns
        self.table.setRowCount(0)        

        # Set the table headers
        self.table.setHorizontalHeaderLabels(["DestMAC", "SrcMAC", "SrcIP", "type"])

        #Set the tooltips to headings
        self.table.horizontalHeaderItem(0).setToolTip("Column 1 ")
        self.table.horizontalHeaderItem(1).setToolTip("Column 2 ")
        self.table.horizontalHeaderItem(2).setToolTip("Column 3 ")
        self.table.horizontalHeaderItem(3).setToolTip("Column 4 ")


        self.table.resize(self.width(),self.height())
        # Set the alignment to the headers
        #self.table.horizontalHeaderItem(0).setTextAlignment(Qt.AlignLeft)
        #self.table.horizontalHeaderItem(1).setTextAlignment(Qt.AlignHCenter)
        #self.table.horizontalHeaderItem(2).setTextAlignment(Qt.AlignRight)


    def cell_was_clicked(self):
        print("////////cell_was_clicked/////////////")
        row = self.table.currentItem().row()
        print (row)
        col = self.table.currentItem().column()
        print (col)
        #print (type(col))
        self.item = self.table.horizontalHeaderItem(col).text()
        print (self.item)
        self.value = self.table.item(row, col).text()
        print (self.value)
        print(type(self.value))
        if self.item == "SrcIP":
            #test public or privet ip 
            ip = IP(self.value)
            print(ip.iptype())
            #depend on the output choose if public ==more detail else iptype output shown 
            if ip.iptype() == "PUBLIC": #public address 
                #print("acc tocken yaya   is      9b13288fba4a13")
                #https://ipinfo.io/account/search?query=8.8.8.8
                access_token = '9b13288fba4a13'
                handler = ipinfo.getHandler(access_token)
                ip_address = self.value
                details = handler.getDetails(ip_address)
                print(type(details.city))
                print(details.region)
                
                msg = QMessageBox()
                msg.setWindowTitle("More detail")
                msg.setIcon(QMessageBox.Information)               
                msg.setText('Ip:   '+str(details.ip)+L+'City:   '+str(details.city) +L+'Region:   '+str(details.region)+L+'Country:   '+str(details.country)+L+'Organization:   '+str(details.org)+L+'Location:   '+str(details.loc)+L+'Postal:   '+str(details.postal)+L+'Timezone:   '+str(details.timezone))
                
                x = msg.exec_()
                
            else:#privet or loopback  ip addss
                msg = QMessageBox()
                msg.setWindowTitle("More detail")
                msg.setIcon(QMessageBox.Information)
                msg.setText(ip.iptype())
                
                x = msg.exec_() 
        elif self.item == "type":#type of the packet  inner window info by classification 
                                 #self.d =>data non dcrpted
            msg = QMessageBox()
            msg.setWindowTitle("More detail")
            msg.setIcon(QMessageBox.Information)
            print (self.d)
            print(type(self.d))
            
            
            if str(self.value) == "ICMPpacket" :
                msg.setText(self.value+L+'Checksum :      '+str(self.chck)+L+'ICMP Code :      '+str(self.cd)+L+'ICMP Type :      '+str(self.t))
                #msg.setInformativeText(str(self.d))
                msg.setDetailedText('data :      '+str(self.d))

            elif str(self.value) == "TCPpacket" :
                msg.setText(self.value+L+'Source Port :      '+str(self.srcP)+L+'Destination Port:      '+str(self.destP)+L+'Sequence Number :      '+str(self.seq)+L+'Acknowledgment :      '+str(self.ack))
                msg.setDetailedText('Data :      '+str(self.d))

            elif str(self.value) == "TCP-HTTPpacket" :
                msg.setText(self.value+L+'Source Port :      '+str(self.srcP)+L+'Destination Port:      '+str(self.destP)+L+'Sequence Number :      '+str(self.seq)+L+'Acknowledgment :      '+str(self.ack))
                msg.setDetailedText(+'Data :      '+str(self.d))

            elif str(self.value) == "UDPpacket" :
                msg.setText(self.value+L+'Source Port:      '+str(self.srcP)+L+'Destination Port:      '+str(self.destP)+L+'Length:      '+str(self.len))
                msg.setDetailedText('Data:      '+str(self.d))
            
            else:
                msg.setText(self.value)
                msg.setDetailedText('Data:      '+str(self.d))

            x = msg.exec_()            

        else:#mac address inner window info by classification 
            if self.value=="00:00:00:00:00:00":

                msg = QMessageBox()
                msg.setWindowTitle("More detail")
                msg.setIcon(QMessageBox.Information)
                
                msg.setText(self.value +L+"ARP request")
                x = msg.exec_()
            elif self.value=="FF:FF:FF:FF:FF:FF":
 
                msg = QMessageBox()
                msg.setWindowTitle("More detail")
                msg.setIcon(QMessageBox.Information)
                
                msg.setText(self.value +L+"Broadcast MAC address")
                x = msg.exec_()
            else :
                
                self.macinfo(self.value)
                msg = QMessageBox()
                msg.setWindowTitle("More detail")
                msg.setIcon(QMessageBox.Information)
                msg.setText(self.value+L+'Address:      '+self.macaddress+L+'Company:      '+self.maccompany+L+'Start_hex:      '+self.macstart_hex+L+'End_hex:      '+self.macend_hex+L+'Type:      '+self.mactype)
                x = msg.exec_()
# sniffer function - create socket connect it end get data bytes - fragment -                

    def sniffer(self):
        #self.table.resizeColumnsToContents()
        #self.table.resizeRowsToContents()
        conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
        count = 0
        maxi = 2
        while (count < maxi):         
            self.table.insertRow(count)
            raw_data, addr = conn.recvfrom(65536)
            dest_mac, src_mac, eth_proto, data = ethernet_frame(raw_data)

            print('\n Ethernet Frame: ')
            print(TAB_1 + 'Destination: {}, Source: {}, Protocol: {}'.format(dest_mac, src_mac, eth_proto))
            
            self.table.setItem(count, 0, QTableWidgetItem(dest_mac))
            self.table.setItem(count, 1, QTableWidgetItem(src_mac))
            
    
            if eth_proto == 8:
                (version, header_length, ttl, proto, src, target, data) = ipv4_Packet(data)
                print(TAB_1 + "IPV4 Packet:")
                print(TAB_2 + 'Version: {}, Header Length: {}, TTL: {}'.format(version, header_length, ttl))
                print(TAB_3 + 'protocol: {}, Source: {}, Target: {}'.format(proto, src, target))
                
                self.table.setItem(count, 2, QTableWidgetItem(src))
                # ICMP
                if proto == 1:
                    icmp_type, code, checksum, data = icmp_packet(data)
                    print(TAB_1 + 'ICMP Packet:')
                    print(TAB_2 + 'Type: {}, Code: {}, Checksum: {},'.format(icmp_type, code, checksum))
                    print(TAB_2 + 'ICMP Data:')
                    print(format_output_line(DATA_TAB_3, data))
                    self.d = data
                    self.t = icmp_type
                    self.chck = checksum
                    self.cd = code 

                    self.table.setItem(count, 3, QTableWidgetItem("ICMPpacket"))

                # TCP
                elif proto == 6:
                    src_port, dest_port, sequence, acknowledgment, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin = struct.unpack(
                '! H H L L H H H H H H', raw_data[:24])
                    print(TAB_1 + 'TCP Segment:')
                    print(TAB_2 + 'Source Port: {}, Destination Port: {}'.format(src_port, dest_port))
                    print(TAB_2 + 'Sequence: {}, Acknowledgment: {}'.format(sequence, acknowledgment))
                    print(TAB_2 + 'Flags:')
                    print(TAB_3 + 'URG: {}, ACK: {}, PSH: {}'.format(flag_urg, flag_ack, flag_psh))
                    print(TAB_3 + 'RST: {}, SYN: {}, FIN:{}'.format(flag_rst, flag_syn, flag_fin))
                    self.srcP = src_port
                    self.destP = dest_port
                    self.seq = sequence
                    self.ack = acknowledgment
                    
                    self.table.setItem(count, 3, QTableWidgetItem("TCPpacket"))
                    if len(data) > 0:
                        # HTTP
                        if src_port == 80 or dest_port == 80:
                            print(TAB_2 + 'HTTP Data:')
                            self.table.setItem(count, 3, QTableWidgetItem("TCP-HTTPpacket"))
                            try:
                                http = HTTP(data)
                                http_info = str(http.data).split('\n')
                                for line in http_info:
                                    print(DATA_TAB_3 + str(line))
                                    ####### data as list of lines !!!!!!!1

                            except:
                                print(format_output_line(DATA_TAB_3, data))
                                self.d = data
                        else:
                            print(TAB_2 + 'TCP Data:')
                            print(format_output_line(DATA_TAB_3, data))
                            self.d = data
                # UDP
                elif proto == 17:
                    self.table.setItem(count, 3, QTableWidgetItem("UDPpacket"))
                    src_port, dest_port, length, data = udp_seg(data)
                    self.d = data
                    print(TAB_1 + 'UDP Segment:')
                    print(TAB_2 + 'Source Port: {}, Destination Port: {}, Length: {}'.format(src_port, dest_port, length))
                    self.srcP = src_port
                    self.destP = dest_port
                    self.len = length
                    

                # Other IPv4
                else:
                    print(TAB_1 + 'Other IPv4 Data:')
                    print(format_output_line(DATA_TAB_2, data))
                    self.d = data
                    self.table.setItem(count, 3, QTableWidgetItem("null"))

            else:
                self.table.setItem(count, 3, QTableWidgetItem("other"))
                print('Ethernet Data:')
                print(format_output_line(DATA_TAB_1, data))
                self.d = data
            print('counter is :   ')
            print(count)
            count = count +1
#function that return mac address info 
    def macinfo(self,mc):
        #API base url,you can also use https if you need
        url = "http://macvendors.co/api/"
        #Mac address to lookup vendor from
        mac_address = mc
        request = urllib2.Request(url+mac_address, headers={'User-Agent' : "API Browser"}) 
        response = urllib2.urlopen( request )
        #Fix: json object must be str, not 'bytes'
        reader = codecs.getreader("utf-8")
        obj = json.load(reader(response))

        #Print company name
        #print (obj['result']['company']+"<br/>");
        #print company address
        #print (obj['result']['address']);
        #print('test MAC INFO output')
        #print (type(obj['result']))
        #print (obj['result'])
        
        self.maccompany = obj['result']['company']
        self.macaddress = obj['result']['address']
        self.macstart_hex = obj['result']['start_hex']
        self.macend_hex = obj['result']['end_hex']
        self.maccountry = obj['result']['country']
        self.mactype =  obj['result']['type']
        #print(type(self.macaddress))
        #return info as list 

        return ['result']

       


def window():
    app = QtWidgets.QApplication(sys.argv)
    win = MyWindow()
    win.show()
    sys.exit(app.exec_())

if __name__ == '__main__':
     window()
