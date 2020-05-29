from PyQt5 import QtWidgets
from PyQt5.QtWidgets import QApplication, QGridLayout, QMainWindow, QLabel, QWidget, QAction, QTableWidget,QTableWidgetItem,QVBoxLayout ,QHBoxLayout,QGroupBox
from PyQt5.QtGui import QIcon
from PyQt5.QtCore import pyqtSlot, QSize, Qt
from PyQt5 import QtGui

import sys
import socket
import struct
import textwrap

TAB_1 = '\t - '
TAB_2 = '\t\t - '
TAB_3 = '\t\t\t - '
TAB_4 = '\t\t\t\t - '

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
        #self.setGeometry(0,0,1500,1000)
        #self.setWindowTitle("Tech With Tim")
        self.w = QtWidgets.QWidget()

        self.v_box = QtWidgets.QVBoxLayout()
        #self.h_box=QtWidgets.QHBoxLayout()


        #self.label = QtWidgets.QLabel(self)
        #self.label.setText("my first label!")


        self.b1 = QtWidgets.QPushButton(self)
        self.b1.setText("Start sniffing !")
        self.b1.clicked.connect(self.sniffer)
        self.tabb()
        self.table.cellClicked.connect(self.cell_was_clicked) 
        
        self.v_box.addWidget(self.b1)
        #self.h_box.addStretch()
        self.v_box.addWidget(self.table)
        #self.h_box.addStretch()


        #self.v_box.addLayout(self.h_box)

        self.w.setLayout(self.v_box)
        self.w.resize(500,500)
        self.w.show()

    def tabb(self):


        self.table = QtWidgets.QTableWidget(self)  # Create a table
        self.table.setColumnCount(4)     #Set three columns
        self.table.setRowCount(0)        # and one row
        # Do the resize of the columns by content

        #self.table.resizeRowsToContents()
 
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
        self.item = self.table.horizontalHeaderItem(col).text()
        print (self.item)
        self.value = self.table.item(row, col).text()
        print (self.value)
        return self.item
 



 



    def sniffer(self):
        #self.table.resizeColumnsToContents()
        #self.table.resizeRowsToContents()
        conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
        count = 0
        maxi = 2
        while (count < maxi):
 
            #print(self.w.tableWidget.item(self.w.tableWidget.currentRow(),count ))          
            self.table.insertRow(count)
            raw_data, addr = conn.recvfrom(65536)
            dest_mac, src_mac, eth_proto, data = ethernet_frame(raw_data)
            #self.label.setText(dest_mac)
            #self.label.setText(" Ethernet Frame: ")
            print('\n Ethernet Frame: ')
            print(TAB_1 + 'Destination: {}, Source: {}, Protocol: {}'.format(dest_mac, src_mac, eth_proto))
            #add ethernet item into the table dest_mac, src_mac, eth_proto
                    # Fill the first line
            self.table.setItem(count, 0, QTableWidgetItem(dest_mac))
            self.table.setItem(count, 1, QTableWidgetItem(src_mac))
            
    
            if eth_proto == 8:
                (version, header_length, ttl, proto, src, target, data) = ipv4_Packet(data)
                print(TAB_1 + "IPV4 Packet:")
                print(TAB_2 + 'Version: {}, Header Length: {}, TTL: {}'.format(version, header_length, ttl))
                print(TAB_3 + 'protocol: {}, Source: {}, Target: {}'.format(proto, src, target))
                #add ethernet item into the table version, header_length, ttl, proto, src, target, 
                self.table.setItem(count, 2, QTableWidgetItem(src))
                # ICMP
                if proto == 1:
                    icmp_type, code, checksum, data = icmp_packet(data)
                    print(TAB_1 + 'ICMP Packet:')
                    print(TAB_2 + 'Type: {}, Code: {}, Checksum: {},'.format(icmp_type, code, checksum))
                    print(TAB_2 + 'ICMP Data:')
                    print(format_output_line(DATA_TAB_3, data))
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

                            except:
                                print(format_output_line(DATA_TAB_3, data))
                        else:
                            print(TAB_2 + 'TCP Data:')
                            print(format_output_line(DATA_TAB_3, data))
                # UDP
                elif proto == 17:
                    self.table.setItem(count, 3, QTableWidgetItem("UDPpacket"))
                    src_port, dest_port, length, data = udp_seg(data)
                    print(TAB_1 + 'UDP Segment:')
                    print(TAB_2 + 'Source Port: {}, Destination Port: {}, Length: {}'.format(src_port, dest_port, length))

                # Other IPv4
                else:
                    print(TAB_1 + 'Other IPv4 Data:')
                    print(format_output_line(DATA_TAB_2, data))
                    self.table.setItem(count, 3, QTableWidgetItem("null"))

            else:
                self.table.setItem(count, 3, QTableWidgetItem("other"))
                print('Ethernet Data:')
                print(format_output_line(DATA_TAB_1, data))
            print('counter is :   ')
            print(count)
            count = count +1



def window():
    app = QtWidgets.QApplication(sys.argv)
    win = MyWindow()
    win.show()
    sys.exit(app.exec_())

if __name__ == '__main__':
     window()
