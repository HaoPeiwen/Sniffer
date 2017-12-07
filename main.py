import sys, string, platform, time, threading
from PyQt5 import QtCore, QtWidgets, QtGui
from ctypes import *
from winpcapy import *
from readPackets import *

#pyuic5 -o s.py sniffergui.ui

class Parameter():
    #常量定义
    def __init__(self):
        self.ListenFlag = 1
        self.RANK = 0  # 当前包最大索引数
        self.selectRANK = 0  # 所选包索引
        self.tmpRANK = 0  # 遍历用索引
        self.LINE_LEN = 16
        self.alldevs = POINTER(pcap_if_t)()
        self.d = POINTER(pcap_if_t)
        self.fp = pcap_t
        self.errbuf = create_string_buffer(PCAP_ERRBUF_SIZE)
        self.header = POINTER(pcap_pkthdr)()
        self.pkt_data = POINTER(c_ubyte)()
        self.deviceNumber = 0
        self.NtwkIf = [] # 网卡列表
        self.packet = [] # 所有抓到包的二维列表
        self.showpacket = [] # 每次显示的一个包
        self.filterlist = []
    
    def reinitial(self):
        self.RANK = 0  # 当前包最大索引数
        self.selectRANK = 0  # 所选包索引
        self.tmpRANK = 0  # 遍历用索引
        self.LINE_LEN = 16
        self.d = POINTER(pcap_if_t)
        self.fp = pcap_t
        self.header = POINTER(pcap_pkthdr)()
        self.pkt_data = POINTER(c_ubyte)()
        self.packet = []  # 所有抓到包的二维列表
        self.showpacket = []  # 每次显示的一个包
        self.filterlist = []

#输出适配器列表
para = Parameter() # 实例调用

#打印设备函数
def printDevices():
    if (pcap_findalldevs(byref(para.alldevs), para.errbuf) == -1):
        print("寻找适配器出错: %s\n", para.errbuf.value)
        sys.exit(1)
    ## Print the list
    d = para.alldevs.contents
    while d:
        para.deviceNumber = para.deviceNumber + 1
        if (d.description):
            para.NtwkIf.append(str(d.description)[2:-1])
        if d.next:
             d = d.next.contents
        else:
             d = False
    if (para.deviceNumber == 0):
        print("\n没有找到相关的网络接口，请确保WinPcap已经安装！\n")
        sys.exit(-1)


class Ui_SnifferGUI(QtWidgets.QMainWindow):
    def __init__(self):
        super().__init__()
        self.setupUi(self)

    def setupUi(self, SnifferGUI):
        SnifferGUI.setObjectName("SnifferGUI")
        SnifferGUI.resize(1250, 860)
        self.centralwidget = QtWidgets.QWidget(SnifferGUI)
        self.centralwidget.setObjectName("centralwidget")
        self.comboBox = QtWidgets.QComboBox(self.centralwidget)
        self.comboBox.setGeometry(QtCore.QRect(90, 20, 351, 21))
        self.comboBox.setObjectName("comboBox")
        self.comboBox.addItem("NetworkInterface")
        self.label = QtWidgets.QLabel(self.centralwidget)
        self.label.setGeometry(QtCore.QRect(30, 20, 61, 21))
        self.label.setObjectName("label")
        self.label_2 = QtWidgets.QLabel(self.centralwidget)
        self.label_2.setGeometry(QtCore.QRect(30, 60, 61, 21))
        self.label_2.setObjectName("label_2")
        self.lineEdit = QtWidgets.QLineEdit(self.centralwidget)
        self.lineEdit.setGeometry(QtCore.QRect(90, 60, 261, 21))
        self.lineEdit.setObjectName("lineEdit")
        self.lineEdit_filter = QtWidgets.QLineEdit(self.centralwidget)
        self.lineEdit_filter.setGeometry(QtCore.QRect(670, 60, 491, 21))
        self.lineEdit_filter.setObjectName("lineEdit_filter")
        self.pushButton_sniff = QtWidgets.QPushButton(self.centralwidget)
        self.pushButton_sniff.setGeometry(QtCore.QRect(470, 20, 71, 23))
        self.pushButton_sniff.setObjectName("pushButton_sniff")
        self.pushButton_filter = QtWidgets.QPushButton(self.centralwidget)
        self.pushButton_filter.setGeometry(QtCore.QRect(370, 60, 71, 22))
        self.pushButton_filter.setObjectName("pushButton_filter")
        self.pushButton_stop = QtWidgets.QPushButton(self.centralwidget)
        self.pushButton_stop.setGeometry(QtCore.QRect(570, 20, 71, 23))
        self.pushButton_stop.setObjectName("pushButton_stop")
        self.pushButton_return = QtWidgets.QPushButton(self.centralwidget)
        self.pushButton_return.setGeometry(QtCore.QRect(470, 60, 71, 23))
        self.pushButton_return.setObjectName("pushButton_return")
        self.pushButton_save = QtWidgets.QPushButton(self.centralwidget)
        self.pushButton_save.setGeometry(QtCore.QRect(670, 20, 71, 23))
        self.pushButton_save.setObjectName("pushButton_save")
        self.pushButton_reassemble = QtWidgets.QPushButton(self.centralwidget)
        self.pushButton_reassemble.setGeometry(QtCore.QRect(770, 20, 71, 23))
        self.pushButton_reassemble.setObjectName("pushButton_reassemble")
        self.commandLinkButton = QtWidgets.QCommandLinkButton(self.centralwidget)
        self.commandLinkButton.setGeometry(QtCore.QRect(560, 50, 90, 41))
        self.commandLinkButton.setObjectName("commandLinkButton")
        self.treeWidget = QtWidgets.QTreeWidget(self.centralwidget)
        self.treeWidget.setGeometry(QtCore.QRect(30, 100, 1181, 421))
        self.treeWidget.setObjectName("treeWidget")
        self.tabWidget_Details = QtWidgets.QTabWidget(self.centralwidget)
        self.tabWidget_Details.setGeometry(QtCore.QRect(30, 540, 501, 261))
        self.tabWidget_Details.setObjectName("tabWidget_Details")
        self.tab_Ethernet = QtWidgets.QWidget()
        self.tab_Ethernet.setObjectName("tab_Ethernet")
        self.listWidget = QtWidgets.QListWidget(self.tab_Ethernet)
        self.listWidget.setGeometry(QtCore.QRect(0, 0, 501, 241))
        self.listWidget.setObjectName("listWidget")
        self.tabWidget_Details.addTab(self.tab_Ethernet, "")
        self.tab_IP = QtWidgets.QWidget()
        self.tab_IP.setObjectName("tab_IP")
        self.listWidget_IP = QtWidgets.QListWidget(self.tab_IP)
        self.listWidget_IP.setGeometry(QtCore.QRect(0, 0, 501, 241))
        self.listWidget_IP.setObjectName("listWidget_IP")
        item = QtWidgets.QListWidgetItem()
        font = QtGui.QFont()
        font.setPointSize(10)
        item.setFont(font)
        self.listWidget_IP.addItem(item)
        self.tabWidget_Details.addTab(self.tab_IP, "")
        self.tab_Protocol = QtWidgets.QWidget()
        self.tab_Protocol.setObjectName("tab_Protocol")
        self.listWidget_Protocol = QtWidgets.QListWidget(self.tab_Protocol)
        self.listWidget_Protocol.setGeometry(QtCore.QRect(0, 0, 501, 241))
        self.listWidget_Protocol.setObjectName("listWidget_Protocol")
        item = QtWidgets.QListWidgetItem()
        font = QtGui.QFont()
        font.setPointSize(10)
        item.setFont(font)
        self.listWidget_Protocol.addItem(item)
        self.tabWidget_Details.addTab(self.tab_Protocol, "")
        self.tabWidget_Reassemble = QtWidgets.QTabWidget(self.centralwidget)
        self.tabWidget_Reassemble.setGeometry(QtCore.QRect(560, 540, 651, 261))
        self.tabWidget_Reassemble.setObjectName("tabWidget_Reassemble")
        self.tab_String = QtWidgets.QWidget()
        self.tab_String.setObjectName("tab_String")
        self.textBrowser_String = QtWidgets.QTextBrowser(self.tab_String)
        self.textBrowser_String.setGeometry(QtCore.QRect(0, 0, 651, 241))
        font = QtGui.QFont()
        font.setFamily("Consolas")
        font.setBold(False)
        font.setPixelSize(15)
        font.setWeight(50)
        self.textBrowser_String.setFont(font)
        self.textBrowser_String.setObjectName("textBrowser_String")
        self.tabWidget_Reassemble.addTab(self.tab_String, "")
        self.tab_HEX = QtWidgets.QWidget()
        self.tab_HEX.setObjectName("tab_HEX")
        self.textBrowser_HEX = QtWidgets.QTextBrowser(self.tab_HEX)
        self.textBrowser_HEX.setGeometry(QtCore.QRect(0, 0, 651, 241))
        font = QtGui.QFont()
        font.setFamily("Consolas")
        font.setBold(False)
        font.setPixelSize(15)
        font.setWeight(50)
        self.textBrowser_HEX.setFont(font)
        self.textBrowser_HEX.setObjectName("textBrowser_HEX")
        self.tabWidget_Reassemble.addTab(self.tab_HEX, "")
        self.tab_GBK = QtWidgets.QWidget()
        self.tab_GBK.setObjectName("tab_GBK")
        self.textBrowser_GBK = QtWidgets.QTextBrowser(self.tab_GBK)
        self.textBrowser_GBK.setGeometry(QtCore.QRect(0, 0, 651, 241))
        font = QtGui.QFont()
        font.setFamily("Consolas")
        font.setBold(False)
        font.setPixelSize(15)
        font.setWeight(50)
        self.textBrowser_GBK.setFont(font)
        self.textBrowser_GBK.setObjectName("textBrowser_GBK")
        self.tabWidget_Reassemble.addTab(self.tab_GBK, "")
        self.tab_UTF8 = QtWidgets.QWidget()
        self.tab_UTF8.setObjectName("tab_UTF8")
        self.textBrowser_UTF8 = QtWidgets.QTextBrowser(self.tab_UTF8)
        self.textBrowser_UTF8.setGeometry(QtCore.QRect(0, 0, 651, 241))
        font = QtGui.QFont()
        font.setFamily("Consolas")
        font.setBold(False)
        font.setPixelSize(15)
        font.setWeight(50)
        self.textBrowser_UTF8.setFont(font)
        self.textBrowser_UTF8.setObjectName("textBrowser_UTF8")
        self.tabWidget_Reassemble.addTab(self.tab_UTF8, "")
        SnifferGUI.setCentralWidget(self.centralwidget)
        self.menubar = QtWidgets.QMenuBar(SnifferGUI)
        self.menubar.setGeometry(QtCore.QRect(0, 0, 1250, 23))
        self.menubar.setObjectName("menubar")
        self.menu_files = QtWidgets.QMenu(self.menubar)
        self.menu_files.setObjectName("menu_files")
        self.menu_edit = QtWidgets.QMenu(self.menubar)
        self.menu_edit.setObjectName("menu_edit")
        self.menu_tools = QtWidgets.QMenu(self.menubar)
        self.menu_tools.setObjectName("menu_tools")
        SnifferGUI.setMenuBar(self.menubar)
        self.statusbar = QtWidgets.QStatusBar(SnifferGUI)
        self.statusbar.setObjectName("statusbar")
        SnifferGUI.setStatusBar(self.statusbar)
        self.statusbar.showMessage('Powered by Evander & Xynnn_')
        self.actionOpen_File = QtWidgets.QAction(SnifferGUI)
        self.actionOpen_File.setObjectName("actionOpen_File")
        self.actionSave_File = QtWidgets.QAction(SnifferGUI)
        self.actionSave_File.setObjectName("actionSave_File")
        self.actionpass = QtWidgets.QAction(SnifferGUI)
        self.actionpass.setObjectName("actionpass")
        self.actionpass_2 = QtWidgets.QAction(SnifferGUI)
        self.actionpass_2.setObjectName("actionpass_2")
        self.menu_files.addAction(self.actionOpen_File)
        self.menu_files.addAction(self.actionSave_File)
        self.menu_edit.addAction(self.actionpass_2)
        self.menu_tools.addAction(self.actionpass)
        self.menubar.addAction(self.menu_files.menuAction())
        self.menubar.addAction(self.menu_edit.menuAction())
        self.menubar.addAction(self.menu_tools.menuAction())
        self.retranslateUi(SnifferGUI)
        self.tabWidget_Details.setCurrentIndex(0)
        self.tabWidget_Reassemble.setCurrentIndex(0)
        self.pushButton_sniff.clicked.connect(threadlisten)
        self.pushButton_stop.clicked.connect(SniffStop)
        self.pushButton_filter.clicked.connect(Filter)
        self.comboBox.currentIndexChanged.connect(ChangeIface)
        self.treeWidget.itemClicked.connect(self.ShowDetails)
        self.pushButton_save.clicked.connect(self.SavePacket2File)
        #self.pushButton_return.clicked.connect(backsearch)
        self.pushButton_reassemble.clicked.connect(self.resembleFragments)
        QtCore.QMetaObject.connectSlotsByName(SnifferGUI)

    def retranslateUi(self, SnifferGUI):
        _translate = QtCore.QCoreApplication.translate
        SnifferGUI.setWindowTitle(_translate("SnifferGUI", "Sniffer 1.0"))
        self.comboBox.setItemText(0, _translate("SnifferGUI", "请选择网卡"))
        self.AddIface()
        self.label.setText(_translate("SnifferGUI", "<html><head/><body><p>网卡接口</p></body></html>"))
        self.label_2.setText(_translate("SnifferGUI", "<html><head/><body><p>包过滤</p></body></html>"))
        self.pushButton_sniff.setToolTip(_translate("SnifferGUI", "<html><head/><body><p>开始抓取</p></body></html>"))
        self.pushButton_sniff.setText(_translate("SnifferGUI", "开始抓包"))
        self.pushButton_filter.setText(_translate("SnifferGUI", "搜索"))
        self.pushButton_stop.setText(_translate("SnifferGUI", "停止抓包"))
        self.pushButton_return.setText(_translate("SnifferGUI", "返回"))
        self.commandLinkButton.setText(_translate("SnifferGUI", "包过滤"))
        self.pushButton_save.setText(_translate("SnifferGUI", "保存"))
        self.pushButton_reassemble.setText(_translate("SnifferGUI", "重组"))
        self.treeWidget.headerItem().setText(0, _translate("SnifferGUI", "编号"))
        self.treeWidget.headerItem().setText(1, _translate("SnifferGUI", "源IP地址"))
        self.treeWidget.headerItem().setText(2, _translate("SnifferGUI", "目的IP地址"))
        self.treeWidget.headerItem().setText(3, _translate("SnifferGUI", "协议"))
        self.treeWidget.headerItem().setText(4, _translate("SnifferGUI", "帧长"))
        self.treeWidget.headerItem().setText(5, _translate("SnifferGUI", "日期"))
        self.treeWidget.headerItem().setText(6, _translate("SnifferGUI", "时间"))
        self.treeWidget.headerItem().setText(7, _translate("SnifferGUI", "信息"))
        # self.treeWidget.header().setSectionResizeMode(0, QtWidgets.QHeaderView.resizeSection(QHeaderView,10)) #锁定长度
        self.treeWidget.header().setSectionResizeMode(3, QtWidgets.QHeaderView.ResizeToContents)
        self.treeWidget.header().setSectionResizeMode(4, QtWidgets.QHeaderView.ResizeToContents)
        self.treeWidget.header().setSectionResizeMode(5, QtWidgets.QHeaderView.ResizeToContents)
        __sortingEnabled = self.treeWidget.isSortingEnabled()
        self.treeWidget.setSortingEnabled(False)
        self.treeWidget.setSortingEnabled(__sortingEnabled)
        __sortingEnabled = self.listWidget.isSortingEnabled()
        self.listWidget.setSortingEnabled(False)
        self.listWidget.setSortingEnabled(__sortingEnabled)
        self.tabWidget_Details.setTabText(self.tabWidget_Details.indexOf(self.tab_Ethernet),
                                          _translate("SnifferGUI", "Ethernet"))
        __sortingEnabled = self.listWidget_IP.isSortingEnabled()
        self.listWidget_IP.setSortingEnabled(False)
        self.listWidget_IP.setSortingEnabled(__sortingEnabled)
        self.tabWidget_Details.setTabText(self.tabWidget_Details.indexOf(self.tab_IP),
                                          _translate("SnifferGUI", "IP"))
        __sortingEnabled = self.listWidget_Protocol.isSortingEnabled()
        self.listWidget_Protocol.setSortingEnabled(False)
        self.listWidget_Protocol.setSortingEnabled(__sortingEnabled)
        self.tabWidget_Details.setTabText(self.tabWidget_Details.indexOf(self.tab_Protocol),
                                          _translate("SnifferGUI", "Protocol"))
        self.tabWidget_Reassemble.setTabText(self.tabWidget_Reassemble.indexOf(self.tab_String),
                                             _translate("SnifferGUI", "String"))
        self.tabWidget_Reassemble.setTabText(self.tabWidget_Reassemble.indexOf(self.tab_HEX),
                                             _translate("SnifferGUI", "<HEX重组>"))
        self.tabWidget_Reassemble.setTabText(self.tabWidget_Reassemble.indexOf(self.tab_GBK),
                                             _translate("SnifferGUI", "<GBK编码>"))
        self.tabWidget_Reassemble.setTabText(self.tabWidget_Reassemble.indexOf(self.tab_UTF8),
                                             _translate("SnifferGUI", "<UTF-8重组>"))
        self.menu_files.setTitle(_translate("SnifferGUI", "文件"))
        self.menu_edit.setTitle(_translate("SnifferGUI", "编辑"))
        self.menu_tools.setTitle(_translate("SnifferGUI", "工具"))
        self.actionOpen_File.setText(_translate("SnifferGUI", "Open File"))
        self.actionOpen_File.setShortcut(_translate("SnifferGUI", "Ctrl+O"))
        self.actionSave_File.setText(_translate("SnifferGUI", "Save File"))
        self.actionSave_File.setShortcut(_translate("SnifferGUI", "Ctrl+S"))
        self.actionpass.setText(_translate("SnifferGUI", "pass"))
        self.actionpass_2.setText(_translate("SnifferGUI", "Clear"))
        self.actionpass_2.setShortcut(_translate("SnifferGUI", "Ctrl+L"))

    # 将标号为n的包存储下来，命名格式为 当前时间.pcap
    def SavePacket2File(self):
        para.selectRANK = int(self.treeWidget.selectedItems()[0].text(0)) -1
        #索引值

        ## 打开缓存文件
        para.fp = pcap_open_offline("temp".encode("utf-8"), para.errbuf)

        #打开存储目标文件
        readFilename = ("%s.pcap" % time.asctime()).replace(":","-")
        para.DUMPFILE = pcap_dump_open(para.fp,readFilename.encode("utf-8"))
        rank = 0

        ## 读取并找寻到相关标号，提取保存
        res = pcap_next_ex(para.fp, byref(para.header), byref(para.pkt_data))
        while (res >= 0):
            if (rank == para.selectRANK):
                pcap_dump(para.DUMPFILE, para.header, para.pkt_data)
                break
            else:
                rank += 1
                res = pcap_next_ex(para.fp, byref(para.header), byref(para.pkt_data))
        pcap_dump_close(para.DUMPFILE)
        pcap_close(para.fp)

    def resembleFragments(self):
        # 首先分析哪些相关包能够重组
        ## Open the capture file
        pkt_index = int(self.treeWidget.selectedItems()[0].text(0))  -1 # 得到索引值
        if self.lineEdit.text() == '':
            id = para.packet[pkt_index][7]
        else:
            id = para.filterlist[pkt_index][7]
        PktDataHex = ""
        #print (id)
        PktLst = []
        PktDataANSI = ""
        for packets in para.packet:
            print ("")
            if (len(packets)<8):
                pass
            elif ((packets[2] == "IPv4" )and (packets[7] == id )):
                print(packets[7])
                PktLst.append((packets[-3],packets[-4],packets[10]))
        print (PktLst)
        PktLst = sorted(PktLst, key=lambda x: int(x[2]))
        ##加工一下
        for fragments in PktLst:
            print(fragments)
            PktDataANSI = PktDataANSI + fragments[0][34:]
            print('111')
            PktDataHex = PktDataHex + fragments[1][102:]
            print('222')
        return [PktDataHex, PktDataANSI]
        #print (PktDataHex)
        #print (PktDataANSI)

    def AddIface(self): # 在列表中添加网卡名
        _translate = QtCore.QCoreApplication.translate
        count = 1
        for inface in para.NtwkIf:
            self.comboBox.addItem("")
            self.comboBox.setItemText(count, _translate("SnifferGUI", inface))
            count += 1

    def ShowDetails(self):
        self.listWidget.clear()
        self.listWidget_IP.clear()
        self.listWidget_Protocol.clear()
        if self.lineEdit.text() == '':
            pktlis = para.packet
        else:
            pktlis = para.filterlist
        _translate = QtCore.QCoreApplication.translate
        pktindex = int(self.treeWidget.selectedItems()[0].text(0)) -1 # 得到索引值

        ShowString(pktlis, pktindex)  # 显示string
        # Ethernet 详细信息显示：

        self.listWidget.addItem(QtWidgets.QListWidgetItem())
        self.listWidget.item(0).setText(_translate("SnifferGUI", "目的MAC: " + pktlis[pktindex][0]))


        self.listWidget.addItem(QtWidgets.QListWidgetItem())
        self.listWidget.item(1).setText(_translate("SnifferGUI", "源MAC: " + pktlis[pktindex][1]))


        self.listWidget.addItem(QtWidgets.QListWidgetItem())
        self.listWidget.item(2).setText(_translate("SnifferGUI", "协议名: " + pktlis[pktindex][2]))



        if pktlis[pktindex][2] == 'ARP' :
            self.tabWidget_Details.setTabText(self.tabWidget_Details.indexOf(
                self.tab_Protocol), _translate("SnifferGUI", "ARP"))
            self.listWidget_Protocol.addItem(QtWidgets.QListWidgetItem())
            self.listWidget_Protocol.item(0).setText(_translate(
                "SnifferGUI", "硬件类型: " + pktlis[pktindex][3]))
            self.listWidget_Protocol.addItem(QtWidgets.QListWidgetItem())
            self.listWidget_Protocol.item(1).setText(_translate(
                "SnifferGUI", "协议类型: " + pktlis[pktindex][4]))
            self.listWidget_Protocol.addItem(QtWidgets.QListWidgetItem())
            self.listWidget_Protocol.item(2).setText(_translate(
                "SnifferGUI", "硬件地址长度: " + pktlis[pktindex][5]))
            self.listWidget_Protocol.addItem(QtWidgets.QListWidgetItem())
            self.listWidget_Protocol.item(3).setText(_translate(
                "SnifferGUI", "协议地址长度: " + pktlis[pktindex][6]))
            self.listWidget_Protocol.addItem(QtWidgets.QListWidgetItem())
            self.listWidget_Protocol.item(4).setText(_translate(
                "SnifferGUI", "操作: " + pktlis[pktindex][7]))
            self.listWidget_Protocol.addItem(QtWidgets.QListWidgetItem())
            self.listWidget_Protocol.item(5).setText(
                _translate("SnifferGUI", "发送者硬件地址: " + pktlis[pktindex][8]))
            self.listWidget_Protocol.addItem(QtWidgets.QListWidgetItem())
            self.listWidget_Protocol.item(6).setText(
                _translate("SnifferGUI", "发送者IP地址: " + pktlis[pktindex][9]))
            self.listWidget_Protocol.addItem(QtWidgets.QListWidgetItem())
            self.listWidget_Protocol.item(7).setText(
                _translate("SnifferGUI", "接受者硬件地址: " + pktlis[pktindex][10]))
            self.listWidget_Protocol.addItem(QtWidgets.QListWidgetItem())
            self.listWidget_Protocol.item(8).setText(
                _translate("SnifferGUI", "接受者IP地址: " + pktlis[pktindex][11]))
            self.listWidget_Protocol.addItem(QtWidgets.QListWidgetItem())
            if pktlis[pktindex][7] == "ARP请求":
                self.listWidget_Protocol.item(9).setText(
                    _translate("SnifferGUI", "信息:谁是 " + pktlis[pktindex][11] + "?请站出来告诉" + pktlis[pktindex][9]))
            elif pktlis[pktindex][7] == "ARP回显":
                self.listWidget_Protocol.item(9).setText(
                    _translate("SnifferGUI", "信息:我是 " + pktlis[pktindex][9] + "，我的MAC是" + pktlis[pktindex][8]))

        elif pktlis[pktindex][2] == 'RARP':
            self.tabWidget_Details.setTabText(self.tabWidget_Details.indexOf(
                self.tab_Protocol), _translate("SnifferGUI", "RARP"))
            self.listWidget_Protocol.addItem(QtWidgets.QListWidgetItem())
            self.listWidget_Protocol.item(0).setText(_translate(
                "SnifferGUI", "硬件类型: " + pktlis[pktindex][3]))
            self.listWidget_Protocol.addItem(QtWidgets.QListWidgetItem())
            self.listWidget_Protocol.item(1).setText(_translate(
                "SnifferGUI", "协议类型: " + pktlis[pktindex][4]))
            self.listWidget_Protocol.addItem(QtWidgets.QListWidgetItem())
            self.listWidget_Protocol.item(2).setText(_translate(
                "SnifferGUI", "硬件地址长度: " + pktlis[pktindex][5]))
            self.listWidget_Protocol.addItem(QtWidgets.QListWidgetItem())
            self.listWidget_Protocol.item(3).setText(_translate(
                "SnifferGUI", "协议地址长度: " + pktlis[pktindex][6]))
            self.listWidget_Protocol.addItem(QtWidgets.QListWidgetItem())
            self.listWidget_Protocol.item(4).setText(_translate(
                "SnifferGUI", "操作: " + pktlis[pktindex][7]))
            self.listWidget_Protocol.addItem(QtWidgets.QListWidgetItem())
            self.listWidget_Protocol.item(5).setText(
                _translate("SnifferGUI", "发送者硬件地址: " + pktlis[pktindex][8]))
            self.listWidget_Protocol.addItem(QtWidgets.QListWidgetItem())
            self.listWidget_Protocol.item(6).setText(
                _translate("SnifferGUI", "发送者IP地址: " + pktlis[pktindex][9]))
            self.listWidget_Protocol.addItem(QtWidgets.QListWidgetItem())
            self.listWidget_Protocol.item(7).setText(
                _translate("SnifferGUI", "接受者硬件地址: " + pktlis[pktindex][10]))
            self.listWidget_Protocol.addItem(QtWidgets.QListWidgetItem())
            self.listWidget_Protocol.item(8).setText(
                _translate("SnifferGUI", "接受者IP地址: " + pktlis[pktindex][11]))
            self.listWidget_Protocol.addItem(QtWidgets.QListWidgetItem())
            if pktlis[pktindex][7] == "RARP请求":
                self.listWidget_Protocol.item(9).setText(
                    _translate("SnifferGUI", "信息:我是" + pktlis[pktindex][8] + "，请分配给我一个IP地址！"))
            elif pktlis[pktindex][7] == "RARP应答":
                self.listWidget_Protocol.item(9).setText(
                    _translate("SnifferGUI", "信息:亲爱的" + pktlis[pktindex][10] + "你好！你的IP地址是" + pktlis[pktindex][11]))

        elif pktlis[pktindex][2] == 'IPv6':
            self.tabWidget_Details.setTabText(self.tabWidget_Details.indexOf(
                self.tab_IP), _translate("SnifferGUI", "IPv6"))
            self.listWidget_IP.addItem(QtWidgets.QListWidgetItem())
            self.listWidget_IP.item(0).setText(_translate(
                "SnifferGUI", "IP协议版本: " + pktlis[pktindex][3]))
            self.listWidget_IP.addItem(QtWidgets.QListWidgetItem())
            self.listWidget_IP.item(1).setText(_translate(
                "SnifferGUI", "优先级: " + str(pktlis[pktindex][4])))
            self.listWidget_IP.addItem(QtWidgets.QListWidgetItem())
            self.listWidget_IP.item(2).setText(_translate(
                "SnifferGUI", "流量标识: " + pktlis[pktindex][5]))
            self.listWidget_IP.addItem(QtWidgets.QListWidgetItem())
            self.listWidget_IP.item(3).setText(_translate(
                "SnifferGUI", "载荷长度: " + str(pktlis[pktindex][6])))
            self.listWidget_IP.addItem(QtWidgets.QListWidgetItem())
            self.listWidget_IP.item(4).setText(_translate(
                "SnifferGUI", "下一包头: " + str(pktlis[pktindex][7])))
            self.listWidget_IP.addItem(QtWidgets.QListWidgetItem())
            self.listWidget_IP.item(5).setText(
                _translate("SnifferGUI", "跳数限制: " + str(pktlis[pktindex][8])))
            self.listWidget_IP.addItem(QtWidgets.QListWidgetItem())
            self.listWidget_IP.item(6).setText(
                _translate("SnifferGUI", "源地址: " + pktlis[pktindex][9]))
            self.listWidget_IP.addItem(QtWidgets.QListWidgetItem())
            self.listWidget_IP.item(7).setText(
                _translate("SnifferGUI", "目的地址: " + pktlis[pktindex][10]))

        elif len(pktlis[pktindex]) < 12:
            pass

        elif pktlis[pktindex][12] == 'TCP': # 以后需要显示什么再说，先摆在这里
            self.listWidget_IP.addItem(QtWidgets.QListWidgetItem())
            self.listWidget_IP.item(0).setText(_translate(
                "SnifferGUI", "IP协议版本: " + pktlis[pktindex][3]))
            self.listWidget_IP.addItem(QtWidgets.QListWidgetItem())
            self.listWidget_IP.item(1).setText(_translate(
                "SnifferGUI", "IP包首部长度: " + str(pktlis[pktindex][4])))
            self.listWidget_IP.addItem(QtWidgets.QListWidgetItem())
            self.listWidget_IP.item(2).setText(_translate(
                "SnifferGUI", "服务类型: " + pktlis[pktindex][5]))
            self.listWidget_IP.addItem(QtWidgets.QListWidgetItem())
            self.listWidget_IP.item(3).setText(_translate(
                "SnifferGUI", "IP包总长度: " + str(pktlis[pktindex][6])))
            self.listWidget_IP.addItem(QtWidgets.QListWidgetItem())
            self.listWidget_IP.item(4).setText(_translate(
                "SnifferGUI", "标识: " + pktlis[pktindex][7]))
            self.listWidget_IP.addItem(QtWidgets.QListWidgetItem())
            self.listWidget_IP.item(5).setText(_translate(
                "SnifferGUI", "禁止分片: " + (pktlis[pktindex][8] == 1 and "是" or "否")))
            self.listWidget_IP.addItem(QtWidgets.QListWidgetItem())
            self.listWidget_IP.item(6).setText(_translate(
                "SnifferGUI", "更多分片: " + (pktlis[pktindex][9] == 1 and "是" or "否")))
            self.listWidget_IP.addItem(QtWidgets.QListWidgetItem())
            self.listWidget_IP.item(7).setText(_translate(
                "SnifferGUI", "片内偏移: " + pktlis[pktindex][10]))
            self.listWidget_IP.addItem(QtWidgets.QListWidgetItem())
            self.listWidget_IP.item(8).setText(_translate(
                "SnifferGUI", "生存时间: " + pktlis[pktindex][11]))
            self.listWidget_IP.addItem(QtWidgets.QListWidgetItem())
            self.listWidget_IP.item(9).setText(_translate(
                "SnifferGUI", "首部校验和: " + pktlis[pktindex][13]))
            self.listWidget_IP.addItem(QtWidgets.QListWidgetItem())
            self.listWidget_IP.item(10).setText(_translate(
                "SnifferGUI", "源IP: " + pktlis[pktindex][14]))
            self.listWidget_IP.addItem(QtWidgets.QListWidgetItem())
            self.listWidget_IP.item(11).setText(_translate(
                "SnifferGUI", "目的IP: " + pktlis[pktindex][15]))
            self.listWidget_IP.addItem(QtWidgets.QListWidgetItem())
            self.listWidget_IP.item(12).setText(_translate(
                "SnifferGUI", "选项: " + pktlis[pktindex][16]))
            ## 以上是IP包的字段，以下是TCP包字段
            self.tabWidget_Details.setTabText(self.tabWidget_Details.indexOf(
                self.tab_Protocol), _translate("SnifferGUI", "TCP"))
            self.listWidget_Protocol.addItem(QtWidgets.QListWidgetItem())
            self.listWidget_Protocol.item(0).setText(
                _translate("SnifferGUI", "源端口: " + str(pktlis[pktindex][17])))
            self.listWidget_Protocol.addItem(QtWidgets.QListWidgetItem())
            self.listWidget_Protocol.item(1).setText(
                _translate("SnifferGUI", "目的端口: " + str(pktlis[pktindex][18])))
            self.listWidget_Protocol.addItem(QtWidgets.QListWidgetItem())
            self.listWidget_Protocol.item(2).setText(
                _translate("SnifferGUI", "序号seq: " + str(pktlis[pktindex][19])))
            self.listWidget_Protocol.addItem(QtWidgets.QListWidgetItem())
            self.listWidget_Protocol.item(3).setText(
                _translate("SnifferGUI", "确认序号ack: " + str(pktlis[pktindex][20])))
            self.listWidget_Protocol.addItem(QtWidgets.QListWidgetItem())
            self.listWidget_Protocol.item(4).setText(
                _translate("SnifferGUI", "首部长度: " + str(pktlis[pktindex][21])))
            self.listWidget_Protocol.addItem(QtWidgets.QListWidgetItem())
            self.listWidget_Protocol.item(5).setText(
                _translate("SnifferGUI", "6位标志位: " + str(pktlis[pktindex][23])
                        +str(pktlis[pktindex][24])
                        +str(pktlis[pktindex][25])
                        +str(pktlis[pktindex][26])
                        +str(pktlis[pktindex][27])
                        +str(pktlis[pktindex][28])))
            self.listWidget_Protocol.addItem(QtWidgets.QListWidgetItem())
            self.listWidget_Protocol.item(6).setText(
                _translate("SnifferGUI", "窗口大小: " + str(pktlis[pktindex][29])))
            self.listWidget_Protocol.addItem(QtWidgets.QListWidgetItem())
            self.listWidget_Protocol.item(7).setText(
                _translate("SnifferGUI", "TCP校验和: " + pktlis[pktindex][30]))
            self.listWidget_Protocol.addItem(QtWidgets.QListWidgetItem())
            self.listWidget_Protocol.item(8).setText(
                _translate("SnifferGUI", "紧急数据偏移量: " + str(pktlis[pktindex][31])))

        elif pktlis[pktindex][12]  == 'ICMP':
            self.listWidget_IP.addItem(QtWidgets.QListWidgetItem())
            self.listWidget_IP.item(0).setText(_translate(
                "SnifferGUI", "IP协议版本: " + pktlis[pktindex][3]))
            self.listWidget_IP.addItem(QtWidgets.QListWidgetItem())
            self.listWidget_IP.item(1).setText(_translate(
                "SnifferGUI", "IP包首部长度: " + str(pktlis[pktindex][4])))
            self.listWidget_IP.addItem(QtWidgets.QListWidgetItem())
            self.listWidget_IP.item(2).setText(_translate(
                "SnifferGUI", "服务类型: " + pktlis[pktindex][5]))
            self.listWidget_IP.addItem(QtWidgets.QListWidgetItem())
            self.listWidget_IP.item(3).setText(_translate(
                "SnifferGUI", "IP包总长度: " + str(pktlis[pktindex][6])))
            self.listWidget_IP.addItem(QtWidgets.QListWidgetItem())
            self.listWidget_IP.item(4).setText(_translate(
                "SnifferGUI", "标识: " + pktlis[pktindex][7]))
            self.listWidget_IP.addItem(QtWidgets.QListWidgetItem())
            self.listWidget_IP.item(5).setText(_translate(
                "SnifferGUI", "禁止分片: " + (pktlis[pktindex][8] == 1 and "是" or "否")))
            self.listWidget_IP.addItem(QtWidgets.QListWidgetItem())
            self.listWidget_IP.item(6).setText(_translate(
                "SnifferGUI", "更多分片: " + (pktlis[pktindex][9] == 1 and "是" or "否")))
            self.listWidget_IP.addItem(QtWidgets.QListWidgetItem())
            self.listWidget_IP.item(7).setText(_translate(
                "SnifferGUI", "片内偏移: " + pktlis[pktindex][10]))
            self.listWidget_IP.addItem(QtWidgets.QListWidgetItem())
            self.listWidget_IP.item(8).setText(_translate(
                "SnifferGUI", "生存时间: " + pktlis[pktindex][11]))
            self.listWidget_IP.addItem(QtWidgets.QListWidgetItem())
            self.listWidget_IP.item(9).setText(_translate(
                "SnifferGUI", "首部校验和: " + pktlis[pktindex][13]))
            self.listWidget_IP.addItem(QtWidgets.QListWidgetItem())
            self.listWidget_IP.item(10).setText(_translate(
                "SnifferGUI", "源IP: " + pktlis[pktindex][14]))
            self.listWidget_IP.addItem(QtWidgets.QListWidgetItem())
            self.listWidget_IP.item(11).setText(_translate(
                "SnifferGUI", "目的IP: " + pktlis[pktindex][15]))
            self.listWidget_IP.addItem(QtWidgets.QListWidgetItem())
            self.listWidget_IP.item(12).setText(_translate(
                "SnifferGUI", "选项: " + pktlis[pktindex][16]))

            ## 以上是IP包的字段，以下是ICMP包字段

            if (pktlis[pktindex][17] != "分片包"):
                self.tabWidget_Details.setTabText(self.tabWidget_Details.indexOf(
                    self.tab_Protocol), _translate("SnifferGUI", "ICMP"))
                self.listWidget_Protocol.addItem(QtWidgets.QListWidgetItem())
                self.listWidget_Protocol.item(0).setText(
                    _translate("SnifferGUI", "操作类型: " + pktlis[pktindex][17]))
                self.listWidget_Protocol.addItem(QtWidgets.QListWidgetItem())
                self.listWidget_Protocol.item(1).setText(
                    _translate("SnifferGUI", "具体操作: " + pktlis[pktindex][18]))
                self.listWidget_Protocol.addItem(QtWidgets.QListWidgetItem())
                self.listWidget_Protocol.item(2).setText(
                    _translate("SnifferGUI", "ICMP校验和: " + pktlis[pktindex][19]))
                self.listWidget_Protocol.addItem(QtWidgets.QListWidgetItem())
                self.listWidget_Protocol.item(3).setText(
                    _translate("SnifferGUI", "ID: " + str(pktlis[pktindex][20])))
                self.listWidget_Protocol.addItem(QtWidgets.QListWidgetItem())
                self.listWidget_Protocol.item(4).setText(
                    _translate("SnifferGUI", "序列号: " + str(pktlis[pktindex][21])))

        elif pktlis[pktindex][12] == 'UDP':
            self.listWidget_IP.addItem(QtWidgets.QListWidgetItem())
            self.listWidget_IP.item(0).setText(_translate(
                "SnifferGUI", "IP协议版本: " + pktlis[pktindex][3]))
            self.listWidget_IP.addItem(QtWidgets.QListWidgetItem())
            self.listWidget_IP.item(1).setText(_translate(
                "SnifferGUI", "IP包首部长度: " + str(pktlis[pktindex][4])))
            self.listWidget_IP.addItem(QtWidgets.QListWidgetItem())
            self.listWidget_IP.item(2).setText(_translate(
                "SnifferGUI", "服务类型: " + pktlis[pktindex][5]))
            self.listWidget_IP.addItem(QtWidgets.QListWidgetItem())
            self.listWidget_IP.item(3).setText(_translate(
                "SnifferGUI", "IP包总长度: " + str(pktlis[pktindex][6])))
            self.listWidget_IP.addItem(QtWidgets.QListWidgetItem())
            self.listWidget_IP.item(4).setText(_translate(
                "SnifferGUI", "标识: " + pktlis[pktindex][7]))
            self.listWidget_IP.addItem(QtWidgets.QListWidgetItem())
            self.listWidget_IP.item(5).setText(_translate(
                "SnifferGUI", "禁止分片: " + (pktlis[pktindex][8] == 1 and "是" or "否")))
            self.listWidget_IP.addItem(QtWidgets.QListWidgetItem())
            self.listWidget_IP.item(6).setText(_translate(
                "SnifferGUI", "更多分片: " + (pktlis[pktindex][9] == 1 and "是" or "否")))
            self.listWidget_IP.addItem(QtWidgets.QListWidgetItem())
            self.listWidget_IP.item(7).setText(_translate(
                "SnifferGUI", "片内偏移: " + pktlis[pktindex][10]))
            self.listWidget_IP.addItem(QtWidgets.QListWidgetItem())
            self.listWidget_IP.item(8).setText(_translate(
                "SnifferGUI", "生存时间: " + pktlis[pktindex][11]))
            self.listWidget_IP.addItem(QtWidgets.QListWidgetItem())
            self.listWidget_IP.item(9).setText(_translate(
                "SnifferGUI", "首部校验和: " + pktlis[pktindex][13]))
            self.listWidget_IP.addItem(QtWidgets.QListWidgetItem())
            self.listWidget_IP.item(10).setText(_translate(
                "SnifferGUI", "源IP: " + pktlis[pktindex][14]))
            self.listWidget_IP.addItem(QtWidgets.QListWidgetItem())
            self.listWidget_IP.item(11).setText(_translate(
                "SnifferGUI", "目的IP: " + pktlis[pktindex][15]))
            self.listWidget_IP.addItem(QtWidgets.QListWidgetItem())
            self.listWidget_IP.item(12).setText(_translate(
                "SnifferGUI", "选项: " + pktlis[pktindex][16]))

            ## 以上是IP包的字段，以下是UDP包字段

            self.tabWidget_Details.setTabText(self.tabWidget_Details.indexOf(
                self.tab_Protocol), _translate("SnifferGUI", "UDP"))
            self.listWidget_Protocol.addItem(QtWidgets.QListWidgetItem())
            self.listWidget_Protocol.item(0).setText(
                _translate("SnifferGUI", "源端口: " + str(pktlis[pktindex][17])))
            self.listWidget_Protocol.addItem(QtWidgets.QListWidgetItem())
            self.listWidget_Protocol.item(1).setText(
                _translate("SnifferGUI", "目的端口: " + str(pktlis[pktindex][18])))
            self.listWidget_Protocol.addItem(QtWidgets.QListWidgetItem())
            self.listWidget_Protocol.item(2).setText(
                _translate("SnifferGUI", "UDP长度: " + str(pktlis[pktindex][19])))
            self.listWidget_Protocol.addItem(QtWidgets.QListWidgetItem())
            self.listWidget_Protocol.item(3).setText(
                _translate("SnifferGUI", "校验和: " + pktlis[pktindex][20]))

        elif pktlis[pktindex][12] == 'IGMP':
            self.listWidget_IP.addItem(QtWidgets.QListWidgetItem())
            self.listWidget_IP.item(0).setText(_translate(
                "SnifferGUI", "IP协议版本: " + pktlis[pktindex][3]))
            self.listWidget_IP.addItem(QtWidgets.QListWidgetItem())
            self.listWidget_IP.item(1).setText(_translate(
                "SnifferGUI", "IP包首部长度: " + str(pktlis[pktindex][4])))
            self.listWidget_IP.addItem(QtWidgets.QListWidgetItem())
            self.listWidget_IP.item(2).setText(_translate(
                "SnifferGUI", "服务类型: " + pktlis[pktindex][5]))
            self.listWidget_IP.addItem(QtWidgets.QListWidgetItem())
            self.listWidget_IP.item(3).setText(_translate(
                "SnifferGUI", "IP包总长度: " + str(pktlis[pktindex][6])))
            self.listWidget_IP.addItem(QtWidgets.QListWidgetItem())
            self.listWidget_IP.item(4).setText(_translate(
                "SnifferGUI", "标识: " + pktlis[pktindex][7]))
            self.listWidget_IP.addItem(QtWidgets.QListWidgetItem())
            self.listWidget_IP.item(5).setText(_translate(
                "SnifferGUI", "禁止分片: " + (pktlis[pktindex][8] == 1 and "是" or "否")))
            self.listWidget_IP.addItem(QtWidgets.QListWidgetItem())
            self.listWidget_IP.item(6).setText(_translate(
                "SnifferGUI", "更多分片: " + (pktlis[pktindex][9] == 1 and "是" or "否")))
            self.listWidget_IP.addItem(QtWidgets.QListWidgetItem())
            self.listWidget_IP.item(7).setText(_translate(
                "SnifferGUI", "片内偏移: " + pktlis[pktindex][10]))
            self.listWidget_IP.addItem(QtWidgets.QListWidgetItem())
            self.listWidget_IP.item(8).setText(_translate(
                "SnifferGUI", "生存时间: " + pktlis[pktindex][11]))
            self.listWidget_IP.addItem(QtWidgets.QListWidgetItem())
            self.listWidget_IP.item(9).setText(_translate(
                "SnifferGUI", "首部校验和: " + pktlis[pktindex][13]))
            self.listWidget_IP.addItem(QtWidgets.QListWidgetItem())
            self.listWidget_IP.item(10).setText(_translate(
                "SnifferGUI", "源IP: " + pktlis[pktindex][14]))
            self.listWidget_IP.addItem(QtWidgets.QListWidgetItem())
            self.listWidget_IP.item(11).setText(_translate(
                "SnifferGUI", "目的IP: " + pktlis[pktindex][15]))
            self.listWidget_IP.addItem(QtWidgets.QListWidgetItem())
            self.listWidget_IP.item(12).setText(_translate(
                "SnifferGUI", "选项: " + pktlis[pktindex][16]))

            ## 以上是IP包的字段，以下是ICMP包字段
            self.tabWidget_Details.setTabText(self.tabWidget_Details.indexOf(
                self.tab_Protocol), _translate("SnifferGUI", "ICMP"))
            self.listWidget_Protocol.addItem(QtWidgets.QListWidgetItem())
            self.listWidget_Protocol.item(0).setText(
                _translate("SnifferGUI", "操作类型: " + pktlis[pktindex][17]))
            self.listWidget_Protocol.addItem(QtWidgets.QListWidgetItem())
            self.listWidget_Protocol.item(1).setText(
                _translate("SnifferGUI", "最大响应时间: " + str(pktlis[pktindex][18])))
            self.listWidget_Protocol.addItem(QtWidgets.QListWidgetItem())
            self.listWidget_Protocol.item(2).setText(
                _translate("SnifferGUI", "IGMP校验和: " + pktlis[pktindex][19]))
            self.listWidget_Protocol.addItem(QtWidgets.QListWidgetItem())
            self.listWidget_Protocol.item(3).setText(
                _translate("SnifferGUI", "组地址: " + pktlis[pktindex][20]))

        elif pktlis[pktindex][12] == '未定义的协议':
            self.listWidget_IP.addItem(QtWidgets.QListWidgetItem())
            self.listWidget_IP.item(0).setText(_translate(
                "SnifferGUI", "IP协议版本: " + pktlis[pktindex][3]))
            self.listWidget_IP.addItem(QtWidgets.QListWidgetItem())
            self.listWidget_IP.item(1).setText(_translate(
                "SnifferGUI", "IP包首部长度: " + str(pktlis[pktindex][4])))
            self.listWidget_IP.addItem(QtWidgets.QListWidgetItem())
            self.listWidget_IP.item(2).setText(_translate(
                "SnifferGUI", "服务类型: " + pktlis[pktindex][5]))
            self.listWidget_IP.addItem(QtWidgets.QListWidgetItem())
            self.listWidget_IP.item(3).setText(_translate(
                "SnifferGUI", "IP包总长度: " + str(pktlis[pktindex][6])))
            self.listWidget_IP.addItem(QtWidgets.QListWidgetItem())
            self.listWidget_IP.item(4).setText(_translate(
                "SnifferGUI", "标识: " + pktlis[pktindex][7]))
            self.listWidget_IP.addItem(QtWidgets.QListWidgetItem())
            self.listWidget_IP.item(5).setText(_translate(
                "SnifferGUI", "禁止分片: " + (pktlis[pktindex][8] == 1 and "是" or "否")))
            self.listWidget_IP.addItem(QtWidgets.QListWidgetItem())
            self.listWidget_IP.item(6).setText(_translate(
                "SnifferGUI", "更多分片: " + (pktlis[pktindex][9] == 1 and "是" or "否")))
            self.listWidget_IP.addItem(QtWidgets.QListWidgetItem())
            self.listWidget_IP.item(7).setText(_translate(
                "SnifferGUI", "片内偏移: " + pktlis[pktindex][10]))
            self.listWidget_IP.addItem(QtWidgets.QListWidgetItem())
            self.listWidget_IP.item(8).setText(_translate(
                "SnifferGUI", "生存时间: " + pktlis[pktindex][11]))
            self.listWidget_IP.addItem(QtWidgets.QListWidgetItem())
            self.listWidget_IP.item(9).setText(_translate(
                "SnifferGUI", "首部校验和: " + pktlis[pktindex][13]))
            self.listWidget_IP.addItem(QtWidgets.QListWidgetItem())
            self.listWidget_IP.item(10).setText(_translate(
                "SnifferGUI", "源IP: " + pktlis[pktindex][14]))
            self.listWidget_IP.addItem(QtWidgets.QListWidgetItem())
            self.listWidget_IP.item(11).setText(_translate(
                "SnifferGUI", "目的IP: " + pktlis[pktindex][15]))
            self.listWidget_IP.addItem(QtWidgets.QListWidgetItem())
            self.listWidget_IP.item(12).setText(_translate(
                "SnifferGUI", "选项: " + pktlis[pktindex][16]))

        else:
            pass

def SniffStop():
    para.ListenFlag = 0
    Process.join()
    print("抓包已停止，可以重新开始抓包")


def ShowString(pktlist, pktindex):
    listHex = pktlist[pktindex][-4]
    listANSI = pktlist[pktindex][-3]

    row = int(len(listANSI)/16)+1
    string_op = ''
    for i in range(row):
        #得到0000，0010...
        rowi = 16*i
        title = hex(rowi)[2:]
        while len(title) < 4:
            title = '0' + title
        string_op += (title+'  ')
        if i != row-1:
            string_op += listHex[3 * rowi:3 * (rowi + 8)]
            string_op += ' '
            string_op += listHex[3 * (rowi + 8):3 * (rowi + 16)]
            string_op += '     '
            string_op += listANSI[rowi:rowi + 8]
            string_op += ' '
            string_op += listANSI[rowi+8:rowi+16]
            string_op += '\n'
        else:
            reminder = len(listANSI)-16*(row-1)
            if reminder <= 8: 
                string_op += listHex[3 * rowi:3 * (rowi + 8)]
                string_op += ' ' * ((16 - reminder) * 3 + 6)
                string_op += listANSI[rowi:rowi + 8]
            else:
                string_op += listHex[3 * rowi:3 * (rowi + 8)]
                string_op += ' '
                string_op += listHex[3 * (rowi + 8):3 * (rowi + 16)]
                string_op += ' ' * ((16 - reminder) * 3 + 5)
                string_op += listANSI[rowi:rowi + 8]
                string_op += ' '
                string_op += listANSI[rowi + 8:rowi + 16]
    ui.textBrowser_String.setText(string_op)


def ChangeIface(): # 选定网卡
    local_alldevs = para.alldevs
    ifaceindex = ui.comboBox.currentIndex()
    print("当前选择为: "+para.NtwkIf[ifaceindex-1])
    for i in range(ifaceindex - 1):
        local_alldevs = local_alldevs.contents.next
    para.fp = pcap_open_live(
        local_alldevs.contents.name, 65536, 1, 1000, para.errbuf)
    para.DUMPFILE = pcap_dump_open(para.fp, "temp".encode("utf-8"))


def list_to_display(lista,Num):  # 显示上面窗口的src，dst，prt，len等
    listdisplay = []
    if lista[2] in ['ARP','RARP']:
        listdisplay = [str(lista[i]) for i in [9, 11, 2]]
        listdisplay.append(lista[-1])  # 长度
        listdisplay.append(lista[-2][:11]) # 日期
        listdisplay.append(lista[-2][11:24])  # 时间
        if lista[7] == "RARP请求":
            listdisplay.append("我是" + lista[8] + "，请分配给我一个IP地址！")
        elif lista[7] == "RARP应答":
            listdisplay.append("亲爱的" + lista[10] + "你好！你的IP地址是" + lista[11])
        elif lista[7] == "ARP请求":
            listdisplay.append("谁是" + lista[11] + "？请站出来告诉" + lista[9])
        elif lista[7] == "ARP回显":
            listdisplay.append("我是" + lista[9] + "，我的MAC是" + lista[8])

    elif lista[2] == 'IPv6':
        listdisplay = [str(lista[i]) for i in [9, 10, 2]]
        listdisplay.append(lista[-1])  # 长度
        listdisplay.append(lista[-2][:11])  # 日期
        listdisplay.append(lista[-2][11:24])  # 时间
        listdisplay.append(lista[9] + "->" +lista[10])
    else:
        if len(lista)>12:
            if lista[12] == 'UDP':
                listdisplay = [str(lista[i]) for i in [14, 15, 12]]
                listdisplay.append(lista[-1])  # 长度
                listdisplay.append(lista[-2][:11])  # 日期
                listdisplay.append(lista[-2][11:24])  # 时间
                listdisplay.append(lista[14] +":"+str(lista[17])+"->"+lista[15]+":"+str(lista[18]))
            elif lista[12] == 'TCP':
                listdisplay = [str(lista[i]) for i in [14, 15, 12]]
                listdisplay.append(lista[-1])  # 长度
                listdisplay.append(lista[-2][:11])  # 日期
                listdisplay.append(lista[-2][11:24])  # 时间
                listdisplay.append(str(lista[17])+"->"+str(lista[18])+"   Seq=" + str(lista[19]) +"  Ack=" + str(lista[20]))
            elif lista[12]  =='IGMP':
                listdisplay = [str(lista[i]) for i in [14, 15, 12]]
                listdisplay.append(lista[-1])  # 长度
                listdisplay.append(lista[-2][:11])  # 日期
                listdisplay.append(lista[-2][11:24])  # 时间
                listdisplay.append('IGMP')
            elif lista[12] == 'ICMP' and lista[17]!= '分片包':
                listdisplay = [str(lista[i]) for i in [14, 15, 12]]
                listdisplay.append(lista[-1])  # 长度
                listdisplay.append(lista[-2][:11])  # 日期
                listdisplay.append(lista[-2][11:24])  # 时间
                listdisplay.append(lista[17] + ":" + lista[18])
            elif lista[12] == 'ICMP' and lista[17]== '分片包':
                listdisplay = [str(lista[i]) for i in [14, 15, 12]]
                listdisplay.append(lista[-1])  # 长度
                listdisplay.append(lista[-2][:11])  # 日期
                listdisplay.append(lista[-2][11:24])  # 时间
                listdisplay.append('ICMP分片')
            else :
                listdisplay = ['无法识别', '', '']
                listdisplay.append(lista[-1])  # 长度
                listdisplay.append(lista[-2][:11])  # 日期
                listdisplay.append(lista[-2][11:24])  # 时间
                listdisplay.append('无法识别的字段！')

        else:
            listdisplay = ['无法识别','','']
            listdisplay.append(lista[-1])  # 长度
            listdisplay.append(lista[-2][:11])  # 日期
            listdisplay.append(lista[-2][11:24])  # 时间
            listdisplay.append('你听说过编号为 '+ lista[2] + ' 的协议吗？我没听过啊，长这么大。。白活了。。')

    listdisplay.insert(0, str(Num))
    return listdisplay

#抓包线程
def threadlisten(): #开启一个线程抓包
    global Process
    Process = threading.Thread(target=ListenDevice)
    if para.ListenFlag == 1:
        Process.start()
    else:
        para.reinitial()
        ChangeIface()
        ui.treeWidget.clear()
        para.ListenFlag = 1
        Process.start()
        

#抓包函数
def ListenDevice():
    para.RANK = 0
    while para.ListenFlag:
        res = pcap_next_ex(para.fp, byref(para.header), byref(para.pkt_data))
        while (res >= 0) and para.ListenFlag:
            if (res == 0):
                ## 超时
                break
            time1 = str(time.strftime("%Y-%m-%d %H:%M:%S.",time.localtime(para.header.contents.ts.tv_sec))) + str("%d" %(para.header.contents.ts.tv_usec))
            length = str("%ld" %(para.header.contents.len))
            para.showpacket = etherPacketLoop(para.pkt_data, para.header.contents.len)
            para.showpacket.append(time1)  # 加一个时间，年月日秒
            para.showpacket.append(length) # 加一个总帧长
            #para.showpacket.append(para.RANK)
            para.packet.append(para.showpacket)
            #packet为格式化的包
            #下一步来个显示函数
            #print出无法识别的包
            if list_to_display(para.showpacket, para.RANK + 1)[1] == '无法识别':
                print(para.showpacket)
            displaygui(list_to_display(para.showpacket, para.RANK+1), para.RANK)
            para.RANK += 1
            #将包内容填到缓存里
            pcap_dump(para.DUMPFILE, para.header, para.pkt_data)
            res = pcap_next_ex(para.fp, byref(para.header), byref(para.pkt_data))
        if (res == -1):
            print("读包失败: %s\n" % pcap_geterr(para.fp))
            sys.exit(-1)
    pcap_dump_close(para.DUMPFILE)
    pcap_close(para.fp)
    sys.exit(-1)


def displaygui(showlist, rank):
    gui_object = ui
    Treeitem = QtWidgets.QTreeWidgetItem(gui_object.treeWidget)
    item_num = 0
    # 根据协议分颜色
    if showlist[3] == 'TCP':
        brush = QtGui.QBrush(QtGui.QColor(254, 217, 166))
        brush.setStyle(QtCore.Qt.SolidPattern)
    elif showlist[3] == 'UDP':
        brush = QtGui.QBrush(QtGui.QColor(179, 205, 227))
        brush.setStyle(QtCore.Qt.SolidPattern)
    elif showlist[3] == 'ARP':
        brush = QtGui.QBrush(QtGui.QColor(204, 235, 197))
        brush.setStyle(QtCore.Qt.SolidPattern)
    elif showlist[3] == 'IPv6':
        brush = QtGui.QBrush(QtGui.QColor(222, 203, 228))
        brush.setStyle(QtCore.Qt.SolidPattern)
    elif showlist[3] == 'ICMP':
        brush = QtGui.QBrush(QtGui.QColor(251, 180, 174))
        brush.setStyle(QtCore.Qt.SolidPattern)
    else:
        brush = QtGui.QBrush(QtGui.QColor(255, 255, 155))
        brush.setStyle(QtCore.Qt.SolidPattern)

    for item in showlist:
        gui_object.treeWidget.topLevelItem(rank).setText(
            item_num, QtCore.QCoreApplication.translate("SnifferGUI", item))
        gui_object.treeWidget.topLevelItem(rank).setBackground(item_num,brush)
        item_num += 1

#搜索过滤函数
def Filter():
    gui_object = ui
    protocol = ui.lineEdit.text().lower()
    filterlist = para.filterlist = []

    if protocol =='tcp':
        ui.treeWidget.clear()
        for pkt in para.packet:
            if len(pkt) == 36:
                filterlist.append(pkt)
        total = len(filterlist)
        for i in range(total):
            displaygui(list_to_display(filterlist[i], i+1), i)

    elif protocol =='udp':
        ui.treeWidget.clear()
        for pkt in para.packet:
            if len(pkt) == 25:
                filterlist.append(pkt)
        total = len(filterlist)
        for i in range(total):
            displaygui(list_to_display(filterlist[i], i + 1), i)
    
    elif protocol =='icmp':
        ui.treeWidget.clear()
        for pkt in para.packet:
            if len(pkt) == 26:
                filterlist.append(pkt)
        total = len(filterlist)
        for i in range(total):
            displaygui(list_to_display(filterlist[i], i + 1), i)

    elif protocol =='igmp':
        ui.treeWidget.clear()
        for pkt in para.packet:
            if len(pkt) == 23:
                filterlist.append(pkt)
        total = len(filterlist)
        for i in range(total):
            displaygui(list_to_display(filterlist[i], i + 1), i)
    
    elif protocol =='ipv6':
        ui.treeWidget.clear()
        for pkt in para.packet:
            if pkt[2] == 'IPv6':
                filterlist.append(pkt)
        total = len(filterlist)
        for i in range(total):
            displaygui(list_to_display(filterlist[i], i + 1), i)
    
    elif protocol =='arp':
        ui.treeWidget.clear()
        for pkt in para.packet:
            if pkt[2] == 'ARP':
                filterlist.append(pkt)
        total = len(filterlist)
        for i in range(total):
            displaygui(list_to_display(filterlist[i], i + 1), i)

    elif protocol =='rarp':
        ui.treeWidget.clear()
        for pkt in para.packet:
            if pkt[2] == 'PARP':
                filterlist.append(pkt)
        total = len(filterlist)
        for i in range(total):
            displaygui(list_to_display(filterlist[i], i + 1), i)
            
    #随意输入，可以返回原始列表（全部包显示）
    else:
        ui.treeWidget.clear()
        i = 0
        for pkt in para.packet:
            displaygui(list_to_display(pkt, i+1), i)
            i += 1


#抓包过滤函数，这个函数要在运行抓包指令开始之前跑一遍
def PacketFilter(filter='tcp'.encode('utf-8')):
    fcode = bpf_program()
    netmask = 0xffffff
    #filter = "tcp"

    ## compile the filter
    if pcap_compile(para.fp, byref(fcode), filter, 1, netmask) < 0:
        print('\nerror compiling filter: wrong syntax.\n')
        pcap_close(para.fp)
        sys.exit(-3)

    ## set the filter

    if pcap_setfilter(para.fp, byref(fcode)) < 0:
        print('\nerror setting the filter\n')
        pcap_close(para.fp)
        sys.exit(-4)

def MainWindows():
    global ui
    app = QtWidgets.QApplication(sys.argv)
    w = QtWidgets.QMainWindow()
    ui = Ui_SnifferGUI()
    ui.setupUi(w)
    w.show()
    sys.exit(app.exec_())
    #Process.join()

#主函数
def main():
    printDevices()
    MainWindows()


if __name__ == '__main__':
    main()