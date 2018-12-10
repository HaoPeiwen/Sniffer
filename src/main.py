import sys, string, platform, time, threading , re
from PyQt5 import QtCore, QtWidgets, QtGui
from ctypes import *
from winpcapy import *
from readPackets import *
from ansi2html import *
from converter import *
from PyQt5.QtWidgets import *
from PyQt5.QtCore import *
from PyQt5.QtWidgets import QMessageBox
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
        self.filterlist = [] # 过滤后显示的包
        self.SearchFlag = 0 # 如果点击搜索则为1，显示列表用filterlist，点击返回或不操作为0，显示列表用packet
        self.Process = None

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
        self.SearchFlag = 0
        

#输出适配器列表
para = Parameter() # 实例调用

#打印设备函数
def printDevices():
    if (pcap_findalldevs(byref(para.alldevs), para.errbuf) == -1):
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

        sys.exit(-1)


class Ui_Dialog(QtWidgets.QDialog):
    def __init__(self):
        super().__init__()
        self.setupUi(self)


    def setupUi(self, Dialog):
        Dialog.setObjectName("Dialog")
        Dialog.resize(435, 237)
        self.buttonBox = QtWidgets.QDialogButtonBox(Dialog)
        self.buttonBox.setGeometry(QtCore.QRect(240, 180, 171, 41))
        self.buttonBox.setOrientation(QtCore.Qt.Horizontal)
        self.buttonBox.setStandardButtons(
            QtWidgets.QDialogButtonBox.Cancel | QtWidgets.QDialogButtonBox.Ok)
        self.buttonBox.setObjectName("buttonBox")
        self.groupBox_Addr = QtWidgets.QGroupBox(Dialog)
        self.groupBox_Addr.setGeometry(QtCore.QRect(140, 10, 271, 161))
        self.groupBox_Addr.setObjectName("groupBox_Addr")
        self.lineEdit_src = QtWidgets.QLineEdit(self.groupBox_Addr)
        self.lineEdit_src.setGeometry(QtCore.QRect(30, 50, 221, 21))
        self.lineEdit_src.setObjectName("lineEdit_src")
        self.label = QtWidgets.QLabel(self.groupBox_Addr)
        self.label.setGeometry(QtCore.QRect(40, 30, 47, 13))
        self.label.setObjectName("label")
        self.lineEdit_dist = QtWidgets.QLineEdit(self.groupBox_Addr)
        self.lineEdit_dist.setGeometry(QtCore.QRect(30, 110, 221, 21))
        self.lineEdit_dist.setObjectName("lineEdit_dist")
        self.label_2 = QtWidgets.QLabel(self.groupBox_Addr)
        self.label_2.setGeometry(QtCore.QRect(40, 90, 47, 13))
        self.label_2.setObjectName("label_2")
        self.groupBox_Protocol = QtWidgets.QGroupBox(Dialog)
        self.groupBox_Protocol.setGeometry(QtCore.QRect(20, 10, 101, 211))
        self.groupBox_Protocol.setObjectName("groupBox_Protocol")
        self.checkBox_IPv6 = QtWidgets.QCheckBox(self.groupBox_Protocol)
        self.checkBox_IPv6.setGeometry(QtCore.QRect(20, 20, 70, 17))
        self.checkBox_IPv6.setObjectName("checkBox_IPv6")
        self.checkBox_TCP = QtWidgets.QCheckBox(self.groupBox_Protocol)
        self.checkBox_TCP.setGeometry(QtCore.QRect(20, 60, 70, 17))
        self.checkBox_TCP.setObjectName("checkBox_TCP")
        self.checkBox_UDP = QtWidgets.QCheckBox(self.groupBox_Protocol)
        self.checkBox_UDP.setGeometry(QtCore.QRect(20, 100, 70, 17))
        self.checkBox_UDP.setObjectName("checkBox_UDP")
        self.checkBox_ARP = QtWidgets.QCheckBox(self.groupBox_Protocol)
        self.checkBox_ARP.setGeometry(QtCore.QRect(20, 140, 70, 17))
        self.checkBox_ARP.setObjectName("checkBox_ARP")
        self.checkBox_ICMP = QtWidgets.QCheckBox(self.groupBox_Protocol)
        self.checkBox_ICMP.setGeometry(QtCore.QRect(20, 180, 81, 16))
        self.checkBox_ICMP.setObjectName("checkBox_ICMP")

        self.retranslateUi(Dialog)
        self.buttonBox.accepted.connect(Dialog.accept)
        self.buttonBox.rejected.connect(Dialog.reject)
        QtCore.QMetaObject.connectSlotsByName(Dialog)

    def retranslateUi(self, Dialog):
        _translate = QtCore.QCoreApplication.translate
        Dialog.setWindowTitle(_translate("Dialog", "设定过滤条件"))
        self.groupBox_Addr.setTitle(_translate("Dialog", "地址"))
        self.label.setText(_translate("Dialog", "源地址"))
        self.label_2.setText(_translate("Dialog", "目的地址"))
        self.groupBox_Protocol.setTitle(_translate("Dialog", "协议"))
        self.checkBox_IPv6.setText(_translate("Dialog", "IPv6"))
        self.checkBox_TCP.setText(_translate("Dialog", "TCP"))
        self.checkBox_UDP.setText(_translate("Dialog", "UDP"))
        self.checkBox_ARP.setText(_translate("Dialog", "ARP/RARP"))
        self.checkBox_ICMP.setText(_translate("Dialog", "ICMP/IGMP"))

    def accept(self):
        FilterString = "" +  (self.checkBox_ARP.isChecked() and " arp or rarp or" or "") + \
                       (self.checkBox_TCP.isChecked() and " tcp or" or "") + \
                       (self.checkBox_UDP.isChecked() and " udp or" or "") + \
                       (self.checkBox_ICMP.isChecked() and " icmp or igmp or" or "") + \
                       (self.checkBox_IPv6.isChecked() and " (ip6) or" or "")
        if FilterString:
            FilterString = FilterString[:-3]
            if self.lineEdit_src.text():
                FilterString = "(" + FilterString + ") and (src host " + self.lineEdit_src.text() + ")"
            if self.lineEdit_dist.text():
                FilterString = "(" + FilterString + ") and (dst host " + self.lineEdit_dist.text() + ")"
        else:
            if self.lineEdit_src.text():
                FilterString = "src host " + self.lineEdit_src.text()
                FilterString = FilterString + (self.lineEdit_dist.text() and " and (dst host " + self.lineEdit_dist.text() or "")
            elif self.lineEdit_dist.text():
                FilterString = "dst host " + self.lineEdit_dist.text() + ""
            else:
                FilterString = "ip or ip6"
        ui.lineEdit_filter.setText(FilterString)
        ui.PacketFilter(FilterString)
        self.close()
    

    def handle_click(self):
        if not self.isVisible():
            self.show()

    def handle_close(self):
        self.close()


class Ui_SnifferGUI(QtWidgets.QMainWindow):
    def __init__(self):
        super().__init__()
        self.setupUi(self)
        ##创建一个线程实例并设置名称、变量、信号槽
        self.thread = Catching()
        self.thread.sinOut.connect(self.func)
        #self.connect(self.thread, SIGNAL("convertPacket")
        #             , self.func)

        #创建GUI窗口
    def setupUi(self, SnifferGUI):
        SnifferGUI.setObjectName("SnifferGUI")
        SnifferGUI.resize(1240, 850)
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
        self.pushButton_TCPstream = QtWidgets.QPushButton(self.centralwidget)
        self.pushButton_TCPstream.setGeometry(QtCore.QRect(870, 20, 71, 23))
        self.pushButton_TCPstream.setObjectName("pushButton_TCPstream")
        self.commandLinkButton = QtWidgets.QCommandLinkButton(self.centralwidget)
        self.commandLinkButton.setGeometry(QtCore.QRect(560, 50, 90, 41))
        self.commandLinkButton.setObjectName("commandLinkButton")
        self.treeWidget = QtWidgets.QTreeWidget(self.centralwidget)
        self.treeWidget.setGeometry(QtCore.QRect(30, 100, 1181, 350))
        self.treeWidget.setObjectName("treeWidget")
        self.tabWidget_Details = QtWidgets.QTabWidget(self.centralwidget)
        self.tabWidget_Details.setGeometry(QtCore.QRect(30, 470, 380, 330))
        self.tabWidget_Details.setObjectName("tabWidget_Details")
        self.tab_Ethernet = QtWidgets.QWidget()
        self.tab_Ethernet.setObjectName("tab_Ethernet")
        self.listWidget = QtWidgets.QListWidget(self.tab_Ethernet)
        self.listWidget.setGeometry(QtCore.QRect(0, 0, 375, 330))
        self.listWidget.setObjectName("listWidget")
        self.tabWidget_Details.addTab(self.tab_Ethernet, "")
        self.tab_IP = QtWidgets.QWidget()
        self.tab_IP.setObjectName("tab_IP")
        self.listWidget_IP = QtWidgets.QListWidget(self.tab_IP)
        self.listWidget_IP.setGeometry(QtCore.QRect(0, 0, 375, 330))
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
        self.listWidget_Protocol.setGeometry(QtCore.QRect(0, 0, 375, 330))
        self.listWidget_Protocol.setObjectName("listWidget_Protocol")
        item = QtWidgets.QListWidgetItem()
        item.setFont(font)
        self.listWidget_Protocol.addItem(item)
        self.tabWidget_Details.addTab(self.tab_Protocol, "")
        self.tabWidget_Reassemble = QtWidgets.QTabWidget(self.centralwidget)
        self.tabWidget_Reassemble.setGeometry(QtCore.QRect(440, 470, 773, 330))
        self.tabWidget_Reassemble.setObjectName("tabWidget_Reassemble")
        self.tab_String = QtWidgets.QWidget()
        self.tab_String.setObjectName("tab_String")
        self.textBrowser_String = QtWidgets.QTextBrowser(self.tab_String)
        self.textBrowser_String.setGeometry(QtCore.QRect(0, 0, 767, 330))
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
        self.textBrowser_HEX.setGeometry(QtCore.QRect(0, 0, 767, 330))
        self.textBrowser_HEX.setFont(font)
        self.textBrowser_HEX.setObjectName("textBrowser_HEX")
        self.tabWidget_Reassemble.addTab(self.tab_HEX, "")
        self.tab_GBK = QtWidgets.QWidget()
        self.tab_GBK.setObjectName("tab_GBK")
        self.textBrowser_GBK = QtWidgets.QTextBrowser(self.tab_GBK)
        self.textBrowser_GBK.setGeometry(QtCore.QRect(0, 0, 767, 330))
        self.textBrowser_GBK.setFont(font)
        self.textBrowser_GBK.setObjectName("textBrowser_GBK")
        self.textBrowser_GBK.setWordWrapMode(QtGui.QTextOption.NoWrap)
        self.tabWidget_Reassemble.addTab(self.tab_GBK, "")
        self.tab_ANSI = QtWidgets.QWidget()
        self.tab_ANSI.setObjectName("tab_ANSI")
        self.textBrowser_ANSI = QtWidgets.QTextBrowser(self.tab_ANSI)
        self.textBrowser_ANSI.setGeometry(QtCore.QRect(0, 0, 767, 330))
        self.textBrowser_ANSI.setFont(font)
        self.textBrowser_ANSI.setObjectName("textBrowser_ANSI")
        self.textBrowser_ANSI.setWordWrapMode(QtGui.QTextOption.NoWrap)
        self.tabWidget_Reassemble.addTab(self.tab_ANSI, "")
        self.tab_UTF8 = QtWidgets.QWidget()
        self.tab_UTF8.setObjectName("tab_UTF8")
        self.textBrowser_UTF8 = QtWidgets.QTextBrowser(self.tab_UTF8)
        self.textBrowser_UTF8.setGeometry(QtCore.QRect(0, 0, 767, 330))
        self.textBrowser_UTF8.setFont(font)
        self.textBrowser_UTF8.setObjectName("textBrowser_UTF8")
        self.tabWidget_Reassemble.addTab(self.tab_UTF8, "")
        self.tab_PRT = QtWidgets.QWidget()
        self.tab_PRT.setObjectName("tab_PRT")
        self.textBrowser_PRT = QtWidgets.QTextBrowser(self.tab_PRT)
        self.textBrowser_PRT.setGeometry(QtCore.QRect(0, 0, 767, 330))
        self.textBrowser_PRT.setFont(font)
        self.textBrowser_PRT.setObjectName("textBrowser_PRT")
        self.textBrowser_PRT.setWordWrapMode(QtGui.QTextOption.NoWrap)
        self.tabWidget_Reassemble.addTab(self.tab_PRT, "")
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
        self.pushButton_sniff.clicked.connect(self.threadlisten)
        self.pushButton_stop.clicked.connect(self.SniffStop)
        self.pushButton_filter.clicked.connect(self.Filter)
        self.comboBox.currentIndexChanged.connect(ChangeIface)
        self.treeWidget.itemClicked.connect(self.ShowDetails)
        self.pushButton_save.clicked.connect(self.SavePacket2File)
        self.pushButton_return.clicked.connect(self.backsearch)
        self.pushButton_reassemble.clicked.connect(self.resembleFragments)
        self.pushButton_TCPstream.clicked.connect(self.TCPDataFlow)
        #self.commandLinkButton.clicked.connect(SecondWindow)
        QtCore.QMetaObject.connectSlotsByName(SnifferGUI)

    #GUI窗口项目命名
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
        self.pushButton_TCPstream.setText(_translate("SnifferGUI", "追踪TCP流"))
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
                                          _translate("SnifferGUI", "以太网帧"))
        __sortingEnabled = self.listWidget_IP.isSortingEnabled()
        self.listWidget_IP.setSortingEnabled(False)
        self.listWidget_IP.setSortingEnabled(__sortingEnabled)
        self.tabWidget_Details.setTabText(self.tabWidget_Details.indexOf(self.tab_IP),
                                          _translate("SnifferGUI", "IP"))
        __sortingEnabled = self.listWidget_Protocol.isSortingEnabled()
        self.listWidget_Protocol.setSortingEnabled(False)
        self.listWidget_Protocol.setSortingEnabled(__sortingEnabled)
        self.tabWidget_Details.setTabText(self.tabWidget_Details.indexOf(self.tab_Protocol),
                                          _translate("SnifferGUI", "协议"))
        self.tabWidget_Reassemble.setTabText(self.tabWidget_Reassemble.indexOf(self.tab_String),
                                             _translate("SnifferGUI", "内容"))
        self.tabWidget_Reassemble.setTabText(self.tabWidget_Reassemble.indexOf(self.tab_HEX),
                                             _translate("SnifferGUI", "<HEX>"))
        self.tabWidget_Reassemble.setTabText(self.tabWidget_Reassemble.indexOf(self.tab_GBK),
                                             _translate("SnifferGUI", "<GBK>"))
        self.tabWidget_Reassemble.setTabText(self.tabWidget_Reassemble.indexOf(self.tab_UTF8),
                                             _translate("SnifferGUI", "<ASCII>"))
        self.tabWidget_Reassemble.setTabText(self.tabWidget_Reassemble.indexOf(self.tab_ANSI),
                                             _translate("SnifferGUI", "<ANSI>"))
        self.tabWidget_Reassemble.setTabText(self.tabWidget_Reassemble.indexOf(self.tab_PRT),
                                             _translate("SnifferGUI", "<格式化>"))
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

    def threadlisten(self):
        if para.ListenFlag == 1:
            self.thread.start()
        else:
            para.reinitial()
            ChangeIface()
            self.treeWidget.clear()
            para.ListenFlag = 1
            self.thread.start()
    def func(self ,packet):
        para.showpacket = etherPacketLoop(packet[0], len(packet[0]))
        para.showpacket.append(packet[1])  # 加一个时间，年月日秒
        para.showpacket.append(packet[2])  # 加一个总帧长
        para.packet.append(para.showpacket)
        self.displaygui(self.list_to_display(para.showpacket, para.RANK + 1), para.RANK)
        para.RANK += 1
    # 在列表中添加网卡名
    # 停止抓包
    def SniffStop(self):
        para.ListenFlag = 0
        para.RANK = 0
        self.thread.stop()

    def AddIface(self):
        _translate = QtCore.QCoreApplication.translate
        count = 1
        for inface in para.NtwkIf:
            self.comboBox.addItem("")
            self.comboBox.setItemText(count, _translate("SnifferGUI", inface))
            count += 1

    #点击显示详细信息
    def ShowDetails(self):
        self.listWidget.clear()
        self.listWidget_IP.clear()
        self.listWidget_Protocol.clear()
        if para.SearchFlag == 0:
            pktlis = para.packet
        else:
            pktlis = para.filterlist
        _translate = QtCore.QCoreApplication.translate
        pktindex = int(self.treeWidget.selectedItems()[0].text(0)) -1 # 得到索引值

        self.ShowString(pktlis, pktindex)  # 显示string
        # 分片页显示
        self.textBrowser_HEX.setText("NULL")
        # Ethernet 详细信息显示：

        self.listWidget.addItem(QtWidgets.QListWidgetItem())
        self.listWidget.item(0).setText(_translate("SnifferGUI", "目的MAC: " + pktlis[pktindex][0]))


        self.listWidget.addItem(QtWidgets.QListWidgetItem())
        self.listWidget.item(1).setText(_translate("SnifferGUI", "源MAC: " + pktlis[pktindex][1]))


        self.listWidget.addItem(QtWidgets.QListWidgetItem())
        self.listWidget.item(2).setText(_translate("SnifferGUI", "协议名: " + pktlis[pktindex][2]))



        if pktlis[pktindex][2] == 'ARP' :
            self.tabWidget_Details.setTabText(self.tabWidget_Details.indexOf(
                self.tab_IP), _translate("SnifferGUI", "NULL"))
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
                self.tab_IP), _translate("SnifferGUI", "NULL"))
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
            if pktlis[pktindex][11] == 'ICMPv6':
                self.tabWidget_Details.setTabText(self.tabWidget_Details.indexOf(
                    self.tab_Protocol), _translate("SnifferGUI", "ICMPv6"))
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
                #ICMPv6
                self.listWidget_Protocol.addItem(QtWidgets.QListWidgetItem())
                self.listWidget_Protocol.item(0).setText(
                    _translate("SnifferGUI", "提示类型: " + str(pktlis[pktindex][12])))
                self.listWidget_Protocol.addItem(QtWidgets.QListWidgetItem())
                self.listWidget_Protocol.item(1).setText(
                    _translate("SnifferGUI", "校验和: " + str(pktlis[pktindex][13])))
            else:
                self.tabWidget_Details.setTabText(self.tabWidget_Details.indexOf(
                    self.tab_Protocol), _translate("SnifferGUI", "NULL"))
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
        else:
            if pktlis[pktindex][9] == 1 or pktlis[pktindex][10] !=  "0":
                self.textBrowser_HEX.setText("此IP包有分片，请点击菜单栏“重组”查看完整内容")
            else:
                self.textBrowser_HEX.setText("此IP包无分片！")
            self.tabWidget_Details.setTabText(self.tabWidget_Details.indexOf(
                self.tab_IP), _translate("SnifferGUI", "IPv4"))
            if pktlis[pktindex][12] == 'TCP': # 以后需要显示什么再说，先摆在这里
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
                #以下是TCP包的一些附加可选条件们
                #TELNET
                if (pktlis[pktindex][18] == 23 or pktlis[pktindex][17] == 23):
                    self.textBrowser_HEX.setText("TELNET，点击上方数据流重建可以展示完整数据流")
                elif (pktlis[pktindex][18] == 21 or pktlis[pktindex][17] == 21):
                    self.textBrowser_HEX.setText("FTP，点击上方数据流重建可以展示完整数据流")
                elif (pktlis[pktindex][18] == 80 or pktlis[pktindex][17] == 80):
                    self.textBrowser_HEX.setText("HTTP，点击上方数据流重建可以展示完整数据流")
                elif (pktlis[pktindex][17] == 443):
                    self.textBrowser_HEX.setText("TLS，安全套接字SSL加密传输，不建议重组！")
                else:
                    self.textBrowser_HEX.setText("不属于TELNET、FTP控制、HTTP的TCP数据流，点击上方数据流重建可以展示完整数据流")
                #FTP
                #HTTP
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
                    self.tab_Protocol), _translate("SnifferGUI", "IGMP"))
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

            elif pktlis[pktindex][12]  == 'IPv6':
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
                    self.tab_Protocol), _translate("SnifferGUI", "IPv6"))
                self.listWidget_Protocol.addItem(QtWidgets.QListWidgetItem())
                self.listWidget_Protocol.item(0).setText(
                    _translate("SnifferGUI", "IP版本: " + pktlis[pktindex][17]))
                self.listWidget_Protocol.addItem(QtWidgets.QListWidgetItem())
                self.listWidget_Protocol.item(1).setText(
                    _translate("SnifferGUI", "优先级: " + pktlis[pktindex][18]))
                self.listWidget_Protocol.addItem(QtWidgets.QListWidgetItem())
                self.listWidget_Protocol.item(2).setText(
                    _translate("SnifferGUI", "流量标识: " + pktlis[pktindex][19]))
                self.listWidget_Protocol.addItem(QtWidgets.QListWidgetItem())
                self.listWidget_Protocol.item(3).setText(
                    _translate("SnifferGUI", "载荷长度: " + str(pktlis[pktindex][20])))
                self.listWidget_Protocol.addItem(QtWidgets.QListWidgetItem())
                self.listWidget_Protocol.item(4).setText(
                    _translate("SnifferGUI", "下一包头协议: " + str(pktlis[pktindex][21])))
                self.listWidget_Protocol.addItem(QtWidgets.QListWidgetItem())
                self.listWidget_Protocol.item(5).setText(
                    _translate("SnifferGUI", "跳数限制: " + str(pktlis[pktindex][22])))
                self.listWidget_Protocol.addItem(QtWidgets.QListWidgetItem())
                self.listWidget_Protocol.item(6).setText(
                    _translate("SnifferGUI", "源地址: " + str(pktlis[pktindex][23])))
                self.listWidget_Protocol.addItem(QtWidgets.QListWidgetItem())
                self.listWidget_Protocol.item(7).setText(
                    _translate("SnifferGUI", "目的地址: " + str(pktlis[pktindex][24])))
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

    def displaygui(self,showlist, rank):
        #gui_object = ui
        Treeitem = QtWidgets.QTreeWidgetItem(self.treeWidget)
        item_num = 0
        # 根据协议分颜色
        if showlist[3] == 'TCP':
            brush = QtGui.QBrush(QtGui.QColor(141, 211, 199))
            brush.setStyle(QtCore.Qt.SolidPattern)
        elif showlist[3] == 'UDP':
            brush = QtGui.QBrush(QtGui.QColor(255, 255, 179))
            brush.setStyle(QtCore.Qt.SolidPattern)
        elif showlist[3] in ['ARP', 'RARP']:
            brush = QtGui.QBrush(QtGui.QColor(190, 186, 218))
            brush.setStyle(QtCore.Qt.SolidPattern)
        elif showlist[3] in ['IPv6', 'ICMPv6']:
            brush = QtGui.QBrush(QtGui.QColor(251, 128, 114))
            brush.setStyle(QtCore.Qt.SolidPattern)
        elif showlist[3] == 'ICMP':
            brush = QtGui.QBrush(QtGui.QColor(128, 177, 211))
            brush.setStyle(QtCore.Qt.SolidPattern)
        elif showlist[3] == 'IGMP':
            brush = QtGui.QBrush(QtGui.QColor(253, 180, 98))
            brush.setStyle(QtCore.Qt.SolidPattern)
        elif showlist[3] == 'HTTP':
            brush = QtGui.QBrush(QtGui.QColor(179, 222, 105))
            brush.setStyle(QtCore.Qt.SolidPattern)
        elif showlist[3] == 'FTP':
            brush = QtGui.QBrush(QtGui.QColor(252, 205, 229))
            brush.setStyle(QtCore.Qt.SolidPattern)
        elif showlist[3] == 'TLS':
            brush = QtGui.QBrush(QtGui.QColor(255, 237, 111))
            brush.setStyle(QtCore.Qt.SolidPattern)
        elif showlist[3] == 'TELNET':
            brush = QtGui.QBrush(QtGui.QColor(188, 128, 189))
            brush.setStyle(QtCore.Qt.SolidPattern)
        elif showlist[3] == 'OICQ':
            brush = QtGui.QBrush(QtGui.QColor(204, 235, 197))
            brush.setStyle(QtCore.Qt.SolidPattern)
        else:
            brush = QtGui.QBrush(QtGui.QColor(251, 180, 174))
            brush.setStyle(QtCore.Qt.SolidPattern)

        for item in showlist:
            self.treeWidget.topLevelItem(rank).setText(
                item_num, QtCore.QCoreApplication.translate("SnifferGUI", item))

            self.treeWidget.topLevelItem(rank).setBackground(item_num, brush)

            item_num += 1

    # 显示上方窗口内容
    def list_to_display(self, lista, Num):  # 显示上面窗口的src，dst，prt，len等
        listdisplay = []
        if lista[2] in ['ARP', 'RARP']:
            listdisplay = [str(lista[i]) for i in [9, 11, 2]]
            listdisplay.append(lista[-1])  # 长度
            listdisplay.append(lista[-2][:11])  # 日期
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
            if lista[11] == 'ICMPv6':
                listdisplay = [str(lista[i]) for i in [9, 10, 11]]
                listdisplay.append(lista[-1])  # 长度
                listdisplay.append(lista[-2][:11])  # 日期
                listdisplay.append(lista[-2][11:24])  # 时间
                listdisplay.append("ICMPv6" + lista[12])
            else:
                listdisplay = [str(lista[i]) for i in [9, 10, 2]]
                listdisplay.append(lista[-1])  # 长度
                listdisplay.append(lista[-2][:11])  # 日期
                listdisplay.append(lista[-2][11:24])  # 时间
                listdisplay.append(lista[9] + "->" + lista[10])
        # 以下为ipv4族
        else:
            if len(lista) > 12:
                if lista[12] == 'UDP':
                    listdisplay = [str(lista[i]) for i in [14, 15]]
                    if (lista[17] == 8000 or lista[17] == 4000 or lista[18] == 4000 or lista[18] == 8000):
                        listdisplay.append("OICQ")
                        listdisplay.append(lista[-1])  # 长度
                        listdisplay.append(lista[-2][:11])  # 日期
                        listdisplay.append(lista[-2][11:24])  # 时间
                        listdisplay.append("OICQ数据..(UDP)")
                    else:
                        listdisplay.append(lista[12])
                        listdisplay.append(lista[-1])  # 长度
                        listdisplay.append(lista[-2][:11])  # 日期
                        listdisplay.append(lista[-2][11:24])  # 时间
                        listdisplay.append(
                            lista[14] + ":" + str(lista[17]) + "->" + lista[15] + ":" + str(lista[18]))
                elif lista[12] == 'TCP':
                    listdisplay = [str(lista[i]) for i in [14, 15]]
                    if (lista[17] == 23 or lista[18] == 23):
                        listdisplay.append("TELNET")
                        listdisplay.append(lista[-1])  # 长度
                        listdisplay.append(lista[-2][:11])  # 日期
                        listdisplay.append(lista[-2][11:24])  # 时间
                        listdisplay.append("Telnet数据..")
                    elif (lista[17] == 80 or lista[18] == 80):
                        listdisplay.append("HTTP")
                        listdisplay.append(lista[-1])  # 长度
                        listdisplay.append(lista[-2][:11])  # 日期
                        listdisplay.append(lista[-2][11:24])  # 时间
                        st = (lista[4] + lista[21]) * 4 + 14
                        try:
                            index = str.index(lista[-3][st:-1], "HTTP/1.1") + st
                            end = str.index(lista[-3][index:-1], "..") + index
                            a = lista[-3][st:end]
                            listdisplay.append(a)
                        except:
                            listdisplay.append("HTTP协议..")
                    elif (lista[17] == 21):
                        listdisplay.append("FTP")
                        listdisplay.append(lista[-1])  # 长度
                        listdisplay.append(lista[-2][:11])  # 日期
                        listdisplay.append(lista[-2][11:24])  # 时间
                        st = (lista[4] + lista[21]) * 4 + 14
                        listdisplay.append(lista[-3][st:-1][:50])
                    elif (lista[17] == 443):
                        listdisplay.append("TLS")
                        listdisplay.append(lista[-1])  # 长度
                        listdisplay.append(lista[-2][:11])  # 日期
                        listdisplay.append(lista[-2][11:24])  # 时间
                        listdisplay.append("应用数据..")
                    elif (lista[17] == 8000 or lista[17] == 4000 or lista[17] == 4000 or lista[17] == 8000):
                        listdisplay.append("OICQ")
                        listdisplay.append(lista[-1])  # 长度
                        listdisplay.append(lista[-2][:11])  # 日期
                        listdisplay.append(lista[-2][11:24])  # 时间
                        listdisplay.append("OICQ数据..(TCP)")
                    else:
                        listdisplay.append("TCP")
                        listdisplay.append(lista[-1])  # 长度
                        listdisplay.append(lista[-2][:11])  # 日期
                        listdisplay.append(lista[-2][11:24])  # 时间
                        a = "["
                        if lista[23] == 1:
                            a += "URG "
                        if lista[24] == 1:
                            a += "ACK "
                        if lista[25] == 1:
                            a += "PSH "
                        if lista[26] == 1:
                            a += "RST "
                        if lista[27] == 1:
                            a += "SYN "
                        if lista[28] == 1:
                            a += "FIN "
                        if a != "[":
                            a = a[0:-1] + "] "
                        else:
                            a = " "
                        listdisplay.append(a + str(lista[17]) + "->" + str(lista[18]) + "   Seq=" + str(
                            lista[19]) + "  Ack=" + str(lista[20]))
                elif lista[12] == 'IGMP':
                    listdisplay = [str(lista[i]) for i in [14, 15, 12]]
                    listdisplay.append(lista[-1])  # 长度
                    listdisplay.append(lista[-2][:11])  # 日期
                    listdisplay.append(lista[-2][11:24])  # 时间
                    if (lista[17] == '16'):
                        listdisplay.append(lista[14] + "申请加入多播组" + lista[20] + "（组成员报告，IGMPv2）")
                    elif (lista[17] == '12'):
                        listdisplay.append(lista[14] + "申请加入多播组" + lista[20] + "（组成员报告，IGMPv1）")
                    elif (lista[17] == '17'):
                        listdisplay.append(lista[14] + "离开多播组" + lista[20])
                    elif (lista[17] == '11'):
                        listdisplay.append(lista[14] + "向多播组" + lista[20] + "的查询")
                    elif (lista[17] == '2203'):
                        listdisplay.append(lista[14] + "申请离开多播组" + lista[20] + "(ICMPv3)")
                    elif (lista[17] == '2204'):
                        listdisplay.append(lista[14] + "申请加入多播组" + lista[20] + "(ICMPv3)")
                    else:
                        listdisplay.append("其他未知的IGMP操作类型：" + lista[17])
                elif lista[12] == 'ICMP' and lista[17] != '分片包':
                    listdisplay = [str(lista[i]) for i in [14, 15, 12]]
                    listdisplay.append(lista[-1])  # 长度
                    listdisplay.append(lista[-2][:11])  # 日期
                    listdisplay.append(lista[-2][11:24])  # 时间
                    listdisplay.append(lista[17] + ":" + lista[18])
                elif lista[12] == 'ICMP' and lista[17] == '分片包':
                    listdisplay = [str(lista[i]) for i in [14, 15, 12]]
                    listdisplay.append(lista[-1])  # 长度
                    listdisplay.append(lista[-2][:11])  # 日期
                    listdisplay.append(lista[-2][11:24])  # 时间
                    listdisplay.append('ICMP分片')
                elif lista[12] == 'IPv6':
                    listdisplay = [str(lista[i]) for i in [14, 15, 12]]
                    listdisplay.append(lista[-1])  # 长度
                    listdisplay.append(lista[-2][:11])  # 日期
                    listdisplay.append(lista[-2][11:24])  # 时间
                    listdisplay.append(lista[23] + '->' + lista[24])
                else:
                    listdisplay = ['无法识别', '', '']
                    listdisplay.append(lista[-1])  # 长度
                    listdisplay.append(lista[-2][:11])  # 日期
                    listdisplay.append(lista[-2][11:24])  # 时间
                    listdisplay.append('未识别的编号为' + lista[12] + "的传输层协议！")
            else:
                listdisplay = ['无法识别', '', '']
                listdisplay.append(lista[-1])  # 长度
                listdisplay.append(lista[-2][:11])  # 日期
                listdisplay.append(lista[-2][11:24])  # 时间
                listdisplay.append('未识别的编号为' + lista[2] + '的IP层协议！')
        listdisplay.insert(0, str(Num))
        return listdisplay

    # 右下角包内容展示
    def ShowString(self, pktlist, pktindex):
        listHex = pktlist[pktindex][-4]
        listANSI = pktlist[pktindex][-3]
        string_op = ''
        row = int(len(listANSI) / 16)
        if len(listANSI) % 16 != 0:  # 如果刚好整除则不需要加一排
            row += 1
        for i in range(row):
            # 得到0000，0010...
            rowi = 16 * i
            title = hex(rowi)[2:]
            while len(title) < 4:
                title = '0' + title
            string_op += (title + '  ')
            if i != row - 1:
                string_op += listHex[3 * rowi:3 * (rowi + 8)]
                string_op += ' '
                string_op += listHex[3 * (rowi + 8):3 * (rowi + 16)]
                string_op += '     '
                string_op += listANSI[rowi:rowi + 8]
                string_op += ' '
                string_op += listANSI[rowi + 8:rowi + 16]
                string_op += '\n'
            else:
                reminder = len(listANSI) - 16 * (row - 1)
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
        self.textBrowser_String.setText(string_op)

    # 追踪TCP数据流
    def TCPDataFlow(self):
        # 首先分析哪些相关包能够重组
        ## Open the capture file
        pkt_index = int(self.treeWidget.selectedItems()
                        [0].text(0)) - 1  # 得到索引值
        # 如果不是TCP协议的包就直接退
        if (len(para.packet[pkt_index]) < 20 or para.packet[pkt_index][12] != "TCP"):
            return

        if para.SearchFlag == 0:
            src_ip = para.packet[pkt_index][14]  # 源IP
            dst_ip = para.packet[pkt_index][15]  # 目的IP
            src_port = para.packet[pkt_index][17]  # 源端口
            dst_port = para.packet[pkt_index][18]  # 目的端口
        else:
            src_ip = para.filterlist[pkt_index][14]  # 源IP
            dst_ip = para.filterlist[pkt_index][15]  # 目的IP
            src_port = para.filterlist[pkt_index][17]  # 源端口
            dst_port = para.filterlist[pkt_index][18]  # 目的端口
        PktDataHex = ""
        PktLst = []
        PktDataANSI = ""
        PktDataOrigin = ""
        count = 0
        for packets in para.packet:
            if (len(packets) < 20 or packets[12] != "TCP"):
                pass
            elif ((packets[14] == src_ip) and (packets[15] == dst_ip) and (packets[17] == src_port) and (
                packets[18] == dst_port)):
                count += 1
                PktLst.append(
                    (packets[-3], packets[-4], packets[-5], packets[19], packets[4] + packets[21]))
                # 包数据[ANSI,Hex,源码(GBK),seq,偏移量]
        PktLst = sorted(PktLst, key=lambda x: int(x[3]))
        ##加工一下
        fp = open("nxm", "wb")
        for fragments in PktLst:
            start = fragments[-1] * 4 + 14
            PktDataANSI = PktDataANSI + fragments[0][start:]
            PktDataHex = PktDataHex + fragments[1][4 * start:]
            PktDataOrigin = PktDataOrigin + fragments[2][start:]
            fp.write(bytes(fragments[2][start:], "latin-1"))

        PktDataGBK = PktDataOrigin.encode("latin-1").decode("gbk", 'ignore')

        conv = Ansi2HTMLConverter()
        PktDataHtml = conv.convert(PktDataGBK)
        PktDataHtml = str.replace(PktDataHtml, "\n</span>", "</span>")

        self.textBrowser_HEX.setText(PktDataHex)
        self.textBrowser_UTF8.setText(PktDataANSI)
        self.textBrowser_GBK.setText(PktDataGBK)
        self.textBrowser_ANSI.setText(PktDataOrigin)
        self.textBrowser_PRT.setHtml(PktDataHtml)
        fp.close()

    # Ip分片重组
    def resembleFragments(self):
        # 首先分析哪些相关包能够重组
        ## Open the capture file
        pkt_index = int(ui.treeWidget.selectedItems()
                        [0].text(0)) - 1  # 得到索引值

        if para.SearchFlag == 0:
            id = para.packet[pkt_index][7]  # 标识
        else:
            id = para.filterlist[pkt_index][7]
        PktDataHex = ""
        PktLst = []
        PktDataANSI = ""
        count = 0
        for packets in para.packet:
            if (len(packets) < 8):
                pass
            elif ((packets[2] == "IPv4") and (packets[7] == id)):
                count += 1
                PktLst.append((packets[-3], packets[-4],
                               packets[10], packets[4]))
        PktLst = sorted(PktLst, key=lambda x: int(x[2]))
        ##加工一下
        for fragments in PktLst:
            # 考虑一下选项吧那就！
            start = fragments[-1] * 4 + 14  # 首部长度是5，*4得到20个字节的IP头

            PktDataANSI = PktDataANSI + fragments[0][start:]
            PktDataHex = PktDataHex + fragments[1][3 * start:]
            # PktDataGBK = PktDataANSI.encode("gbk")
        self.ReassembleShow(PktDataHex, PktDataANSI, count)

    def ReassembleShow(self ,PktDataHex, PktDataANSI, Count):
        listHex = PktDataHex
        listANSI = PktDataANSI
        if Count < 1:
            string_op = 'NULL'
        else:
            string_op = '当前字段由%d个包重组\n' % Count
            row = int(len(listANSI) / 16)
            if len(listANSI) % 16 != 0:  # 如果刚好整除则不需要加一排
                row += 1
            for i in range(row):
                # 得到0000，0010...
                rowi = 16 * i
                title = hex(rowi)[2:]
                while len(title) < 4:
                    title = '0' + title
                string_op += (title + '  ')
                if i != row - 1:
                    string_op += listHex[3 * rowi:3 * (rowi + 8)]
                    string_op += ' '
                    string_op += listHex[3 * (rowi + 8):3 * (rowi + 16)]
                    string_op += '     '
                    string_op += listANSI[rowi:rowi + 8]
                    string_op += ' '
                    string_op += listANSI[rowi + 8:rowi + 16]
                    string_op += '\n'
                else:
                    reminder = len(listANSI) - 16 * (row - 1)
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
        ui.textBrowser_HEX.setText(string_op)

    # 返回搜索
    def backsearch(self):
        para.SearchFlag = 0
        self.treeWidget.clear()
        self.lineEdit.clear()
        i = 0
        for pkt in para.packet:
            self.displaygui(self.list_to_display(pkt, i + 1), i)
            i += 1

        # 抓包过滤函数，这个函数要在运行抓包指令开始之前跑一遍
    def PacketFilter(self , filter):
        fcode = bpf_program()
        netmask = 0xffffff
        # filter = "tcp"
        ## compile the filter
        if pcap_compile(para.fp, byref(fcode), filter.encode("utf-8"), 1, netmask) < 0:
            pcap_close(para.fp)
            sys.exit(-3)

        ## set the filter

        if pcap_setfilter(para.fp, byref(fcode)) < 0:
            pcap_close(para.fp)
            sys.exit(-4)

        # 搜索过滤函数
    def Filter(self, filter):
        MACaddr = re.compile(r'([A-Fa-f0-9]{2}-){5}[A-Fa-f0-9]{2}')
        IPaddr = re.compile(
            r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)')
        search_field = self.lineEdit.text().lower()  # 得到搜索字段的小写
        filterlist = para.filterlist = []
        if search_field != '':
            para.SearchFlag = 1  # 显示搜索列表
            para.ListenFlag = 0  # 停止抓包
        if search_field in ['tcp', 'udp', 'icmp', 'igmp', 'ipv6', 'arp', 'rarp', 'icmpv6']:
            protocol = search_field  # 则搜索为协议
            if protocol == 'tcp':
                self.treeWidget.clear()
                for pkt in para.packet:
                    try:
                        if pkt[12] == "TCP":
                            filterlist.append(pkt)
                    except:
                        pass
                total = len(filterlist)
                for i in range(total):
                    self.displaygui(self.list_to_display(filterlist[i], i + 1), i)

            elif protocol == 'udp':
                self.treeWidget.clear()
                for pkt in para.packet:
                    try:
                        if pkt[12] == "UDP":
                            filterlist.append(pkt)
                    except:
                        pass
                total = len(filterlist)
                for i in range(total):
                    self.displaygui(self.list_to_display(filterlist[i], i + 1), i)

            elif protocol == 'icmp':
                self.treeWidget.clear()
                for pkt in para.packet:
                    try:
                        if pkt[12] =="ICMP":
                            filterlist.append(pkt)
                    except:
                        pass
                total = len(filterlist)
                for i in range(total):
                    self.displaygui(self.list_to_display(filterlist[i], i + 1), i)

            elif protocol == 'igmp':
                self.treeWidget.clear()
                for pkt in para.packet:
                    try:
                        if pkt[12] == "IGMP":
                            filterlist.append(pkt)
                    except:
                        pass
                total = len(filterlist)
                for i in range(total):
                    self.displaygui(self.list_to_display(filterlist[i], i + 1), i)

            elif protocol == 'ipv6':
                self.treeWidget.clear()
                for pkt in para.packet:
                    if pkt[2] == 'IPv6':
                        filterlist.append(pkt)
                total = len(filterlist)
                for i in range(total):
                    self.displaygui(self.list_to_display(filterlist[i], i + 1), i)
            elif protocol == 'icmpv6':
                self.treeWidget.clear()
                for pkt in para.packet:
                    try:
                        if pkt[11] == 'ICMPv6':
                            filterlist.append(pkt)
                    except:
                        pass
                total = len(filterlist)
                for i in range(total):
                    self.displaygui(self.list_to_display(filterlist[i], i + 1), i)

            elif protocol == 'arp':
                self.treeWidget.clear()
                for pkt in para.packet:
                    if pkt[2] == 'ARP':
                        filterlist.append(pkt)
                total = len(filterlist)
                for i in range(total):
                    self.displaygui(self.list_to_display(filterlist[i], i + 1), i)

            elif protocol == 'rarp':
                self.treeWidget.clear()
                for pkt in para.packet:
                    if pkt[2] == 'PARP':
                        filterlist.append(pkt)
                total = len(filterlist)
                for i in range(total):
                    self.displaygui(self.list_to_display(filterlist[i], i + 1), i)

        # 输入为空，可以返回原始列表（全部包显示）
        elif search_field in ['ftp', 'http', 'tls', 'telnet', 'oicq']:
            protocol = search_field  # 则搜索为协议
            if protocol == 'ftp':
                self.treeWidget.clear()
                for pkt in para.packet:
                    try:
                        if pkt[17] == 21:
                            filterlist.append(pkt)
                    except:
                        pass
                total = len(filterlist)
                for i in range(total):
                    self.displaygui(self.list_to_display(filterlist[i], i + 1), i)

            elif protocol == 'http':
                self.treeWidget.clear()
                for pkt in para.packet:
                    try:
                        if pkt[17] == 80 or pkt[18] == 80:
                            filterlist.append(pkt)
                    except:
                        pass
                total = len(filterlist)
                for i in range(total):
                    self.displaygui(self.list_to_display(filterlist[i], i + 1), i)

            elif protocol == 'tls':
                self.treeWidget.clear()
                for pkt in para.packet:
                    try:
                        if pkt[17] == 443:
                            filterlist.append(pkt)
                    except:
                        pass
                total = len(filterlist)
                for i in range(total):
                    self.displaygui(self.list_to_display(filterlist[i], i + 1), i)

            elif protocol == 'telnet':
                self.treeWidget.clear()
                for pkt in para.packet:
                    try:
                        if pkt[17] == 23 or pkt[18] == 23:
                            filterlist.append(pkt)
                    except:
                        pass
                total = len(filterlist)
                for i in range(total):
                    self.displaygui(self.list_to_display(filterlist[i], i + 1), i)
            else: #oicq
                self.treeWidget.clear()
                for pkt in para.packet:
                    try:
                        if pkt[17] == 8000 or pkt[17] == 4000 or pkt[18] == 4000 or pkt[18] == 8000:
                            filterlist.append(pkt)
                    except:
                        pass
                total = len(filterlist)
                for i in range(total):
                    self.displaygui(self.list_to_display(filterlist[i], i + 1), i)

        elif search_field == '':
            self.treeWidget.clear()
            i = 0
            for pkt in para.packet:
                self.displaygui(self.list_to_display(pkt, i + 1), i)
                i += 1
        elif re.match(MACaddr, search_field):  # 若输入为mac地址格式
            self.treeWidget.clear()
            for pkt in para.packet:
                if search_field in pkt[0] or search_field in pkt[1]:
                    filterlist.append(pkt)
            total = len(filterlist)
            for i in range(total):
                self.displaygui(self.list_to_display(filterlist[i], i + 1), i)


        elif re.match(IPaddr, search_field):  # 若输入为ip地址格式
            self.treeWidget.clear()
            for pkt in para.packet:
                if pkt[2] in ['ARP', 'RARP']:
                    if search_field in [pkt[9], pkt[11]]:
                        filterlist.append(pkt)
                elif pkt[2] == 'IPv6':
                    if search_field in [pkt[9], pkt[10]]:
                        filterlist.append(pkt)
                else:
                    if len(pkt) > 12:
                        if search_field in [pkt[14], pkt[15]]:
                            filterlist.append(pkt)
                    else:
                        pass
            total = len(filterlist)
            for i in range(total):
                self.displaygui(self.list_to_display(filterlist[i], i + 1), i)
        else:
            self.treeWidget.clear()
            for pkt in para.packet:
                if search_field in pkt[-3].lower():
                    filterlist.append(pkt)
            total = len(filterlist)
            for i in range(total):
                self.displaygui(self.list_to_display(filterlist[i], i + 1), i)

#第二窗口注释


#分片重组显示


#选择网卡
def ChangeIface(): # 选定网卡
    local_alldevs = para.alldevs
    ifaceindex = ui.comboBox.currentIndex()
    for i in range(ifaceindex - 1):
        local_alldevs = local_alldevs.contents.next
    para.fp = pcap_open_live(
        local_alldevs.contents.name, 65536, 1, 1000, para.errbuf)
    #pcap_setbuff(para.fp,65536)
    para.DUMPFILE = pcap_dump_open(para.fp, "temp".encode("utf-8"))

class Catching(QThread):
    sinOut = pyqtSignal(list)
    def __init__(self ,parent = None):
        super(Catching, self).__init__(parent)
        self.stoped = False
        self.mutex = QMutex()

    def run(self):
        with QMutexLocker(self.mutex):
            self.stoped = False
        para.RANK = 0
        while para.ListenFlag:
            res = pcap_next_ex(para.fp, byref(para.header), byref(para.pkt_data))
            while (res >= 0) and para.ListenFlag:
                if (res == 0):
                    ## 超时
                    break
                time1 = str(time.strftime("%Y-%m-%d %H:%M:%S.", time.localtime(para.header.contents.ts.tv_sec))) + str(
                    "%d" % (para.header.contents.ts.tv_usec))
                length = str("%ld" % (para.header.contents.len))
                # for i in range(para.header.contents.len):
                a = [[]]
                for i in range(para.header.contents.len):
                    a[0].append(para.pkt_data[i])
                #para.showpacket = etherPacketLoop(para.pkt_data, para.header.contents.len)
                #para.showpacket.append(time1)  # 加一个时间，年月日秒
                #para.showpacket.append(length)  # 加一个总帧长
                a.append(time1)
                a.append(length)
                #para.packet.append(para.showpacket)
                # packet为格式化的包
                # 下一步来个显示函数
                #self.sinOut.emit("aa")
                self.sinOut.emit(a)
                #displaygui(list_to_display(para.showpacket, para.RANK + 1), para.RANK)
                # 将包内容填到缓存里
                pcap_dump(para.DUMPFILE, para.header, para.pkt_data)
                res = pcap_next_ex(para.fp, byref(para.header), byref(para.pkt_data))
            if (res == -1):
                sys.exit(-1)
        pcap_dump_close(para.DUMPFILE)
        pcap_close(para.fp)
        while True:
            if self.stoped:
                return

    def stop(self):
        with QMutexLocker(self.mutex):
            self.stoped = True
#抓包函数





def MainWindows():
    global ui
    #para.queue = multiprocessing.Queue()
    #para.Process = threading.Thread(target=ListenDevice)#,name = "抓包" ,args=(para.queue,))
    app = QtWidgets.QApplication(sys.argv)
    w = QtWidgets.QMainWindow()
    SecWin = Ui_Dialog()
    ui = Ui_SnifferGUI()
    ui.setupUi(w)
    ui.commandLinkButton.clicked.connect(SecWin.handle_click) # 点commandLinkButton弹出第二个窗口；
    w.show()
    sys.exit(app.exec_())

#主函数
def main():
    printDevices()
    MainWindows()


if __name__ == '__main__':
    main()
