from ctypes import *
from winpcapy import *
import sys
import string
import platform
import time
from  readPackets import *
class Parameter():
    #常量定义
    def __init__(self):
        self.ListenFlag = 1
        self.RANK = 0    #当前包最大索引数
        self.selectRANK = 0 #所选包索引
        self.tmpRANK = 0#遍历用索引
        self.LINE_LEN=16
        self.alldevs=POINTER(pcap_if_t)()
        self.d=POINTER(pcap_if_t)
        self.fp=pcap_t
        self.errbuf= create_string_buffer(PCAP_ERRBUF_SIZE)
        self.header=POINTER(pcap_pkthdr)()
        self.pkt_data=POINTER(c_ubyte)()
        self.deviceNumber = 0
#输出适配器列表
para = Parameter()

def printDevices():
    if (pcap_findalldevs(byref(para.alldevs), para.errbuf) == -1):
        print ("寻找适配器出错: %s\n", para.errbuf.value)
        sys.exit(1)
    ## Print the list
    d=para.alldevs.contents
    while d:
        para.deviceNumber = para.deviceNumber + 1
        print ("%d. %s" % (para.deviceNumber, d.name))
        if (d.description):
            print (" (%s)\n" % (d.description))
        else:
            print (" (没有相关的描述)\n")
        if d.next:
             d=d.next.contents
        else:
             d=False
    if (para.deviceNumber==0):
        print ("\n没有找到相关的网络接口，请确保WinPcap已经安装！\n")
        sys.exit(-1)

#打开指定适配器 inum为适配器标号
def openDevice(inum):
    if inum in string.digits:
        inum = int(inum)
    else:
        inum = 0
    if ((inum < 1) | (inum > para.deviceNumber)):
        print("\n网络接口代码已经超出范围。\n")
        ## 释放设备列表
        pcap_freealldevs(para.alldevs)
        sys.exit(-1)

    d = para.alldevs
    for i in range(0, inum - 1):
        d = d.contents.next
    para.fp = pcap_open_live(d.contents.name, 65536, 1, 1000, para.errbuf)
    if (para.fp == None):
        print("\n打开适配器错误\n")
        ##释放设备列表
        pcap_freealldevs(para.alldevs)
        sys.exit(-1)
    #缓存文件 全局变量
    para.DUMPFILE = pcap_dump_open(para.fp, "temp".encode("utf-8"))

#监听函数
def ListenDevice():
    para.RANK = 0
    while(para.ListenFlag):
        res = pcap_next_ex(para.fp, byref(para.header), byref(para.pkt_data))
        while (res >= 0):
            if (res == 0):
                ## 超时
                break
            print(time.strftime("%Y-%m-%d %H:%M:%S.", time.localtime(para.header.contents.ts.tv_sec)), end='')
            print("%d(%ld)\n" % (para.header.contents.ts.tv_usec, para.header.contents.len))
            packet = etherPacketLoop(para.pkt_data, para.header.contents.len)
            packet.append(para.RANK)
            '''if (packet[2]=="IPv4" and ~packet[8] ):
                #如果是ipv4  且 有分包
                pcap_dump(para.DUMPFILE, para.header, para.pkt_data)'''
            print (packet)
            #packet为格式化的包
            #下一步来个显示函数
            para.RANK += 1

            #将包内容填到缓存里
            pcap_dump(para.DUMPFILE, para.header, para.pkt_data)
            res = pcap_next_ex(para.fp, byref(para.header), byref(para.pkt_data))
        if (res == -1):
            print("读包失败: %s\n" % pcap_geterr(para.fp))
            sys.exit(-1)
    pcap_close(para.fp)

#将标号为n的包存储下来，命名格式为 当前时间.pcap
def SavePacket2File(n):
    DHAND = CFUNCTYPE(None, POINTER(c_ubyte), POINTER(pcap_pkthdr), POINTER(c_ubyte))
    readPara = Parameter()
    ##每个记录的包被查看都被调用一次
    def _dispatcher_handler(temp1, header, pkt_data):
        ## 只有是当要保存的包时才保存，其他都略过
        if (readPara.selectRANK == para.selectRANK):
            pcap_dump(readFilename.encode("utf-8"), readPara.header, readPara.pkt_data)
        else:
            return
        readPara.selectRANK += 1

    dispatcher_handler = DHAND(_dispatcher_handler)
    readFilename = "%s.pcap" % time.asctime()
    ## 打开缓存文件
    readPara.fp = pcap_open_offline("temp".encode("utf-8"), readPara.errbuf)
    ## 读取并找寻到相关标号，提取保存
    pcap_loop(readPara.fp, para.selectRANK + 1, dispatcher_handler, None)
    pcap_close(readPara.fp)

#Ip分片重组,输入为id和
def resembleFragments(id):
    #首先分析哪些相关包能够重组
    ## Open the capture file
    para.fp = pcap_open_offline("temp".encode("utf-8"), para.errbuf)
    if not bool(fp):
        print("\n未找到缓存文件temp\n")
    ## Retrieve the packets from the file
    res = pcap_next_ex(para.fp, byref(para.header), byref(para.pkt_data))

    ##加工一下
    # 用于存储每个数据头的列表
    fragments = []
    totallen = 34
    #每个列表是一个同包的列表，首个元素是对应的id ，然后是(pkt_data,header,数据偏移量)
    while (res >= 0):
        ## print pkt timestamp and pkt len
        ##  Print the packet
        a.append(create_string_buffer(para.header.contents.len))
        protocol = "%.2x%.2x" % (para.pkt_data[12], para.pkt_data[13])
        tmp = ""
        tmp = tmp + "%.2x" % pkt_data[20]
        tmp = tmp + "%.2x" % pkt_data[21]
        tmp1 = int(tmp[0], 16)
        ip_DF = (tmp1 // 4) % 2
        ip_MF = (tmp1 // 2) % 2
        ip_off = int(tmp[3:], 16)
        thisid = "%.2x%.2x" % (para.pkt_data[18], para.pkt_data[19])
        #偏移量

        if (protocol == '0800' and (ip_MF == 1 or ip_off > 0) and thisid == id):
            fragments.append((create_string_buffer(para.header.contents.len),create_string_buffer(16),ip_off))
            totallen += para.header.contents.len - 34
            for i in range(1, para.header.contents.len + 1):
                fragments[-1][0][i - 1] = para.pkt_data[i - 1]
                #拷贝数据到指定的内存段
            for i in range(16):
                fragments[-1][1][i] = para.header[i]
                #拷贝头部到指定的内存段

        print("\n\n")
        res = pcap_next_ex(para.fp, byref(para.header), byref(para.pkt_data))
    #读完包开始重拼
    pktbuf = create_string_buffer(totallen)
    #存数据
    headbuf = create_string_buffer(16)
    #存头部
    PKTDATA = POINTER(c_ubyte)()
    P1 = POINTER(c_ubyte)()
    PKTDATA.contents = pktbuf
    #两个指针
    fragments = sorted(fragments,key = lambda x:x[2])
    P1.contents =  fragments[0][0]
    tmpoff = len(fragments[0][0])
    for i in range(len(fragments[0][0])):
        PKTDATA[i] = P1[i]
        #按偏移量重排
    for frag in fragments[1:]:
        P1.contents = frag[0]

        for i in range(len(frag[0])):
            PKTDATA[tmpoff + i] = P1[i]
        tmpoff += len(frag[0])
    PktDataHex = ""
    PktDataUtf_8 = ""
    for i in range(tmpoff):
        PktDataHex = PktDataHex + "%.2x " % PKTDATA[i]
    for i in range(tmpoff):
        PktDataUtf_8 = PktDataASCII + chr(PKTDATA[i])
    pcap_close(para.fp)
    return [PktDataHex,PktDataUtf_8]
'''
#Ip分片重组
def resembleFragments():
    #首先分析哪些包能够重组
    ## Open the capture file
    para.fp = pcap_open_offline("temp".encode("utf-8"), para.errbuf)
    if not bool(fp):
        print("\n未找到缓存文件temp\n")
    ## Retrieve the packets from the file
    res = pcap_next_ex(para.fp, byref(para.header), byref(para.pkt_data))

    ##加工一下
    # 用于存储每个数据头的列表
    fragments = []
    #每个列表是一个同包的列表，首个元素是对应的id ，然后是(pkt_data,header,数据偏移量)
    while (res >= 0):
        ## print pkt timestamp and pkt len
        print("%ld:%ld (%ld)\n" % (para.header.contents.ts.tv_sec, para.header.contents.ts.tv_usec, para.header.contents.len))
        ##  Print the packet
        a.append(create_string_buffer(para.header.contents.len))
        protocol = "%.2x.2x" % (para.pkt_data[12],para.pkt_data[13])
        tmp = ""
        tmp = tmp + "%.2x" % pkt_data[20]
        tmp = tmp + "%.2x" % pkt_data[21]
        tmp1 = int(tmp[0], 16)
        ip_DF = (tmp1 // 4) % 2
        ip_MF = (tmp1 // 2) % 2
        ip_off = int(tmp[3:], 16)
        #偏移量
        if (protocol == '0800' and (ip_MF == 1 or ip_off > 0)):
            id = "%.2x%.2x" % (para.pkt_data[18],para.pkt_data[19])
            if (len(fragments) == 0) :
                fragments.append([])
                fragments[0].append(id)
                fragments[0].append((create_string_buffer(para.header.contents.len),create_string_buffer(16),ip_off))
                for i in range(1, para.header.contents.len + 1):
                    fragments[0][1][0][i - 1] = para.pkt_data[i - 1]
                    #拷贝数据到指定的内存段
                for i in range(16):
                    fragments[0][1][1][i] = para.header[i]
                    #拷贝头部到指定的内存段
            else:
                flag = -1
                for i in range(len(fragments)):
                    if (fragments[i][0] == id):
                        flag = i
                if (flag >=0):
                    #找到同属一个IP包的元素了
                    fragments[i].append((create_string_buffer(para.header.contents.len),create_string_buffer(16) ,ip_off))
                    for j in range(1, para.header.contents.len + 1):
                        fragments[i][-1][0][j - 1] = para.pkt_data[j - 1]
                        # 拷贝数据到指定的内存段
                    for j in range(16):
                        fragments[i][-1][1][j] = para.header[j]
                        # 拷贝头部到指定的内存段
                else :
                    fragments.append([id,(create_string_buffer(para.header.contents.len), create_string_buffer(16), ip_off)])
                    #没有同属一个包的，新建一个数组
                    for j in range(1, para.header.contents.len + 1):
                        fragments[-1][1][0][j - 1] = para.pkt_data[j - 1]
                        # 拷贝数据到指定的内存段
                    for j in range(16):
                        fragments[-1][1][1][j] = para.header[j]
                        # 拷贝头部到指定的内存段

        print("\n\n")
        res = pcap_next_ex(para.fp, byref(para.header), byref(para.pkt_data))
    #读完包开始重拼
    pktbuf = create_string_buffer(len(a[0]) + len(a[1]) - 34)
    #存数据
    headbuf = create_string_buffer(16)
    #存头部
    PKTDATA = POINTER(c_ubyte)()
    HEADER = POINTER(pcap_pkthdr)()
    P1 = POINTER(c_ubyte)()
    #两个指针
    pcap_close(para.fp)
    para.fp = pcap_t
    dumpfile = pcap_dump_open(para.fp, "ResembledPackets".encode("utf-8"))
    #打开保存文件
    for packetsList in fragments:
        #每一个重拼包
        packetsList[1:] = sorted(packetsList[1:],key = lambda x:x[2])
        #按偏移量重排
        totallen = 34
        # 求总长度
        for ipFrag in packetsList[1:]:
            #每一个分片元组
            HEADER.contents = ipFrag[1]
            #指向数据头部
            totallen += len(HEADER.contents.len - 34)
        ResembledPacket = create_string_buffer(totallen)
        #创建一个总长的缓冲区
        P1.contents = ResembledPacket
        #对第一个分片移动到缓冲区里
        ipFrag = packetsList[1]
        PKTDATA.contents = ipFrag[0]
        for i in range(len(ipFrag[0])):
            P1[i] = PKTDATA[i]
            #把第一个分片拷贝到产生包中
        off = len(ipFrag[0])
        #偏移量
        #剩下的分片操作
        for ipFrag in packetsList[2:]:
            #每一个分片元组
            HEADER.contents = ipFrag[1]
            PKTDATA.contents = ipFrag[0]
            for i in range(HEADER.contents.len - 34):
                P1[i + off] = PKTDATA[i + 34]
            off = off + HEADER.contents.len - 34
        #接下来要保存了
        HEADER.contents.len = off
        HEADER.contents.caplen = off
        pcap_dump(dumpfile, HEADER, P1)
    pcap_close(para.fp)
'''

#包过滤
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
printDevices()
num = input("请输入数字：")

openDevice(num)
#PacketFilter()
ListenDevice()