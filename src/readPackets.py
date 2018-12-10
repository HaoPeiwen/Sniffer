from ctypes import *
import types

#以太网帧处理
def etherPacketLoop(pkt_data,len):
    ether = []
    src = ''
    dst = ''
    protocol = ''
    for i in range(5):
        src = src + "%.2x-" % (pkt_data[i])
    src = src + ("%.2x" % pkt_data[5])
    #0-5为目的MAC----------------------------------------0
    for i in range(5):
        dst = dst + "%.2x-" % (pkt_data[i + 6])
    dst = dst + ("%.2x" % pkt_data[11])
    #6-11为源MAC----------------------------------------1
    for i in range(2):
        protocol = protocol + ("%.2x" % pkt_data[i + 12])
    #12、13为协议类型----------------------------------------2
    ether.append(src)
    ether.append(dst)
    #ether.append(protocol)
    if (protocol == "0806"):
        #ARP
        ether.append("ARP")
        ether += ARPPacketLoop(pkt_data, len)
    elif(protocol == "8035"):
        #RARP
        ether.append("RARP")
        ether += RARPPacketLoop(pkt_data, len)
    elif (protocol == "0800"):
        # IP
        ether.append("IPv4")
        ether += IPv4PacketLoop(pkt_data, len)
    elif (protocol == "86dd"):
        # IP
        ether.append("IPv6")
        ether += IPv6PacketLoop(pkt_data, len, 14)
    else:
        ether.append(protocol)
        data = ""
        dataANSI = ""
        for i in range(len):
            data = data + "%.2x " % (pkt_data[i])
            if (pkt_data[i] > 31 and pkt_data[i] < 127):
                dataANSI = dataANSI + chr(pkt_data[i])
            else:
                dataANSI = dataANSI + '.'
        ether.append(data)
        ether.append(dataANSI)

    return ether

#以太网包头为14字节长
#ARP包处理
def ARPPacketLoop(pkt_data,len):
    #从第14字节开始为ARP包内容
    packet = []
    #硬件类型----------------------------------------3
    hardType = ""
    for i in range(2):
        hardType = hardType + "%.2x" % (pkt_data[ i + 14 ])
    packet.append(hardType)

    # 协议类型----------------------------------------4
    ar_pro = ""
    for i in range(2):
        ar_pro = ar_pro + "%.2x" % (pkt_data[i + 16])
    packet.append(ar_pro)

    # 硬件地址长度----------------------------------------5
    ar_hln = ""
    ar_hln = ar_hln + "%d" % (pkt_data[18])
    packet.append(ar_hln)

    # 协议地址长度----------------------------------------6
    ar_pln = ""
    ar_pln = ar_pln + "%d" % (pkt_data[19])
    packet.append(ar_pln)

    # 操作码----------------------------------------7
    ar_op = ""
    for i in range(2):
        ar_op = ar_op + "%.2x" % (pkt_data[i + 20])
    if (ar_op == "0001"):
        packet.append("ARP请求")
    elif (ar_op == "0002"):
        packet.append("ARP回显")
    else:
        packet.append("未知操作")

    #发送者硬件地址----------------------------------------8
    arp_sha = ""
    for i in range(5):
        arp_sha = arp_sha + "%.2x-" % (pkt_data[i+22])
    arp_sha = arp_sha + ("%.2x" % pkt_data[27])
    packet.append(arp_sha)

    #发送者IP地址----------------------------------------9
    arp_spa = ""
    for i in range(3):
        arp_spa = arp_spa + "%d." % (pkt_data[i+28])
    arp_spa = arp_spa + ("%d" % pkt_data[31])
    packet.append(arp_spa)

    #目标硬件地址----------------------------------------10
    arp_tha = ""
    for i in range(5):
        arp_tha = arp_tha + "%.2x-" % (pkt_data[i+32])
    arp_tha = arp_tha + ("%.2x" % pkt_data[37])
    packet.append(arp_tha)

    # 目标IP地址----------------------------------------11
    arp_tpa = ""
    for i in range(3):
        arp_tpa = arp_tpa + "%d." % (pkt_data[i + 38])
    arp_tpa = arp_tpa + ("%d" % pkt_data[41])
    packet.append(arp_tpa)
    # HEX----------------------------------------12
    # ANSI----------------------------------------13
    arp_data = ""
    arp_dataANSI = ""
    for i in range(len):
        arp_data = arp_data + "%.2x " % (pkt_data[i])
        if (pkt_data[i] > 31 and pkt_data[i] < 127):
            arp_dataANSI = arp_dataANSI + chr(pkt_data[i])
        else:
            arp_dataANSI = arp_dataANSI + '.'
    packet.append(arp_data)
    packet.append(arp_dataANSI)
    return packet

#RARP包处理
def RARPPacketLoop(pkt_data,len):
    #从第14字节开始为ARP包内容
    packet = []
    #硬件类型
    hardType = ""
    for i in range(2):
        hardType = hardType + "%.2x" % (pkt_data[ i + 14 ])
    packet.append(hardType)

    # 协议类型
    ar_pro = ""
    for i in range(2):
        ar_pro = ar_pro + "%.2x" % (pkt_data[i + 16])
    packet.append(ar_pro)

    # 硬件地址长度
    ar_hln = ""
    ar_hln = ar_hln + "%d" % (pkt_data[18])
    packet.append(ar_hln)

    # 协议地址长度
    ar_pln = ""
    ar_pln = ar_pln + "%d" % (pkt_data[19])
    packet.append(ar_pln)

    # 操作码
    ar_op = ""
    for i in range(2):
        ar_op = ar_op + "%.2x" % (pkt_data[i + 20])
    if (ar_op == "0003"):
        packet.append("RARP请求")
    elif (ar_op == "0004"):
        packet.append("RARP应答")
    else:
        packet.append("未知操作")

    #发送者硬件地址
    arp_sha = ""
    for i in range(5):
        arp_sha = arp_sha + "%.2x-" % (pkt_data[i+21])
    arp_sha = arp_sha + ("%.2x" % pkt_data[26])
    packet.append(arp_sha)

    #发送者IP地址
    arp_spa = ""
    for i in range(3):
        arp_spa = arp_spa + "%d." % (pkt_data[i+27])
    arp_spa = arp_spa + ("%d" % pkt_data[30])
    packet.append(arp_spa)

    #目标硬件地址
    arp_tha = ""
    for i in range(5):
        arp_tha = arp_tha + "%.2x-" % (pkt_data[i+31])
    arp_tha = arp_tha + ("%.2x" % pkt_data[36])
    packet.append(arp_tha)

    # 目标IP地址
    arp_tpa = ""
    for i in range(3):
        arp_tpa = arp_tpa + "%d." % (pkt_data[i + 37])
    arp_tpa = arp_tpa + ("%d" % pkt_data[40])
    packet.append(arp_tpa)
    # 剩余数据
    rarp_data = ""
    rarp_dataANSI = ""
    for i in range(len):
        rarp_data = rarp_data + "%.2x " % (pkt_data[i])
        if (pkt_data[i] > 31 and pkt_data[i] < 127):
            rarp_dataANSI = rarp_dataANSI + chr(pkt_data[i])
        else:
            rarp_dataANSI = rarp_dataANSI + '.'
    packet.append(rarp_data)
    packet.append(rarp_dataANSI)
    return packet

#IPv4包处理
def IPv4PacketLoop(pkt_data,len):
    #从第14字节开始为IPv4包内容
    packet = []
    #第一个字节高四位是IP版本号，后四位是首部长度
    tmp = ""
    tmp = tmp + "%.2x" % (pkt_data[14])
    #ip版本----------------------------------------3
    ip_v = ""
    ip_v = ip_v + "%d" % (int(tmp[0],16))
    packet.append(ip_v)
    # 首部长度----------------------------------------4
    ip_hl = (int(tmp[1],16))
    packet.append(ip_hl)

    # 服务类型，一个字节直接输出了，懒得处理了----------------------------------------5
    ip_tos = ""
    ip_tos = ip_tos +  "%.2x" % (pkt_data[15])
    packet.append(ip_tos)

    # 全长----------------------------------------6
    tmp = ""
    for i in range(2):
        tmp = tmp + "%.2x" % (pkt_data[ i +16 ])
    ip_len = int(tmp,16)
    packet.append(ip_len)

    #标识符生存时间----------------------------------------7
    tmp = ""
    for i in range(2):
        tmp = tmp + "%.2x" % (pkt_data[i + 18])
    ip_id = ""
    ip_id = ip_id + "%d" %(int(tmp, 16))
    packet.append(ip_id)

    #2位标志(DF,MF)和13位片偏移
    #DF禁止分片标识----------------------------------------8
    #MF更多分片标识----------------------------------------9
    #off片内偏移----------------------------------------10
    tmp = ""
    tmp = tmp + "%.2x" % pkt_data[20]
    tmp = tmp + "%.2x" % pkt_data[21]
    tmp1 = int(tmp[0],16)
    ip_DF = (tmp1 // 4 )% 2
    ip_MF = (tmp1 // 2 )% 2
    ip_off = ""
    ip_off = ip_off + "%d" % (int(tmp[1:],16)+4096*(tmp1%2))
    packet.append(ip_DF)
    packet.append(ip_MF)
    packet.append(ip_off)

    #生存时间----------------------------------------11
    ip_ttl = ""
    ip_ttl = ip_ttl + "%d" % int(pkt_data[22])
    packet.append(ip_ttl)

    # 协议----------------------------------------12
    ip_p = ""
    ip_p = ip_p + "%.2x" % pkt_data[23]
    if(ip_p == "01"):
        packet.append("ICMP")
    elif(ip_p == "02"):
        packet.append("IGMP")
    elif (ip_p == "04"):
        packet.append("IPv4")
    elif (ip_p == "06"):
        packet.append("TCP")
    elif (ip_p == "11"):
        packet.append("UDP")
    elif (ip_p == "29"):
        packet.append("IPv6")
    else:
        packet.append(ip_p)

    #首部校验和----------------------------------------13
    ip_cksum = ""
    for i in range(2):
        ip_cksum = ip_cksum + "%.2x" % (pkt_data[ i +24 ])
    packet.append(ip_cksum)

    #32位源IP地址----------------------------------------14
    ip_src = ""
    for i in range(3):
        ip_src = ip_src + "%d." % (pkt_data[i+26])
    ip_src = ip_src + ("%d" % pkt_data[29])
    packet.append(ip_src)

    # 32位目的IP地址----------------------------------------15
    ip_dst = ""
    for i in range(3):
        ip_dst = ip_dst + "%d." % (pkt_data[i + 30])
    ip_dst = ip_dst + ("%d" % pkt_data[33])
    packet.append(ip_dst)

    #选项----------------------------------------16
    #头长度大于5才有
    if(ip_hl != 5):
        ip_options = ""
        ip_oplen = ip_hl - 5
        #选项长度
        for i in range( 4 * ip_oplen ):
            ip_options = ip_options + "%.2x" % (pkt_data[i + 34])
        packet.append(ip_options)
    else:
        ip_oplen = 0
        packet.append("无选项")
    ip_dataStart = ip_oplen*4 + 34
    # 数据的第一个字节偏移量
    # 用得少，再说吧
    if (ip_off != "0"):
        packet.append("分片包")
        # 分片包----------------------------------------17
        data = ""
        dataANSI = ""
        for i in range(len):
            data = data + "%.2x " % (pkt_data[i])
            if (pkt_data[i] > 31 and pkt_data[i] < 127):
                dataANSI = dataANSI + chr(pkt_data[i])
            else:
                dataANSI = dataANSI + '.'
        packet.append(data)
        packet.append(dataANSI)
        return packet
    elif (ip_p == "01" ):
        #ICMP
        return packet + ICMPPacketLoop(pkt_data, len, ip_dataStart)
    elif (ip_p == "02" ):
        #IGMP
        return packet + IGMPPacketLoop(pkt_data, len, ip_dataStart)
    elif (ip_p == "06" ):
        #TCP
        return packet + TCPPacketLoop(pkt_data, len, ip_dataStart)
    elif (ip_p == "11" ):
        #TCP
        return packet + UDPPacketLoop(pkt_data, len, ip_dataStart)
    elif (ip_p == "29" ):
        #TCP
        return packet +IPv6PacketLoop(pkt_data, len, ip_dataStart)
    elif (ip_p == "3a" ):
        #ICMP
        return packet + ICMPv6PacketLoop(pkt_data, len, ip_dataStart)
    else:
        packet.append("未识别的后续内容")#----------------------------------------17
        data = ""
        dataANSI = ""
        for i in range(len):
            data = data + "%.2x " % (pkt_data[i])
            if (pkt_data[i] > 31 and pkt_data[i] < 127):
                dataANSI = dataANSI + chr(pkt_data[i])
            else:
                dataANSI = dataANSI + '.'
        packet.append(data)
        packet.append(dataANSI)
    return packet
# IPv6包处理

def IPv6PacketLoop(pkt_data, len ,begin):
    # 从第14字节开始为IPv6包内容
    packet = []
    # 第一行32位 8个 半字节
    tmp = ""
    for i in range(4):
        tmp = tmp + "%.2x" % (pkt_data[begin + i])
    #-------------------------------------------------------------ipV4头部的话此处17 对应+14
    # ip版本----------------------------------------3
    ip_v = tmp[0]
    packet.append(ip_v)
    #优先级----------------------------------------4
    ip_trafficClass = int(tmp[1:2],16)
    packet.append(str(ip_trafficClass))
    #流量标识----------------------------------------5
    ip_FlowLabel = tmp[3:]
    packet.append(ip_FlowLabel)
    #载荷长度----------------------------------------6
    tmp = ""
    for i in range(2):
        tmp = tmp + "%.2x" % (pkt_data[begin + 4 + i])
    ip_pdlen = int(tmp,16)
    packet.append(ip_pdlen)

    #下一包头协议----------------------------------------7
    ip_nxth ="%.2x" % (pkt_data[begin + 6])
    packet.append(ip_nxth)

    #跳数限制----------------------------------------8
    tmp = "%.2x" % (pkt_data[begin + 7])
    ip_hpl = int(tmp, 16)
    packet.append(ip_hpl)

    #源地址----------------------------------------9
    ip_src = ""
    for i in range(8):
        for j in range(2):
            ip_src = ip_src + "%.2x" % (pkt_data[i*2 + j + begin + 8])
        if (i!=7):
            ip_src = ip_src + ":"
    packet.append(ip_src)

    # 目的地址----------------------------------------10
    ip_dst = ""
    for i in range(8):
        for j in range(2):
            ip_dst = ip_dst + "%.2x" % (pkt_data[i * 2 + j + begin + 24])
        if (i != 7):
            ip_dst = ip_dst + ":"
    packet.append(ip_dst)
    ip_dataStart = begin + 40
    # 协议名----------------------------------------11

    if (ip_nxth == "3a"):
        # ICMP
        packet.append("ICMPv6")
        return packet + ICMPv6PacketLoop(pkt_data, len, ip_dataStart)
    elif (ip_nxth == "02"):
        # IGMP
        packet.append("IGMP")
        return packet + IGMPPacketLoop(pkt_data, len, ip_dataStart)
    elif (ip_nxth == "06"):
        # TCP
        packet.append("TCP")
        return packet + TCPPacketLoop(pkt_data, len, ip_dataStart)
    elif (ip_nxth == "11"):
        # UDP
        packet.append("UDP")
        return packet + UDPPacketLoop(pkt_data, len, ip_dataStart)
    elif (ip_nxth == "00"):

        tmp = "%.2x" % pkt_data[ip_dataStart]
        if tmp == "3a":
            ip_dataStart += 8
            packet.append("ICMPv6")
            return packet + ICMPv6PacketLoop(pkt_data, len, ip_dataStart)
        else:
            packet.append("未识别的ipv6包上层协议/拓展报头")
            uh_data = ""
            uh_dataANSI = ""
            for i in range(len):
                uh_data = uh_data + "%.2x " % (pkt_data[i])
                if (pkt_data[i] > 31 and pkt_data[i] < 127):
                    uh_dataANSI = uh_dataANSI + chr(pkt_data[i])
                else:
                    uh_dataANSI = uh_dataANSI + '.'
            packet.append(uh_data)
            packet.append(uh_dataANSI)

            return packet

    else:  # (ip_nxth == "00"):
        packet.append("未识别的ipv6包上层协议/拓展报头")
        uh_data = ""
        uh_dataANSI = ""
        for i in range(len):
            uh_data = uh_data + "%.2x " % (pkt_data[i])
            if (pkt_data[i] > 31 and pkt_data[i] < 127):
                uh_dataANSI = uh_dataANSI + chr(pkt_data[i])
            else:
                uh_dataANSI = uh_dataANSI + '.'
        packet.append(uh_data)
        packet.append(uh_dataANSI)

        return packet
#ICMP包处理

def ICMPPacketLoop(pkt_data, len, begin):
    # 从begin开始
    packet = []
    # 提示类型，我靠啊，好长啊！好多啊！
    tmp = "%.2x" % (pkt_data[begin])
    icmp_type = (int(tmp,16))#----------------------------------------17
    tmp = "%.2x" % (pkt_data[begin + 1])
    icmp_code = (int(tmp, 16))#----------------------------------------18
    if (icmp_type == 0):
        packet.append("Echo响应(Ping)")
        packet.append("目标主机应答")
    elif (icmp_type == 3):
        packet.append("目的不可达")
        if (icmp_code == 0):
            packet.append("网络不可达")
        elif (icmp_code == 1):
            packet.append("主机不可达")
        elif (icmp_code == 2):
            packet.append("协议不可达")
        elif (icmp_code == 3):
            packet.append("端口不可达")
        elif (icmp_code == 4):
            packet.append("需要分段但设置为不允许分段")
        elif (icmp_code == 5):
            packet.append("源路由失败")
        elif (icmp_code == 6):
            packet.append("目的站点网络未知")
        elif (icmp_code == 7):
            packet.append("目的主机网络未知")
        elif (icmp_code == 8):
            packet.append("原主机被隔离")
        elif (icmp_code == 9):
            packet.append("与目的站点网络的通信被禁止")
        elif (icmp_code == 10):
            packet.append("与目的站点主机的通信被禁止")
        elif (icmp_code == 11):
            packet.append("对请求的服务类型，网络不可达")
        elif (icmp_code == 12):
            packet.append("对请求的服务类型,主机不可达")
        else:
            packet.append("其他问题")
    elif( icmp_type == 5):
        packet.append("重定向")
        if (icmp_code == 0):
            packet.append("网络重定向")
        elif (icmp_code == 1):
            packet.append("主机重定向")
        elif (icmp_code == 2):
            packet.append("服务类型和网络重定向")
        elif (icmp_code == 3):
            packet.append("服务类型和主机重定向")
    elif (icmp_type == 8):
        packet.append("请求回显")
        if (icmp_code == 0):
            packet.append("Echo请求")
    elif (icmp_type == 9):
        packet.append("路由器通告")
        if (icmp_code == 0):
            packet.append("路由通告")
    elif (icmp_type == 10):
        packet.append("路由器请求")
        if (icmp_code == 0):
            packet.append("路由器的发现/选择/请求")
    elif (icmp_type == 11):
        packet.append("ICMP超时")
        if (icmp_code == 0):
            packet.append("TTL 超时")
        elif (icmp_code == 1):
            packet.append("分片重组超时")
    elif (icmp_type == 12):
        packet.append("参数问题：错误IP头部")
        icmp_code = (int(pkt_data[begin + 1], 16))
        if (icmp_code == 0):
            packet.append("IP 报首部参数错误")
        elif (icmp_code == 1):
            packet.append("丢失必要选项")
        elif (icmp_code == 2):
            packet.append("不支持的长度")
    elif (icmp_type == 13):
        packet.append("时间戳请求")
        if (icmp_code == 0):
            packet.append("时间戳请求")
    elif (icmp_type == 14):
        packet.append("时间戳应答")
        if (icmp_code == 0):
            packet.append("时间戳应答")
    #校验和#----------------------------------------19
    icmp_cksum = ""
    for i in range(2):
        icmp_cksum = icmp_cksum + "%.2x" % (pkt_data[begin + 2 + i])
    packet.append(icmp_cksum)

    #ID#----------------------------------------20
    tmp = ""
    for i in range(2):
        tmp = tmp + "%.2x" % (pkt_data[begin + 4 + i])
    icmp_id = int(tmp,16)
    packet.append(icmp_id)

    #序列号#----------------------------------------21
    tmp = ""
    for i in range(2):
        tmp = tmp + "%.2x" % (pkt_data[begin + 6 + i])
    icmp_seq = int(tmp,16)
    packet.append(icmp_seq)

    # 剩余数据
    icmp_data = ""
    icmp_dataANSI = ""
    for i in range(len):
        icmp_data = icmp_data + "%.2x " % (pkt_data[i])
        if (pkt_data[i]>31 and pkt_data[i]<127):
            icmp_dataANSI = icmp_dataANSI + chr(pkt_data[i])
        else :
            icmp_dataANSI = icmp_dataANSI + '.'
    packet.append(icmp_data)
    packet.append(icmp_dataANSI)
    return packet

def ICMPv6PacketLoop(pkt_data, len, begin):
    # 从begin开始
    packet = []
    # 提示类型，又来了，疯掉了----------------------------------------12
    tmp = "%.2x" % (pkt_data[begin])
    icmp_type = (int(tmp,16))
    tmp = "%.2x" % (pkt_data[begin + 1])
    icmp_code = (int(tmp, 16))
    if (icmp_type == 2):
        packet.append("包太大")
    elif (icmp_type == 1):
        if (icmp_code == 0):
            packet.append("目的地无法到达：无路由到目的地")
        elif (icmp_code == 1):
            packet.append("目的地无法到达：与目的地的通信被网管阻断")
        elif (icmp_code == 2):
            packet.append("目的地无法到达：源地址越界")
        elif (icmp_code == 3):
            packet.append("目的地无法到达：地址不可达")
        elif (icmp_code == 4):
            packet.append("目的地无法到达：端口不可达")
        elif (icmp_code == 5):
            packet.append("目的地无法到达：源地址出入策略错误")
        elif (icmp_code == 6):
            packet.append("目的地无法到达：到目的地路由被拒绝")
        elif (icmp_code == 7):
            packet.append("目的地无法到达：原路由头出错")
    elif (icmp_type == 3):
        if (icmp_code == 0):
            packet.append("超时：传输过程中跳跃数超出范围")
        elif (icmp_code == 1):
            packet.append("超时：分片重组超时")
    elif (icmp_type == 4):
        if (icmp_code == 0):
            packet.append("参数错误：遇到错误的头字段")
        elif (icmp_code == 1):
            packet.append("参数错误：遇到无法识别的下一个头类型")
        elif (icmp_code == 2):
            packet.append("参数错误：遇到无法识别IPv6选项")
    elif (icmp_type == 128):
        packet.append("Echo请求")
    elif (icmp_type == 129):
        packet.append("Echo答复")
    elif (icmp_type == 130):
        packet.append("多播监听查询")
    elif (icmp_type == 131):
        packet.append("多播监听报告")
    elif (icmp_type == 132):
        packet.append("多播监听完成")
    elif (icmp_type == 133):
        packet.append("路由器请求")
    elif (icmp_type == 134):
        packet.append("路由器广播")
    elif (icmp_type == 135):
        packet.append("邻居请求")
    elif (icmp_type == 136):
        packet.append("邻居广播")
    elif (icmp_type == 137):
        packet.append("消息重定向")
    elif (icmp_type == 138):
        if (icmp_code == 0):
            packet.append("路由器重编号：命令")
        elif (icmp_code == 1):
            packet.append("路由器重编号：结果")
        elif (icmp_code == 255):
            packet.append("路由器重编号：序列号重置")
    elif (icmp_type == 139):
        if (icmp_code == 0):
            packet.append("ICMP节点信息查询：数据字段包含该查询的IPv6地址")
        elif (icmp_code == 1):
            packet.append("ICMP节点信息查询：数据字段包含查询的名称或空")
        elif (icmp_code == 2):
            packet.append("ICMP节点信息查询：数据字段包含该查询的IPv4地址")
    elif (icmp_type == 140):
        if (icmp_code == 0):
            packet.append("ICMP节点信息响应：响应成功，数据字段可能不为空")
        elif (icmp_code == 1):
            packet.append("ICMP节点信息响应：拒绝响应，数据字段为空")
        elif (icmp_code == 2):
            packet.append("ICMP节点信息响应：查询结果未知，数据字段为空")
    elif (icmp_type == 141):
        packet.append("反向邻居发现请求消息")
    elif (icmp_type == 142):
        packet.append("反向邻居发现广播消息")
    elif (icmp_type == 143):
        packet.append("多播侦听器发现报告")
    elif (icmp_type == 144):
        packet.append("主机代理地址发现请求消息")
    elif (icmp_type == 145):
        packet.append("主机代理地址发现回复消息")
    elif (icmp_type == 146):
        packet.append("移动前缀请求")
    elif (icmp_type == 147):
        packet.append("移动前缀广播")
    elif (icmp_type == 148):
        packet.append("认证路径请求")
    elif (icmp_type == 149):
        packet.append("认证路径广播")
    elif (icmp_type == 151):
        packet.append("多播路由器广播")
    elif (icmp_type == 152):
        packet.append("多播路由器请求")
    elif (icmp_type == 153):
        packet.append("多播路由器终止")
    elif (icmp_type == 155):
        packet.append("	RPL控制消息")
    else:
        packet.append("未识别的协议请求")
#校验和----------------------------------------13
    icmp_cksum = ""
    for i in range(2):
        icmp_cksum = icmp_cksum + "%.2x" % (pkt_data[begin + 2 + i])
    packet.append(icmp_cksum)


    # 剩余数据----------------------------------------14
    icmp_data = ""
    icmp_dataANSI = ""
    for i in range(len):
        icmp_data = icmp_data + "%.2x " % (pkt_data[i])
        if (pkt_data[i] > 31 and pkt_data[i] < 127):
            icmp_dataANSI = icmp_dataANSI + chr(pkt_data[i])
        else:
            icmp_dataANSI = icmp_dataANSI + '.'

    packet.append(icmp_data)
    packet.append(icmp_dataANSI)
    return packet

#IGMP包处理
def IGMPPacketLoop(pkt_data, len, begin):
    # 从begin开始
    packet = []
    igmp_type =  "%.2x" % (pkt_data[begin])
    #操作类型----------------------------------------17

    if (igmp_type == "22"):
        igmp_type = igmp_type + "%.2x" % (pkt_data[begin + 8])
    packet.append(igmp_type)
    '''
    if (igmp_type =="11"):
        packet.append("成员关系查询")
    elif (igmp_type =="12"):
        packet.append("IGMPv1成员报告")
    elif (igmp_type =="16"):
        packet.append("IGMPv2成员报告")
    elif (igmp_type =="17"):
        packet.append("成员离开组")
    elif (igmp_type =="22"):  03离开  04加入
        packet.append("IGMPv3成员关系报告")
    else:
        packet.append("未知操作")
    '''
    #z最大响应时间----------------------------------------18
    tmp = "%.2x" % (pkt_data[begin + 1])
    igmp_rspTime = int(tmp,16)
    packet.append(igmp_rspTime)

    # 校验和----------------------------------------19
    igmp_cksum = ""
    for i in range(2):
        igmp_cksum = igmp_cksum + "%.2x" % (pkt_data[begin + 2 + i])
    packet.append(igmp_cksum)

    #组地址----------------------------------------20
    igmp_add = ""
    if (igmp_type[:2] == "22"):
        for i in range(3):
            igmp_add = igmp_add + "%d." % (pkt_data[begin + 12 + i])
        igmp_add = igmp_add + ("%d" % pkt_data[begin + 15])
    else:
        for i in range(3):
            igmp_add = igmp_add + "%d." % (pkt_data[begin + 4 + i])
        igmp_add = igmp_add + ("%d" % pkt_data[begin + 7])
    packet.append(igmp_add)
    igmp_data = ""
    igmp_data_ANSI = ""
    for i in range(len):
        igmp_data = igmp_data + "%.2x " % (pkt_data[i])
        if (pkt_data[i] > 31 and pkt_data[i] < 127):
            igmp_data_ANSI = igmp_data_ANSI + chr(pkt_data[i])
        else:
            igmp_data_ANSI = igmp_data_ANSI + '.'

    packet.append(igmp_data)
    packet.append(igmp_data_ANSI)
    return packet

#UDP包处理
def UDPPacketLoop(pkt_data, len, begin):
    # 从begin开始
    packet = []
    # 源端口号----------------------------------------17
    tmp = ""
    for i in range(2):
        tmp = tmp + "%.2x" % (pkt_data[begin + i])
    uh_sport = (int(tmp, 16))
    packet.append(uh_sport)

    # 目的端口号----------------------------------------18
    tmp = ""
    for i in range(2):
        tmp = tmp + "%.2x" % (pkt_data[begin + i + 2])
    uh_dport = (int(tmp, 16))
    packet.append(uh_dport)

    # UDP长度----------------------------------------19
    tmp = ""
    for i in range(2):
        tmp = tmp + "%.2x" % (pkt_data[begin + i + 4])
    uh_ulen = (int(tmp, 16))
    packet.append(uh_ulen)


    # 校验和----------------------------------------20
    uh_sum = ""
    for i in range(2):
        uh_sum = uh_sum + "%.2x" % (pkt_data[begin + i + 6])
    packet.append(uh_sum)

    #HEX----------------------------------------21
    #ANSI----------------------------------------22
    uh_data = ""
    uh_dataANSI = ""
    for i in range(len):
        uh_data = uh_data + "%.2x " % (pkt_data[i])
        if (pkt_data[i] > 31 and pkt_data[i] < 127):
            uh_dataANSI = uh_dataANSI + chr(pkt_data[i])
        else:
            uh_dataANSI = uh_dataANSI + '.'
    packet.append(uh_data)
    packet.append(uh_dataANSI)

    return packet

#TCP包处理
def TCPPacketLoop(pkt_data, len, begin):

    # 从begin开始
    packet = []
    #源端口号----------------------------------------17
    tmp = ""
    for i in range(2):
        tmp = tmp + "%.2x" % (pkt_data[begin + i])
    th_sport = (int(tmp, 16))
    packet.append(th_sport)

    # 目的端口号----------------------------------------18
    tmp = ""
    for i in range(2):
        tmp = tmp + "%.2x" % (pkt_data[begin + i + 2])
    th_dport = (int(tmp, 16))
    packet.append(th_dport)

    # 序号seq----------------------------------------19
    tmp = ""
    for i in range(4):
        tmp = tmp + "%.2x" % (pkt_data[begin + i + 4])
    th_seq = (int(tmp, 16))
    packet.append(th_seq)

    # 确认序号ack----------------------------------------20
    tmp = ""
    for i in range(4):
        tmp = tmp + "%.2x" % (pkt_data[begin + i + 8])
    th_ack = (int(tmp, 16))
    packet.append(th_ack)

    #首部长度----------------------------------------21
    tmp = ""
    tmp = tmp +  "%.2x" % (pkt_data[begin + 12])
    th_off = int(tmp[0],16)
    packet.append(th_off)

    #保留字段 6位0----------------------------------------22
    packet.append("000000")

    #标志位----------------------------------------23 - 28
    tmp = ""
    tmp = tmp + "%.2x" % (pkt_data[begin + 13])
    tcp_flags = int(tmp,16)
    URG = (tcp_flags // 32 )% 2
    ACK = (tcp_flags // 16 )% 2
    PSH = (tcp_flags // 8 )% 2
    RST = (tcp_flags // 4 )% 2
    SYN = (tcp_flags // 2 )% 2
    FIN = tcp_flags % 2
    packet.append(URG)
    packet.append(ACK)
    packet.append(PSH)
    packet.append(RST)
    packet.append(SYN)
    packet.append(FIN)

    # 窗口大小----------------------------------------29
    tmp = ""
    for i in range(2):
        tmp = tmp + "%.2x" % (pkt_data[begin + i + 14])
    th_win = (int(tmp, 16))
    packet.append(th_win)

    # 校验和----------------------------------------30
    th_sum = ""
    for i in range(2):
        th_sum = th_sum + "%.2x" % (pkt_data[begin + i + 16])
    packet.append(th_sum)

    # 紧急数据偏移量----------------------------------------31
    tmp = ""
    for i in range(2):
        tmp = tmp + "%.2x" % (pkt_data[begin + i + 18])
    th_urp = (int(tmp, 16))
    packet.append(th_urp)

    #选项字段选择性忽略

    th_data = ""
    th_data_ANSI = ""
    dataOrigin = ""
    for i in range(len):
        th_data = th_data + "%.2x " % (pkt_data[i])
        dataOrigin = dataOrigin + chr(pkt_data[i])
        if (pkt_data[i] > 31 and pkt_data[i] < 127):
            th_data_ANSI = th_data_ANSI + chr(pkt_data[i])
        else:
            th_data_ANSI = th_data_ANSI + '.'
    packet.append(dataOrigin)
    packet.append(th_data)
    packet.append(th_data_ANSI)
    return packet

