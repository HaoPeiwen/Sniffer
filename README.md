# Sniffer
![](https://img.shields.io/pypi/pyversions/Django.svg) ![](https://img.shields.io/badge/platform-win--64-lightgrey.svg)
 ![](https://img.shields.io/apm/l/vim-mode.svg) 

IS301 Computer Communication and Network Project

计算机通信网大作业 - 网络抓包器

*作者 - Evander & Xynnn_*

## Getting Startted
### Prerequisites
- Python 3.x on Win-64 platform
- [PyQt5](https://riverbankcomputing.com/software/pyqt/download5) GUI
- [ansi2html](https://github.com/ralphbean/ansi2html) used to parse ANSI ESCAPE Sequence to html css.


### Usage
    pip3 install pyqt5
    pip3 install ansi2html
    cd ./src
    python ./main.py

    # Or just run bin/sniffer_v1.exe

    pip3 install pyqt5
    pip3 install ansi2html
    cd ./bin
    ./sniffer_v1.exe
  
*Note: Python 3.x only, and the script may contains any other packages, just search for installing them.*

## Features

### Sniffing & Searching

![](https://raw.githubusercontent.com/HaoPeiwen/Sniffer/master/demo1.gif)

### Packets Filter & IP Packets Reassembly

![](https://raw.githubusercontent.com/HaoPeiwen/Sniffer/master/demo2.gif)

### Tracing TCP Stream

You can reassemble TCP stream packets and open it which is generated as file `nxm` automacitally in the current path. 

Let's capture a FTP transfer file:

![](https://raw.githubusercontent.com/HaoPeiwen/Sniffer/master/demo4.png)
![](https://raw.githubusercontent.com/HaoPeiwen/Sniffer/master/demo5.png)


### Formatted Display
  
Telnet *bbs.sjtu.edu.cn* as example, after tracing TCP stream, we got <ASCII> code and formatted display as you can see:

![](https://raw.githubusercontent.com/HaoPeiwen/Sniffer/master/demo3.gif)

### Saving Capture Log
Click "保存" to save a file named `*.pcap` whereby you make further analysis through [*Wireshark*](https://www.wireshark.org/).

## To be continue
Want to see something else added? [Open an issue.](https://github.com/HaoPeiwen/Sniffer/issues/new)
