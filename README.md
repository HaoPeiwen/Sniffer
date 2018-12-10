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

- Sniffing and Filter searching

![demo1](https://raw.githubusercontent.com/HaoPeiwen/Sniffer/master/demo1.gif)

- Packets filter and Reassembly

![demo2](https://raw.githubusercontent.com/HaoPeiwen/Sniffer/master/demo2.gif)

- Formatted display
  
Telnet *bbs.sjtu.edu.cn* as example

![demo3](https://raw.githubusercontent.com/HaoPeiwen/Sniffer/master/demo3.gif)

- Save `*.pcap` files
- Reassembly FTP transfer files and open it (as named `num`)

## To be continue...
