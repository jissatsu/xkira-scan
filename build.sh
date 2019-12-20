#!/bin/bash

warning()
{
    echo -e "\n\e[33m[WARNING] \e[0m"
    echo "This will install pcap and libnet under /usr/local/lib"
    echo -e "It will override the pcap and libnet header files (if any) in /usr/local/include!\n"
}

install_pcap()
{
    cd /usr/local/lib
    wget https://www.tcpdump.org/release/libpcap-1.8.1.tar.gz
    tar xzvf libpcap-1.8.1.tar.gz

    cd libpcap-1.8.1
    sudo ./configure --prefix=/usr/local
    sudo make
    sudo make install
}

install_libnet()
{
    cd /usr/local/lib
    wget https://netcologne.dl.sourceforge.net/project/libnet-dev/libnet-1.1.6.tar.gz
    tar xzvf libnet-1.1.6.tar.gz

    cd libnet-1.1.6
    sudo ./configure --prefix=/usr/local
    sudo make
    sudo make install
}

warning
read -p "$(echo -e '\e[33mDo you want to proceed? (y/n)\e[0m -> ')" stat

case "$stat" in
    y | yes )
        install_pcap
        install_libnet
        ;;
    * )
        echo -e "\n\e[33mAborting pcap and libnet installation!\e[0m"
        exit 1
        ;;
esac