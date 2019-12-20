#!/bin/bash

ROOT_ID=0
E_NOTROOT=87
UNAME=$(uname -m)

abort_root()
{
    echo -e "\e[33mMust be root to run this script!\e[0m"
    exit $E_NOTROOT
}

warning()
{
    echo -e "\n\e[33m[WARNING] \e[0m"
    echo "This will install pcap and libnet under /usr/local/lib"
    echo -e "It will override the pcap and libnet header files (if any) in /usr/local/include!\n"
}

install_bison()
{
    cd /usr/local/lib
    wget http://ftp.gnu.org/gnu/bison/bison-3.4.tar.gz
    tar -zxvf bison-3.4.tar.gz

    cd bison-3.4
    ./configure
    make
    make install
    unlink /usr/bin/bison
    ln -s /usr/local/bin/bison /usr/bin/bison
}

install_pcap()
{
    cd /usr/local/lib
    wget https://www.tcpdump.org/release/libpcap-1.8.1.tar.gz
    tar xzvf libpcap-1.8.1.tar.gz

    cd libpcap-1.8.1
    ./configure --prefix=/usr/local
    make
    make install
}

install_libnet()
{
    cd /usr/local/lib
    wget https://netcologne.dl.sourceforge.net/project/libnet-dev/libnet-1.1.6.tar.gz
    tar xzvf libnet-1.1.6.tar.gz

    cd libnet-1.1.6
    ./configure --prefix=/usr/local
    make
    make install
}

[ $UID -ne $ROOT_ID ] && abort_root
warning
read -p "$(echo -e '\e[33mDo you want to proceed? (y/n)\e[0m -> ')" stat

case "$stat" in
    y | yes )
        install_bison
        install_pcap
        install_libnet
        ;;
    * )
        echo -e "\n\e[33mAborting pcap and libnet installation!\e[0m"
        exit 1
        ;;
esac

if [ -d /etc/ld.so.conf.d ]; then
	echo "/usr/local/lib" > /etc/ld.so.conf.d/99kira-scan.conf
	ldconfig
fi

# create symlink to the library in `/usr/lib`
if [ -L /usr/lib/libpcap.so.1 ]; then
	unlink /usr/lib/libpcap.so.1
fi
ln -s /usr/local/lib/libpcap.so.1 /usr/lib/libpcap.so.1
