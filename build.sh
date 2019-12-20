#!/bin/bash

UNAME=$(uname -m)

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
    sudo ./configure
    sudo make
    sudo make install
    sudo unlink /usr/bin/bison
    sudo ln -s /usr/local/bin/bison /usr/bin/bison
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
        install_bison
        install_pcap
        install_libnet
        ;;
    * )
        echo -e "\n\e[33mAborting pcap and libnet installation!\e[0m"
        exit 1
        ;;
esac

case "$UNAME" in
    x86_64 | amd64 )
        if [ -d /usr/lib/x86_64-linux-gnu ]; then
            # create symlink to the library in `/usr/lib/x86_64-linux-gnu`
		if [ -L /usr/lib/x86_64-linux-gnu/libpcap.so.1 ]; then
            		sudo unlink /usr/lib/x86_64-linux-gnu/libpcap.so.1
           		sudo ln -s /usr/local/lib/libpcap.so.1 /usr/lib/x86_64-linux-gnu/libpcap.so.1
		fi
	fi
        ;;
    i386 )
        if [ -d /usr/lib/i386-linux-gnu ]; then
            # create symlink to the library in `/usr/lib/i386-linux-gnu`
		if [ -L /usr/lib/i386-linux-gnu/libpcap.so.1 ]; then
            		sudo unlink /usr/lib/i386-linux-gnu/libpcap.so.1
            		sudo ln -s /usr/local/lib/libpcap.so.1 /usr/lib/i386-linux-gnu/libpcap.so.1
        	fi
	fi
        ;;
esac
# create symlink to the library in `/usr/lib`
if [ -L /usr/lib/libpcap.so.1 ]; then
	sudo unlink /usr/lib/libpcap.so.1
	sudo ln -s /usr/local/lib/libpcap.so.1 /usr/lib/libpcap.so.1
fi
