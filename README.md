# xkira-scan
xkira-scan is a SYN / ICMP scanning module

## About
* xkira-scan performs a `SYN` scan against a single host or a subnet on a specific port or port-range and splits the result into 3 categories:

	* `DOWN`     - hosts that appear to be down or behind a firewall
	* `FILTERED` - hosts that are actually up, but have all the scan ports filtered
	* `OTHER`    - hosts that are up and have atleast one scan port open or closed (responded with an `RST` or `ACK`)

### Tested on 
* `Kali Linux 2018.1-amd64`
* `Kali Linux 2019.3-amd64`
* `Linux Mint`

## Usage
* scan a subnet on a single port `sudo kira-scan -d 31.111.42.210/26 -p 80`
* scan a subnet on a port range  `sudo kira-scan -d 31.111.42.210/30 -p 20-22`
* scan a single host on a single port `sudo kira-scan -d 31.111.42.210 -p 80`
* scan a single host on a port range  `sudo kira-scan -d 31.111.42.210 -p 20-22`

## Libraries used
	* libpcap - version 1.7.4 (Works fine with libpcap-1.9.1 too)
	* libnet  - version 1.1.6

## Gcc version used
	* 5.4.0

## Screenshots
![alt text](https://github.com/jissatsu/xkira-scan/blob/master/screenshots/pct1.png)
![alt text](https://github.com/jissatsu/xkira-scan/blob/master/screenshots/pct2.png)
![alt text](https://github.com/jissatsu/xkira-scan/blob/master/screenshots/pct3.png)
