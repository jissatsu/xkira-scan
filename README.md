# xkira-scan
xkira-scan is a SYN / ICMP scanning module (Linux only)

## About
* xkira-scan performs a `SYN` scan against a single host or a subnet on a specific port or port-range and splits the result into 3 categories:

	* `DOWN`     - hosts that appear to be down or behind a firewall
	* `FILTERED` - hosts that are actually up, but have all the scan ports filtered
	* `OTHER`    - hosts that are up and have atleast one scan port open or closed (responded with an `RST` or `ACK`)

### Tested on 
* `Kali Linux 2018.1-amd64`
* `Linux Mint`

## Libraries used
	* libpcap - version 1.7.4
	* libnet  - version 1.1.6

## Gcc version used
	* 5.4.0

## Screenshots
![alt text](https://github.com/jissatsu/xkira-scan/blob/master/screenshots/pct1.png)
![alt text](https://github.com/jissatsu/xkira-scan/blob/master/screenshots/pct2.png)
![alt text](https://github.com/jissatsu/xkira-scan/blob/master/screenshots/pct3.png)
