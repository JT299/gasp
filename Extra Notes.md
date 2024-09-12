## https://miro.com/app/board/o9J_klSqCSY=/

## Methodology
```
Net Recon Methodology

     - Host discovery
	+ Ruby ping sweep ( if ping available)
		Methodology

Net Recon Methodology

     - Host discovery
	+ Ruby ping sweep ( if ping available)
		for i in [1..254] ;do (ping -c 1 192.168.1.$i 2>/dev/null | grep "bytes from" &) ;done

	+ NMAP scan if no ping (Check scan meothodology below)

     - Port Discovery
	+ nmap
	+ nc scan script

     Port Validation
	+ banner grab using nc [ip addr][port]

    - Follow-on actions based on ports found
	+ if 21 or 80 wget -r [ip addr] (or) wget -r ftp://[ip addr] (or) firefox
	+if 22 or 23 connect and PASSIVE RECON
	+if no 22 or 23 and you NEED to GET ON the box and you have port 21
		+ FTP[ip addr] connects to ftp server
			- passive
			- ls
			- get[file name]

Scan Methodology
	NMAP -Pn [ip addr] -T4 -p 21-23,80

	- Quick Scan Ports 21-23, 80
	- Specific ports based on hints/clues found
	-Well known port range
	- Which tcpdump wireshark nmap telnet get curl ping

		+ 0 - 1023 (Actually scan 1-1023)
	- Chunkcs of 2000 or first 10000 ports (65535)
	- hail mary - Scan all the ports (65535)

Passive Recon Methodology
	Italicized/bolded words are commands

		-hostname
		-permisssions:
			+sudo -l
		-interfaces and subnets
			+ip a
			+ show interface [vyos]
		-Neighbors
			+ip neigh
		-Routing Table
			+ip route
			+ show ip route [vyos]

		-Files of intest
			+find / -iname flag*
			+find / -iname hint*

		-Other listening ports
			+ss -ntlp

		-Other tools
			+ which tcpdump wireshark nmap telnet get curl ping


	+ NMAP scan if no ping (Check scan meothodology below)

     - Port Discovery
	+ nmap
	+ nc scan script

     Port Validation
	+ banner grab using nc [ip addr][port]

    - Follow-on actions based on ports found
	+ if 21 or 80 wget -r [ip addr] (or) wget -r ftp://[ip addr] (or) firefox
	+if 22 or 23 connect and PASSIVE RECON
	+if no 22 or 23 and you NEED to GET ON the box and you have port 21
		+ FTP[ip addr] connects to ftp server
			- passive
			- ls
			- get[file name]

Scan Methodology
	NMAP -Pn [ip addr] -T4 -p 21-23,80

	- Quick Scan Ports 21-23, 80
	- Specific ports based on hints/clues found
	-Well known port range
	- Which tcpdump wireshark nmap telnet get curl ping

		+ 0 - 1023 (Actually scan 1-1023)
	- Chunkcs of 2000 or first 10000 ports (65535)
	- hail mary - Scan all the ports (65535)

Passive Recon Methodology
	Italicized/bolded words are commands

		-hostname
		-permisssions:
			+sudo -l
		-interfaces and subnets
			+ip a
			+ show interface [vyos]
		-Neighbors
			+ip neigh
		-Routing Table
			+ip route
			+ show ip route [vyos]

		-Files of intest
			+find / -iname flag*
      +find / -iname hint*

    -Other listening ports
			+ss -ntlp
`
		-Other tools
			+ which tcpdump wireshark nmap telnet get curl ping
```

## RICK and Morty
![image](https://github.com/user-attachments/assets/ad902119-30cb-433c-9517-a51ee2d7813c)
```
RICK>: Telnet 10.50.32.176 ----> (Remote Back) ssh student@10.50.42.163 -R 21899:localhost:22 -NT ===>  BIH>: ssh net2_student18@localhost -p 21899 -D 9050 -NT (then ennumerate Morty)

BIH>: ssh net2_student18@localhost -p 21899 -L 21801:10.1.2.18:2222 -NT ===> ssh net2_student18@localhost -21802 -D 9050 -NT (ennumerate Jerry)

BIH>: ssh net2_student18@localhost -p 21802 -L 21803:172.16.10.121:2323 -NT =====> ssh net2_student18@localhost -p 21803 -D 9050 -NT (ennumerate Beth)

BIH>: ssh net2_student18@localhost -p 21803 -L 21804:192.168.10.69:22 -NT =====> ssh net2_student18@localhost -p 21804 -D 9050 -NT (ennumerate message) 
```



## FUTURE
![image](https://github.com/user-attachments/assets/9b38ac9b-f8c2-4d91-a13e-feed23c1de5e)
```
ssh student@localhost -L 21801:10.50.38.13:1234 -NT

ssh net2_student18@localhost -p 21801 -L 21802:172.17.17.28:23 -NT

telnet localhost 21802 =====>  ssh net2_student18@172.17.17.17 -p 1234 -R 21899:localhost:4321 -NT

ssh net2_student18@localhost -p 21801 -L 21803:localhost:21899 -NT

ssh net2_student18@localhost -p 21803 -L 21804:192.168.30.150:1212 -NT

ssh net2_student18@localhost -p 21804 -L 21805:10.10.12.121:2932 -NT

ssh net2_student18@localhost -p 21805 -D 9050 -NT

proxychains nc localhost 23456
```
## South Park
![image](https://github.com/user-attachments/assets/407c9985-a54e-4e8f-9663-e2b860738bb7)

```
telnet 10.50.23.236 ---> ssh student@10.50.42.163 -R 21899:localhost:8462 -NT (Telnet to Eric, create a remote tunnel back to BIH)

ssh net2_student18@localhost -p 21899 -L 21801:192.168.100.60:22 -NT (Create a local tunnel going to Kenny)

ssh net2_student18@localhost -p 21801 -L 21802:10.90.50.140:6481 -NT (Create a local tunnel going to Kyle)

ssh net2_student18@localhost -p 21802 -L 21803:172.20.21.5:23 -NT (Create a local tunnel going to Stan via telnet port 23)

telnet localhost 21803 (Telnet to stan)  ----> ssh net2_student18@172.20.21.4 -p 6481 -R 21898:localhost:22 -NT (creating a remote tunnel going back to Kyle)

ssh net2_student18@localhost -p 21802 -L 21805:localhost:21898 -NT (Connecting the two Remote Tunnels. -p will be the port opened up for that device 21802)

ssh net2_student18@localhost -p 21805  -----> ss -ntlp

ssh net2_student18@localhost -p 21805 -D 9050 -NT
```
## ARCHER:
![image](https://github.com/user-attachments/assets/8302e2a3-1bab-4d2e-a5ca-1ed8ce79797e)

```
ssh net2_student18@10.50.38.17 -p 22 -L 21801:10.1.2.200:23 -NT ( creates a Local tunnel going to Lana from Sterling )

telnet localhost 21801 -----> ssh net2_student18@10.1.2.130 -p 22 -R 21899:localhost:8976 -NT ( Telnet to lana then set up a Remote tunnel going back to sterling) 

ssh net2_student18@10.50.38.17 -p 22 -L 21802:localhost:21899 -NT ( creating a local tunnel to lana )

ssh net2_student18@localhost -p 21802 -L 21803:10.2.5.20:22 -NT ( create a local tunnel going to Cheryl )

ssh net2_student18@localhost -p 21803 -L 21804:10.3.9.39:23 -NT ( create a local tunnel going to Malory via telnet )

telnet localhost 21804 -----> ssh net2_student18@10.3.9.33 -p 22 -R 21898:localhost:3597 -NT ( telnet to malory then set up a remote tunnel going back to cheryl via ssh )

ssh net2_student18@localhost -p 21803 -L 21806:localhost:21898 -NT

ssh net2_student18@localhost -p 21806 -D 9050 -NT  -----> proxychains nc localhost 58246 ( Dynamic tunnel )
```
## FAAAA Tunnel
```
telnet 10.50.42.86 -------> ssh student@10.50.42.163 -R 21899:localhost:22 (telnet to floating IP then created a Remote tunnel back to BIH / enumm devices)

BIH>: ssh net2_student18@localhost -p 21899 -L 21802:192.168.0.40:5555 -NT (Tunnel going to the .40 device)

192.168.0.40>: ssh net2_student18@localhost -p 21802 -L 21804:172.16.0.60:23 -NT (Tunnel going from the .40 to the .60 TELNET PORT network via telnet port)

BIH>: telnet localhost 21804 -------->

172.16.0.60>: ssh net2_student18@192.168.0.40 -p 5555 -R 21895:localhost:22 -NT (created a Remote tunnel via SSH back to the .40 from the 172.16.0.60 device) 

BIH>: ssh net2_student18@localhost -p 21802 -L 21810:localhost:21895 -NT ( created a local tunnel to the .40 on the same port I used to create  the first local tunnel to the .40)

BIH>: ssh net2_comrade18@localhost -p 21810 (connecting the two Remote tunnels together)
```

## SCP within a tunnel
```
proxychains scp net2_student18@192.168.10.101:/usr/share/cctc/capstone-analysis_HEX-ENCODED.pcap .

proxychains scp net2_student18@192.168.10.101:/usr/share/cctc/* .   (Copies everything from directory)
```
## Stream Sock  /// https://net.cybbh.io/public/networking/latest/12_programming/fg.html#_12_5_demonstration_of_creating_stream_and_dgram_sockets
```
stream_sock.py
```
## rules: find   ///  https://net.cybbh.io/public/networking/latest/11_acl/fg.html
```
cat alien-abductions.rules | grep -e "flags: 0"
```
## TCPDUMP  /////  https://net.cybbh.io/public/networking/latest/06_traffic_cap/fg.html#_6_2_1_explain_tcpdump_primitives
```
 Basic TCPDump options

    -A Prints the frame payload in ASCII.

tcpdump -A

    -D Print the list of the network interfaces available on the system and on which TCPDump can capture packets. For each network interface, a number and an interface name, followed by a text description of the interface, is printed. This can be used to identify which interfaces are available for traffic capture.

tcpdump -D

    -i Normally, eth0 will be selected by default if you do not specify an interface. However, if a different interface is needed, it must be specified.

tcpdump -i eth0

    -e Prints Data-Link Headers. Default is to print the encapsulated protocol only.

tcpdump -e

    -X displays packet data in HEX and ASCII.
    -XX displays the packet data in HEX and ASCII to include the Ethernet portion.

tcpdump -i eth0 -X
tcpdump -i eth0 -XX

    -w writes the capture to an output file

tcpdump -w something.pcap

    -r reads from the pcap

tcpdump -r something.pcap

    -v gives more verbose output with details on the time to live, IPID, total length, options, and flags. Additionally, it enables integrity checking.

tcpdump -vv

    -n Does not covert protocol and addresses to names

tcpdump -n
```
## tcpdump portrange 20-100 and host 10.1.0.2 or host 10.1.0.3 and dst net 10.2.0.0/24 -vn

## tcpdump -i eth -XX -vv dst host 

## CAP TUNNEL:
```
ssh net2_student18@10.50.31.50 -p 7777 -L 21801:10.2.2.7:23 -NT

telnet localhost 21801

ssh net2_student18@10.2.2.6 -p 7777 -R 21899:localhost:2222 -NT   ----->> ssh net2_student18@10.50.31.50 -p 7777 -L 21802:localhost:21899 -NT

ssh net2_comrade18@localhost -p 21802 -L 21803:10.10.10.140:301 -NT
```
