#!/bin/bash

redexclaim="\e[1;91m[!]\e[0m"
greenplus="\e[1;92m[+]\e[0m"
yellowstar="\e[1;93m[*]\e[0m"

install_regular_tools=false
install_pentest_tools=false
install_mate=false

USERNAME=$(who | awk 'NR==1 {print $1}')

display_ascii_art() {
    base64_ascii="ICAgICAgICAgIF9fICAgIF9fX19fICBfXyAgICAgICAgICAgICAgICAuX18gICBfXyAgIC5fXyAgX18KICAgIF9fX19fLyAgfF9f"
    base64_ascii+="LyBfX19fXC8gIHxfICBfX19fICAgX19fXyB8ICB8IHwgIHwgX3xfX3wvICB8XyAKICBfLyBfX19cICAgX19cICAgX19cXCAgIF9f"
    base64_ascii+="XC8gIF8gXCAvICBfIFx8ICB8IHwgIHwvIC8gIFwgICBfX1wKICBcICBcX19ffCAgfCAgfCAgfCAgIHwgIHwgKCAgPF8+IHwgIDxf"
    base64_ascii+="PiApICB8X3wgICAgPHwgIHx8ICB8CiAgIFxfX18gID5fX3wgIHxfX3wgICB8X198ICBcX19fXy8gXF9fX18vfF9fX18vX198XyBc"
    base64_ascii+="X198fF9ffAogICAgICAgXC8gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBcLwo="

    echo ""
    echo $base64_ascii | base64 -d
    echo ""
    echo "  Version: 1.0.0 - 2024/03/24"
    echo "  GitHub: github.com/FelixSchuster"
    echo ""
}

check_root_and_handle_options() {
    if [ $# -lt 1 ]; then
        echo -e "\n  $redexclaim No option specified"
        usage
        exit 1
    fi
    while [ $# -gt 0 ]; do
        case $1 in
        -h | --help)
            usage
            exit 0
            ;;
        -m | --mate)
            install_mate=true
            ;;
        -r | --regular-tools)
            install_regular_tools=true
            ;;
        -p | --pentest-tools)
            install_pentest_tools=true
            ;;
        *)
            echo -e "\n  $redexclaim Invalid option: $1"
            usage
            exit 1
            ;;
        esac
        shift
    done

    if [ $EUID -ne 0 ]; then
        echo -e "\n  $redexclaim Script must be run with 'sudo ${0##*/}' or as root!"
        usage
        exit 1
    fi

    echo -e "\n  $yellowstar Specified options:"
    if [ "$install_mate" = true ]; then
        echo -e "    -m, --mate              Configure the MATE desktop environment"
    fi
    if [ "$install_pentest_tools" = true ]; then
        echo -e "    -p, --pentest-tools     Install pentest tools and regular tools"
    elif [ "$install_regular_tools" = true ]; then
        echo -e "    -r, --regular-tools     Install regular tools"
    fi
}

usage() {
    echo -e "\n  Usage: ${0##*/} [option]\n"
    echo -e "  Options:"
    echo -e "    -h, --help              Display this help message"
    echo -e "    -m, --mate              Configure the MATE desktop environment"
    echo -e "    -r, --regular-tools     Install regular tools"
    echo -e "    -p, --pentest-tools     Install pentest tools and regular tools\n"
}

update_system() {
    echo -e "\n  $yellowstar Updating apt cache ...\n"
    apt-get update -y

    echo -e "\n  $yellowstar Upgrading packages ...\n"
    apt-get upgrade -y

    echo -e "\n  $yellowstar Upgrading distribution ...\n"
    apt-get dist-upgrade -y
}

configure_mate() {
    echo -e "\n  $yellowstar Configuring MATE Desktop Environment...\n"

    if ! uname -a | grep -qi "ubuntu-mate"; then
        echo "\n  $redexclaim This configuration might fail since the OS is not Ubuntu MATE."
        read -rp "Do you want to proceed anyway? (y/n): " choice
        case "$choice" in
            y|Y ) echo "Proceeding...";;
            * ) echo "Aborting."; return 1;;
        esac
    fi
    
    USER_PID=$(pgrep -u $USERNAME -n mate-session)
    USER_DBUS=$(tr '\0' '\n' < /proc/$USER_PID/environ | grep DBUS_SESSION_BUS_ADDRESS= | sed -e 's/DBUS_SESSION_BUS_ADDRESS=//')
    sudo -u $USERNAME DBUS_SESSION_BUS_ADDRESS="$USER_DBUS" dconf load /org/mate/ < /opt/ctftoolkit/templates/mate.conf
}

install_regular_tools() {
    echo -e "\n  $yellowstar Installing git ...\n"
    apt-get install git -y

    echo -e "\n  $yellowstar Installing snap ...\n"
    apt-get install snapd -y

    echo -e "\n  $yellowstar Installing curl ...\n"
    apt-get install curl -y

    echo -e "\n  $yellowstar Installing python3-dev ...\n"
    apt-get install python3-dev -y

    echo -e "\n  $yellowstar Installing Wireguard ...\n"
    apt-get install wireguard -y

    echo -e "\n  $yellowstar Installing OpenSSH-Server ...\n"
    apt-get install openssh-server -y
    systemctl stop ssh
    systemctl disable ssh

    echo -e "\n  $yellowstar Installing jq ...\n"
    apt-get install jq -y

    echo -e "\n  $yellowstar Installing Docker Compose ...\n"
    install_docker_compose

    echo -e "\n  $yellowstar Installing net-tools ...\n"
    apt-get install net-tools -y

    echo -e "\n  $yellowstar Installing wireless-tools ...\n"
    apt-get install wireless-tools -y

    echo -e "\n  $yellowstar Installing dos2unix ...\n"
    apt-get install dos2unix -y

    echo -e "\n  $yellowstar Installing Visual Studio Code ...\n"
    snap install code --classic
}

install_pentest_tools() {
    echo -e "\n  $yellowstar Installing pip ...\n"
    apt-get install python3-pip -y

    echo -e "\n  $yellowstar Installing pipx ...\n"
    apt-get install pipx -y

    echo -e "\n  $yellowstar Installing Ruby ...\n"
    apt-get install ruby-dev -y
    apt-get install ruby-rubygems -y

    echo -e "\n  $yellowstar Installing Ansible ...\n"
    apt-get install ansible -y

    echo -e "\n  $yellowstar Installing Searchsploit ...\n"
    snap install searchsploit

    echo -e "\n  $yellowstar Installing nmap ...\n"
    apt-get install nmap -y

    echo -e "\n  $yellowstar Installing Nikto ...\n"
    apt-get install nikto -y

    echo -e "\n  $yellowstar Installing ZAProxy ...\n"
    snap install zaproxy --classic

    echo -e "\n  $yellowstar Installing SQLMap ...\n"
    apt-get install sqlmap -y

    echo -e "\n  $yellowstar Installing SMBClient ...\n"
    apt-get install smbclient -y

    echo -e "\n  $yellowstar Installing Proxychains ...\n"
    install_proxychains

    echo -e "\n  $yellowstar Installing the Metasploit Framework ...\n"
    install_metasploit

    echo -e "\n  $yellowstar Installing mitm6 ...\n"
    PIPX_HOME=/opt/pipx PIPX_BIN_DIR=/usr/local/bin pipx install mitm6

    echo -e "\n  $yellowstar Installing Impacket ...\n"
    PIPX_HOME=/opt/pipx PIPX_BIN_DIR=/usr/local/bin pipx install impacket

    echo -e "\n  $yellowstar Installing Coercer ...\n"
    PIPX_HOME=/opt/pipx PIPX_BIN_DIR=/usr/local/bin pipx install coercer

    echo -e "\n  $yellowstar Installing Certipy ...\n"
    PIPX_HOME=/opt/pipx PIPX_BIN_DIR=/usr/local/bin pipx install certipy-ad

    echo -e "\n  $yellowstar Installing Hashcat ...\n"
    apt-get install hashcat -y

    echo -e "\n  $yellowstar Installing aircrack-ng ...\n"
    apt-get install aircrack-ng -y

    echo -e "\n  $yellowstar Installing Hydra ...\n"
    apt-get install hydra -y

    echo -e "\n  $yellowstar Installing rlwrap ...\n"
    apt-get install rlwrap -y

    echo -e "\n  $yellowstar Installing cewl ...\n"
    apt-get install cewl -y

    echo -e "\n  $yellowstar Installing ffuf ...\n"
    apt-get install ffuf -y

    echo -e "\n  $yellowstar Installing dnsrecon ...\n"
    apt-get install dnsrecon -y

    echo -e "\n  $yellowstar Installing hcxtools ...\n"
    apt-get install hcxtools -y

    echo -e "\n  $yellowstar Installing enum4linux ...\n"
    snap install enum4linux

    echo -e "\n  $yellowstar Installing Postman ...\n"
    snap install postman

    echo -e "\n  $yellowstar Installing xfreerdp ...\n"
    apt-get install freerdp2-x11 -y

    echo -e "\n  $yellowstar Installing wfuzz ...\n"
    apt-get install wfuzz -y

    echo -e "\n  $yellowstar Installing WPScan ...\n"
    gem install wpscan

    echo -e "\n  $yellowstar Installing fcrackzip ...\n"
    apt-get install fcrackzip -y

    echo -e "\n  $yellowstar Installing exiftool ...\n"
    apt-get install libimage-exiftool-perl -y

    echo -e "\n  $yellowstar Downloading John ...\n"
    download_john

    echo -e "\n  $yellowstar Installing Bloodhound Community Edition ...\n"
    install_bloodhound

    echo -e "\n  $yellowstar Dowloading SecLists ...\n"
    download_seclists

    echo -e "\n  $yellowstar Dowloading Mimikatz ...\n"
    download_mimikatz

    echo -e "\n  $yellowstar Dowloading PEAS ...\n"
    download_peas

    echo -e "\n  $yellowstar Dowloading Privesccheck ...\n"
    git clone https://github.com/itm4n/PrivescCheck /opt/privesccheck

    echo -e "\n  $yellowstar Installing Netexec ...\n"
    install_netexec

    echo -e "\n  $yellowstar Installing Evil-WinRM ...\n"
    install_evilwinrm

    echo -e "\n  $yellowstar Installing Gobuster ...\n"
    install_gobuster

    echo -e "\n  $yellowstar Installing Gowitness ...\n"
    GOBIN=/usr/local/bin go install github.com/sensepost/gowitness@latest

    echo -e "\n  $yellowstar Installing Assetfinder ...\n"
    sudo GOBIN=/usr/local/bin go install github.com/tomnomnom/assetfinder@lates

    echo -e "\n  $yellowstar Installing Kerbrute ...\n"
    install_kerbrute

    echo -e "\n  $yellowstar Installing Responder ...\n"
    install_responder

    echo -e "\n  $yellowstar Installing Ghidra ...\n"
    install_ghidra

    echo -e "\n  $yellowstar Installing Nessus ...\n"
    install_nessus

    echo -e "\n  $yellowstar Installing DirBuster ...\n"
    install_dirbuster

    echo -e "\n  $yellowstar Installing BurpSuite ...\n"
    install_burpsuite

    echo -e "\n  $yellowstar Downloading ntlm_theft ...\n"
    download_ntlm_theft

    echo -e "\n  $yellowstar Downloading pkinittools ...\n"
    download_pkinittools

    echo -e "\n  $yellowstar Installing ldapdomaindump ...\n"
    PIPX_HOME=/opt/pipx PIPX_BIN_DIR=/usr/local/bin pipx install ldapdomaindump

    echo -e "\n  $yellowstar Installing adidnsdump ...\n"
    PIPX_HOME=/opt/pipx PIPX_BIN_DIR=/usr/local/bin pipx install git+https://github.com/dirkjanm/adidnsdump

    echo -e "\n  $yellowstar Installing PyWhisker ...\n"
    PIPX_HOME=/opt/pipx PIPX_BIN_DIR=/usr/local/bin pipx install git+https://github.com/ShutdownRepo/pywhisker

    echo -e "\n  $yellowstar Installing enum4linux-ng ...\n"
    PIPX_HOME=/opt/pipx PIPX_BIN_DIR=/usr/local/bin pipx install git+https://github.com/cddmp/enum4linux-ng

    echo -e "\n  $yellowstar Installing ntpdate ...\n"
    apt-get install ntpdate -y

    echo -e "\n  $yellowstar Installing Wireshark ...\n"
    install_wireshark

    echo -e "\n  $yellowstar Fixing 'sudo: command not found' errors ...\n"
    fix_sudo
}

install_docker_compose() {
    apt-get install ca-certificates curl -y
    install -m 0755 -d /etc/apt/keyrings
    curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc
    chmod a+r /etc/apt/keyrings/docker.asc
    echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/ubuntu \
        $(. /etc/os-release && echo "$VERSION_CODENAME") stable" | \
        tee /etc/apt/sources.list.d/docker.list > /dev/null
    apt-get update
    apt-get install docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin -y
    usermod -aG docker $USERNAME
}

download_john() {
    # see https://github.com/openwall/john/blob/bleeding-jumbo/doc/INSTALL-UBUNTU
    apt-get -y install git build-essential libssl-dev zlib1g-dev 
    git clone https://github.com/openwall/john -b bleeding-jumbo /opt/john
    cd /opt/john/src
    ./configure && make -s clean && make -sj4
}

download_ntlm_theft() {
    git clone https://github.com/Greenwolf/ntlm_theft.git /opt/ntlm_theft
    chmod +x /opt/ntlm_theft/ntlm_theft.py
    cd /opt/ntlm_theft
    python3 -m venv venv
    source venv/bin/activate
    pip3 install xlsxwriter
    deactivate
}

install_metasploit() {
    curl https://raw.githubusercontent.com/rapid7/metasploit-omnibus/master/config/templates/metasploit-framework-wrappers/msfupdate.erb > msfinstall
    chmod 755 msfinstall
    ./msfinstall
    rm msfinstall
}

install_proxychains() {
    apt-get install proxychains4 -y
    ansible-playbook /opt/ctftoolkit/templates/ansible-proxychains.yml
}

install_nessus() {
    nessus_file=$(curl https://www.tenable.com/downloads/nessus\?loginAttempted\=true | grep -o -m1 -E "Nessus-[0-9]{1,2}.[0-9]{1}.[0-9]{1}-debian10_amd64.deb" | grep -m1 -i ".deb")
    releases_url="https://www.tenable.com/downloads/api/v2/pages/nessus/files/"

    wget -q $releases_url/$nessus_file -O /opt/ctftoolkit/templates/nessus.deb
    dpkg -i /opt/ctftoolkit/templates/nessus.deb
    rm -f /opt/ctftoolkit/templates/nessus.deb
    systemctl enable --now nessusd
}

install_wireshark() {
    DEBIAN_FRONTEND=noninteractive apt-get -y install wireshark
    # chgrp wireshark /usr/bin/dumpcap
    setcap cap_net_raw,cap_net_admin+eip /usr/bin/dumpcap
    # usermod -aG wireshark $USERNAME
    # chown -R $USERNAME /usr/bin/dumpcap
}

install_burpsuite() {
    curl "https://portswigger-cdn.net/burp/releases/download?product=community&version=2024.5.5&type=Linux" -o /opt/ctftoolkit/templates/install_burpsuite.sh
    chmod +x /opt/ctftoolkit/templates/install_burpsuite.sh
    /opt/ctftoolkit/templates/install_burpsuite.sh -q
    rm -f /opt/ctftoolkit/templates/install_burpsuite.sh
}

install_bloodhound() {
    PIPX_HOME=/opt/pipx PIPX_BIN_DIR=/usr/local/bin pipx install bloodhound-ce
    if [ ! -d /opt/bloodhound ]; then
        mkdir /opt/bloodhound
    fi
    curl -L https://ghst.ly/getbhce -o /opt/bloodhound/docker-compose.yaml
    docker compose -f /opt/bloodhound/docker-compose.yaml pull
    if [ ! "$(cat /etc/bash.bashrc | grep "alias bloodhound")" ]; then
        echo 'alias bloodhound="docker compose -f /opt/bloodhound/docker-compose.yaml up"' >> /etc/bash.bashrc
    fi
    if [ ! "$(cat /etc/bash.bashrc | grep "alias bloodhound-reset")" ]; then
        echo 'alias bloodhound-reset="docker compose -f /opt/bloodhound/docker-compose.yaml down -v"' >> /etc/bash.bashrc
    fi
}

install_dirbuster() {
    apt-get install openjdk-17-jdk openjdk-17-jre -y
    git clone https://gitlab.com/kalilinux/packages/dirbuster /opt/dirbuster
    if [ ! "$(cat /etc/bash.bashrc | grep "alias dirbuster")" ]; then
        echo 'alias dirbuster="java -jar /opt/dirbuster/DirBuster-1.0-RC1.jar"' >> /etc/bash.bashrc
    fi
}

download_seclists() {
    if [ ! -d /opt/seclists ]; then
        git clone https://github.com/danielmiessler/SecLists.git /opt/seclists
    else
        cd /opt/seclists
        git pull
    fi
    if [ ! -d /opt/rockyou ]; then
        mkdir /opt/rockyou
    fi
    tar -zxvf /opt/seclists/Passwords/Leaked-Databases/rockyou.txt.tar.gz -C /opt/rockyou
}

download_mimikatz() {
    if [ ! -d /opt/mimikatz ]; then
        mkdir /opt/mimikatz
    fi
    curl https://github.com/gentilkiwi/mimikatz/releases/download/2.2.0-20220919/mimikatz_trunk.zip -o /opt/mimikatz/mimikatz_trunk.zip
}

download_peas() {
    if [ ! -d /opt/linpeas ]; then
        mkdir /opt/linpeas
    fi
    if [ ! -d /opt/winpeas ]; then
        mkdir /opt/winpeas
    fi
    releases_url="https://github.com/carlospolop/PEASS-ng/releases/latest/download/"
    linpeas_arr=('linpeas.sh' 'linpeas_darwin_amd64' 'linpeas_darwin_arm64' 'linpeas_fat.sh' 'linpeas_linux_386' 'linpeas_linux_amd64' 'linpeas_linux_arm')
    winpeas_arr=('winPEAS.bat' 'winPEASany.exe' 'winPEASany_ofs.exe' 'winPEASx64_ofs.exe' 'winPEASx86.exe' 'winPEASx86_ofs.exe')
    for linpeas_file in ${linpeas_arr[@]}; do
        echo -e "Downloading $linpeas_file .."
        wget -q $releases_url/$linpeas_file -O /opt/linpeas/$linpeas_file
        chmod +x /opt/linpeas/$linpeas_file
    done
    for winpeas_file in ${winpeas_arr[@]}; do
        echo -e "Downloading $winpeas_file .."
        wget -q $releases_url/$winpeas_file -O /opt/winpeas/$winpeas_file
        chmod +x /opt/winpeas/$winpeas_file
    done
}

download_pkinittools() {
    git clone https://github.com/dirkjanm/PKINITtools.git
    cd PKINITtools/
    python3 -m venv venv
    source venv/bin/activate
    pip install -r requirements.txt
    # see https://github.com/dirkjanm/PKINITtools/issues/9
    pip install -I git+https://github.com/wbond/oscrypto.git
    deactivate
}

install_evilwinrm() {
    gem install evil-winrm
    # see https://forum.hackthebox.com/t/evil-winrm-error-on-connection-to-host/257342/18
    ansible-playbook /opt/ctftoolkit/templates/ansible-winrm.yml
}

install_gobuster() {
    snap install go --classic
    git clone https://github.com/OJ/gobuster.git /opt/gobuster
    cd /opt/gobuster
    go get
    go build
    if [ ! "$(echo /etc/bash.bashrc | grep 'alias gobuster')" ]; then
        echo 'alias gobuster="/opt/gobuster/gobuster"' >> /etc/bash.bashrc
    fi
}

install_kerbrute() {
    if [ ! -d /opt/kerbrute ]; then
        mkdir /opt/kerbrute
    fi
    releases_url="https://github.com/ropnop/kerbrute/releases/latest/download/"
    kerbrute_arr=('kerbrute_darwin_386 ' 'kerbrute_darwin_amd64 ' 'kerbrute_linux_386' 'kerbrute_linux_amd64 ' 'kerbrute_windows_386.exe ' 'kerbrute_windows_amd64.exe')
    for kerbrute_file in ${kerbrute_arr[@]}; do
        echo -e "Downloading $kerbrute_file .."
        wget -q $releases_url/$kerbrute_file -O /opt/kerbrute/$kerbrute_file
        chmod +x /opt/kerbrute/$kerbrute_file
    done
    if [ ! "$(cat /etc/bash.bashrc | grep "alias kerbrute")" ]; then
        echo 'alias kerbrute="/opt/kerbrute/kerbrute_linux_amd64"' >> /etc/bash.bashrc
    fi
}

install_netexec() {
    apt-get install build-essential
    apt-get install python3-dev
    PIPX_HOME=/opt/pipx PIPX_BIN_DIR=/usr/local/bin pipx install git+https://github.com/Pennyw0rth/NetExec
}

install_responder() {
    if [ ! -d /opt/responder ]; then
        git clone https://github.com/lgandx/Responder.git /opt/responder
    else
        cd /opt/responder
        git pull
    fi
    if [ ! "$(cat /etc/bash.bashrc | grep "alias responder")" ]; then
        echo 'alias responder="/opt/responder/Responder.py"' >> /etc/bash.bashrc
    fi
}

install_ghidra() {
    apt-get install openjdk-17-jdk -y
    if [ ! -d /opt/ghidra ]; then
        mkdir /opt/ghidra
    else
        rm -r /opt/ghidra/*
    fi
    releases_url="https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_11.1.2_build/ghidra_11.1.2_PUBLIC_20240709.zip"
    ghidra_file=$(basename "$releases_url")
    echo -e "Downloading $ghidra_file .."
    wget -q $releases_url -O /opt/ghidra/$ghidra_file
    unzip /opt/ghidra/$ghidra_file -d /opt/ghidra
    rm /opt/ghidra/$ghidra_file
    mv /opt/ghidra/ghidra_*/* /opt/ghidra/
    chmod +x /opt/ghidra/ghidraRun
    if [ ! "$(cat /etc/bash.bashrc | grep "alias ghidra")" ]; then
        echo 'alias ghidra="/opt/ghidra/ghidraRun"' >> /etc/bash.bashrc
    fi
}

fix_sudo() {
    # see https://askubuntu.com/questions/22037/aliases-not-available-when-using-sudo
    if [ ! "$(cat /etc/bash.bashrc | grep "alias sudo")" ]; then
        echo 'alias sudo="sudo "' >> /etc/bash.bashrc
    fi
}

install_plocate() {
    echo -e "\n  $yellowstar Installing plocate ...\n"
    apt-get install plocate -y
    updatedb
}

copy_ctftoolkit_to_opt() {
    echo -e "\n  $yellowstar Copying ctftoolkit to /opt/ctftoolkit/ ...\n"
    mkdir /opt/ctftoolkit
    cp -r -v * /opt/ctftoolkit/
    chmod +x /opt/ctftoolkit/templates/*.sh
}

fix_opt() {
    echo -e "\n  $yellowstar Updating the permissions of /opt ...\n"
    groupadd opt
    chown -R :opt /opt
    usermod -aG opt $USERNAME
}

main() {
    display_ascii_art
    check_root_and_handle_options "$@"
    copy_ctftoolkit_to_opt
    update_system

    if [ "$install_mate" = true ]; then
        configure_mate
    fi

    if [ "$install_pentest_tools" = true ]; then
        install_regular_tools
        install_pentest_tools
        install_plocate
    elif [ "$install_regular_tools" = true ]; then
        install_regular_tools
        install_plocate
    fi

    fix_opt

    echo -e "\n  $greenplus All done! Happy hacking!\n"
}

main "$@"

