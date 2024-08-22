#!/bin/bash

# TODO:
# unattended installation via dpkg-reconfigure for mate and wireshark
# download ligolo

greenplus="\e[1;33m[+]\e[0m"
yellowstar="\e[1;33m[*]\e[0m"
redexclaim="\e[1;31m[!]\e[0m"

install_regular_tools=false
install_pentest_tools=false
install_mate=false

current_user=$(who | awk 'NR==1 {print $1}')

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
        echo -e "    -m, --mate              Configure the mate desktop environment"
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
    echo -e "    -m, --mate              Configure the mate desktop environment"
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

install_mate_desktop() {
    echo -e "\n  $yellowstar Installing the mate desktop environment ...\n"
    apt-get install ubuntu-mate-desktop -y
    # DEBIAN_FRONTEND=noninteractive apt-get install ubuntu-mate-desktop -y
    # dpkg-reconfigure gdm3

    echo -e "\n  $yellowstar Saving the mate desktop environment configuration script ...\n"
    cp /opt/ctftoolkit/tools/configure_mate.sh /home/$current_user/Desktop/configure_mate.sh
    chmod +x /home/$current_user/Desktop/configure_mate.sh
}

install_regular_tools() {
    echo -e "\n  $yellowstar Installing git ...\n"
    apt-get install git -y

    echo -e "\n  $yellowstar Installing snap ...\n"
    apt-get install snapd -y

    echo -e "\n  $yellowstar Installing curl ...\n"
    apt-get install curl -y

    echo -e "\n  $yellowstar Installing wireguard ...\n"
    apt-get install wireguard -y
    apt-get install openresolv -y
    apt-get install resolvconf -y

    echo -e "\n  $yellowstar Installing openssh-server ...\n"
    apt-get install openssh-server -y
    systemctl stop ssh
    systemctl disable ssh

    echo -e "\n  $yellowstar Installing jq ...\n"
    apt-get install jq -y

    echo -e "\n  $yellowstar Installing docker compose ...\n"
    install_docker_compose

    echo -e "\n  $yellowstar Installing net-tools ...\n"
    apt-get install net-tools -y

    echo -e "\n  $yellowstar Installing wireless-tools ...\n"
    apt-get install wireless-tools -y

    echo -e "\n  $yellowstar Installing dos2unix ...\n"
    apt-get install dos2unix -y

    echo -e "\n  $yellowstar Installing visual studio code ...\n"
    snap install code --classic
}

install_pentest_tools() {
    echo -e "\n  $yellowstar Installing pip ...\n"
    apt-get install python3-pip -y

    echo -e "\n  $yellowstar Installing pipx ...\n"
    apt-get install pipx -y

    echo -e "\n  $yellowstar Installing rubygems ...\n"
    apt-get install ruby-dev -y
    apt-get install ruby-rubygems -y

    echo -e "\n  $yellowstar Installing ansible ...\n"
    apt-get install ansible -y

    echo -e "\n  $yellowstar Installing searchsploit ...\n"
    snap install searchsploit

    echo -e "\n  $yellowstar Installing nmap ...\n"
    apt-get install nmap -y

    echo -e "\n  $yellowstar Installing nikto ...\n"
    apt-get install nikto -y

    echo -e "\n  $yellowstar Installing zaproxy ...\n"
    snap install zaproxy --classic

    echo -e "\n  $yellowstar Installing sqlmap ...\n"
    apt-get install sqlmap -y

    echo -e "\n  $yellowstar Installing smbclient ...\n"
    apt-get install smbclient -y

    echo -e "\n  $yellowstar Installing proxychains ...\n"
    apt-get install proxychains -y

    echo -e "\n  $yellowstar Installing the metasploit framework ...\n"
    curl https://raw.githubusercontent.com/rapid7/metasploit-omnibus/master/config/templates/metasploit-framework-wrappers/msfupdate.erb > msfinstall
    chmod 755 msfinstall
    ./msfinstall

    echo -e "\n  $yellowstar Installing mitm6 ...\n"
    apt-get install python3-dev -y
    PIPX_HOME=/opt/pipx PIPX_BIN_DIR=/usr/local/bin pipx install mitm6

    echo -e "\n  $yellowstar Installing impacket ...\n"
    PIPX_HOME=/opt/pipx PIPX_BIN_DIR=/usr/local/bin pipx install impacket

    echo -e "\n  $yellowstar Installing hashcat ...\n"
    apt-get install hashcat -y

    echo -e "\n  $yellowstar Installing aircrack-ng ...\n"
    apt-get install aircrack-ng -y

    echo -e "\n  $yellowstar Installing hcxtools ...\n"
    apt-get install hcxtools -y

    echo -e "\n  $yellowstar Installing enum4linux ...\n"
    snap install enum4linux

    echo -e "\n  $yellowstar Installing xfreerdp ...\n"
    apt-get install freerdp2-x11 -y

    echo -e "\n  $yellowstar Installing wfuzz ...\n"
    apt-get install wfuzz -y

    echo -e "\n  $yellowstar Installing wpscan ...\n"
    gem install wpscan

    echo -e "\n  $yellowstar Installing fcrackzip ...\n"
    apt-get install fcrackzip -y

    echo -e "\n  $yellowstar Installing exiftool ...\n"
    apt-get install libimage-exiftool-perl -y

    echo -e "\n  $yellowstar Downloading john ...\n"
    download_john

    echo -e "\n  $yellowstar Installing bloodhound community edition ...\n"
    install_bloodhound

    echo -e "\n  $yellowstar Dowloading seclists ...\n"
    download_seclists

    echo -e "\n  $yellowstar Dowloading mimikatz ...\n"
    download_mimikatz

    echo -e "\n  $yellowstar Dowloading peas ...\n"
    download_peas

    echo -e "\n  $yellowstar Dowloading privesccheck ...\n"
    git clone https://github.com/itm4n/PrivescCheck /opt/privesccheck

    echo -e "\n  $yellowstar Installing netexec ...\n"
    install_netexec

    echo -e "\n  $yellowstar Installing evil-winrm ...\n"
    install_evilwinrm

    echo -e "\n  $yellowstar Installing gobuster ...\n"
    install_gobuster

    echo -e "\n  $yellowstar Installing kerbrute ...\n"
    install_kerbrute

    echo -e "\n  $yellowstar Installing responder ...\n"
    install_responder

    echo -e "\n  $yellowstar Installing ghidra ...\n"
    install_ghidra

    echo -e "\n  $yellowstar Installing nessus ...\n"
    install_nessus

    echo -e "\n  $yellowstar Installing burpsuite ...\n"
    install_burpsuite

    echo -e "\n  $yellowstar Downloading ntlm_theft ...\n"
    download_ntlm_theft

    echo -e "\n  $yellowstar Installing ldapdomaindump ...\n"
    apt-get install ldapdomaindump -y

    echo -e "\n  $yellowstar Installing ntpdate ...\n"
    apt-get install ntpdate -y

    echo -e "\n  $yellowstar Installing wireshark ...\n"
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
    usermod -aG docker $current_user
}

download_john() {
    # https://github.com/openwall/john/blob/bleeding-jumbo/doc/INSTALL-UBUNTU
    apt-get -y install git build-essential libssl-dev zlib1g-dev 
    git clone https://github.com/openwall/john -b bleeding-jumbo /opt/john
    cd /opt/john/src
    ./configure && make -s clean && make -sj4
    # if [ ! "$(echo /etc/bash.bashrc | grep '/opt/john/run')" ]; then
    #     echo 'export PATH="/opt/john/run:$PATH"' >> /etc/bash.bashrc
    # fi
}

download_ntlm_theft() {
    git clone https://github.com/Greenwolf/ntlm_theft.git /opt/ntlm_theft
    chmod +x /opt/ntlm_theft/ntlm_theft.py
    runuser $current_user --command "pip3 install xlsxwriter"
    # if [ ! "$(cat /etc/bash.bashrc | grep "alias ntlm_theft.py")" ]; then
    #     echo 'alias ntlm_theft.py="python3 /opt/ntlm_theft/ntlm_theft.py"' >> /etc/bash.bashrc
    # fi
}

install_nessus() {
    nessus_file=$(curl https://www.tenable.com/downloads/nessus\?loginAttempted\=true | grep -o -m1 -E "Nessus-[0-9]{1,2}.[0-9]{1}.[0-9]{1}-debian10_amd64.deb" | grep -m1 -i ".deb")
    releases_url="https://www.tenable.com/downloads/api/v2/pages/nessus/files/"

    wget -q $releases_url/$nessus_file -O /opt/ctftoolkit/tools/nessus.deb
    dpkg -i /opt/ctftoolkit/tools/nessus.deb
    rm -f /opt/ctftoolkit/tools/nessus.deb
    systemctl enable --now nessusd
}

install_wireshark() {
    apt-get -y install wireshark
    # DEBIAN_FRONTEND=noninteractive apt-get -y install wireshark
    # dpkg-reconfigure wireshark-common
    usermod -aG wireshark $current_user
    chown -R $current_user /usr/bin/dumpcap
}

install_burpsuite() {
    curl "https://portswigger-cdn.net/burp/releases/download?product=community&version=2024.5.5&type=Linux" -o /opt/ctftoolkit/tools/install_burpsuite.sh
    chmod +x /opt/ctftoolkit/tools/install_burpsuite.sh
    /opt/ctftoolkit/tools/install_burpsuite.sh -q
    rm -f /opt/ctftoolkit/tools/install_burpsuite.sh
}

install_bloodhound() {
    PIPX_HOME=/opt/pipx PIPX_BIN_DIR=/usr/local/bin pipx install bloodhound
    if [ ! -d /opt/bloodhound ]; then
        mkdir /opt/bloodhound
    fi
    curl -L https://ghst.ly/getbhce -o /opt/bloodhound/docker-compose.yaml
    docker compose -f /opt/bloodhound/docker-compose.yaml pull
    if [ ! "$(cat /etc/bash.bashrc | grep "alias bloodhound")" ]; then
        echo 'alias bloodhound="docker compose -f /opt/bloodhound/docker-compose.yaml up"' >> /etc/bash.bashrc
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
        git clone https://github.com/ParrotSec/mimikatz.git /opt/mimikatz
    else
        cd /opt/mimikatz
        git pull
    fi
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

install_evilwinrm() {
    gem install evil-winrm
    
    # see https://forum.hackthebox.com/t/evil-winrm-error-on-connection-to-host/257342/18
    ansible-playbook /opt/ctftoolkit/config/ansible.yml
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
    if [ ! -d /opt/netexec ]; then
        mkdir /opt/netexec
    fi
    releases_url="https://github.com/Pennyw0rth/NetExec/releases/latest/download/"
    netexec_file='nxc'
    echo -e "Downloading $netexec_file .."
    wget -q $releases_url/$netexec_file -O /opt/netexec/$netexec_file
    chmod +x /opt/netexec/$netexec_file
    if [ ! "$(cat /etc/bash.bashrc | grep "alias netexec")" ]; then
        echo 'alias netexec="/opt/netexec/nxc"' >> /etc/bash.bashrc
    fi
    if [ ! "$(cat /etc/bash.bashrc | grep "alias nxc")" ]; then
        echo 'alias nxc="/opt/netexec/nxc"' >> /etc/bash.bashrc
    fi
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

install_mlocate() {
    echo -e "\n  $yellowstar Installing mlocate ...\n"
    apt-get install mlocate -y
    updatedb
}

copy_ctftoolkit_to_opt() {
    echo -e "\n  $yellowstar Copying ctftoolkit to /opt/ctftoolkit/ ...\n"
    mkdir /opt/ctftoolkit
    cp -r -v * /opt/ctftoolkit/
    chmod +x /opt/ctftoolkit/tools/*.sh
}

main() {
    display_ascii_art
    check_root_and_handle_options "$@"
    copy_ctftoolkit_to_opt
    update_system

    if [ "$install_pentest_tools" = true ]; then
        install_regular_tools
        install_pentest_tools
        install_mlocate
    elif [ "$install_regular_tools" = true ]; then
        install_regular_tools
        install_mlocate
    fi
    if [ "$install_mate" = true ]; then
        install_mate_desktop
        echo -e "\n  $redexclaim Reboot and run '/home/$current_user/Desktop/ConfigureMate.sh' to apply the mate configuration\n"
    else
        echo -e "\n  $redexclaim Reboot to apply changes\n"
    fi

    echo -e "\n  $greenplus All done! Happy hacking!\n"
}

main "$@"
