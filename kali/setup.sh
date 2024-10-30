#!/bin/bash

redexclaim="\e[1;91m[!]\e[0m"
greenplus="\e[1;92m[+]\e[0m"
yellowstar="\e[1;93m[*]\e[0m"

current_user=$(who | awk 'NR==1 {print $1}')

check_root() {
    if [ $EUID -ne 0 ]; then
        echo -e "\n  $redexclaim Script must be run with 'sudo ${0##*/}' or as root!"
        exit 1
    fi
}

update_system() {
    echo -e "\n  $yellowstar Updating apt cache ...\n"
    apt-get update -y

    echo -e "\n  $yellowstar Upgrading packages ...\n"
    apt-get upgrade -y

    echo -e "\n  $yellowstar Upgrading distribution ...\n"
    apt-get dist-upgrade -y
}

configure_timezone() {
    echo -e "\n  $yellowstar Configuring timezone ...\n"
    timedatectl set-timezone Europe/Vienna
}

install_mate() {
    echo -e "\n  $yellowstar Installing mate ...\n"
    apt-get update -y
    apt-get install libglib2.0-bin -y
    apt-get install mate-desktop-environment -y
}

configure_mate() {
    echo -e "\n  $yellowstar Configuring mate ...\n"

    # yaru theme
    wget https://github.com/bbjubjub2494/yaru-classic/releases/download/22.10.3.1/yaru-theme-gnome-shell_22.10.3+git4e47fe81_all.deb
    wget https://github.com/bbjubjub2494/yaru-classic/releases/download/22.10.3.1/yaru-theme-gtk_22.10.3+git4e47fe81_all.deb
    wget https://github.com/bbjubjub2494/yaru-classic/releases/download/22.10.3.1/yaru-theme-icon_22.10.3+git4e47fe81_all.deb
    wget https://github.com/bbjubjub2494/yaru-classic/releases/download/22.10.3.1/yaru-theme-sound_22.10.3+git4e47fe81_all.deb
    wget https://github.com/bbjubjub2494/yaru-classic/releases/download/22.10.3.1/yaru-theme-unity_22.10.3+git4e47fe81_all.deb
    dpkg -i yaru-theme-*.deb
    apt-get install -f -y
    rm yaru-theme-*.deb

    # caja open in terminal context menu
    apt-get install caja-open-terminal -y
    caja -q

    # mate configuration
    apt-get install dconf-cli -y
    
    echo "#!/bin/bash" >> configure_mate.sh
    echo "cat mate.conf | dconf load /org/mate/" >> configure_mate.sh
    echo "rm mate.conf" >> configure_mate.sh
    echo "rm configure_mate.sh" >> configure_mate.sh
    chmod 777 configure_mate.sh

    mkdir /opt/tools/
    mv display_ips.sh /opt/tools/
    chmod 777 /opt/tools/display_ips.sh
}

install_vscode() {
    echo -e "\n  $yellowstar Installing vscode ...\n"
    apt-get install wget gpg -y
    wget -qO- https://packages.microsoft.com/keys/microsoft.asc | gpg --dearmor > packages.microsoft.gpg
    install -D -o root -g root -m 644 packages.microsoft.gpg /etc/apt/keyrings/packages.microsoft.gpg
    echo "deb [arch=amd64,arm64,armhf signed-by=/etc/apt/keyrings/packages.microsoft.gpg] https://packages.microsoft.com/repos/code stable main" | tee /etc/apt/sources.list.d/vscode.list > /dev/null
    rm -f packages.microsoft.gpg
    apt-get install apt-transport-https -y
    apt-get update -y
    apt-get install code -y
}

main() {
    check_root "$@"

    # fix encoding and permissions
    dos2unix mate.conf display_ips.sh
    chmod +x display_ips.sh

    update_system
    configure_timezone
    install_mate
    configure_mate
    install_vscode

    echo -e "\n  $redexclaim Run 'sudo update-alternatives --config x-session-manager' and select '/usr/bin/mate-session'"
    echo -e "\n  $redexclaim Then reboot and run './configure_mate.sh'\n"

    rm setup.sh
}

main "$@"
