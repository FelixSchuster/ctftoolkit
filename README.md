# ctftoolkit

*ctftoolkit* transforms Ubuntu into a pentesting distribution by installing a few tools I usually use when playing CTFs.
This script was tested on Ubuntu MATE 24.04.2 LTS.

```
          __    _____  __                .__   __   .__  __
    _____/  |__/ ____\/  |_  ____   ____ |  | |  | _|__|/  |_ 
  _/ ___\   __\   __\\   __\/  _ \ /  _ \|  | |  |/ /  \   __\
  \  \___|  |  |  |   |  | (  <_> |  <_> )  |_|    <|  ||  |
   \___  >__|  |__|   |__|  \____/ \____/|____/__|_ \__||__|
       \/                                          \/

  GitHub: github.com/FelixSchuster


  Usage: ctftoolkit.sh [option]

  Options:
    -h, --help              Display this help message
    -m, --mate              Configure the mate desktop environment
    -r, --regular-tools     Install regular tools
    -p, --pentest-tools     Install pentest tools and regular tools
```

The `--mate` option configures the Mate desktop environment as shown below.
It adds a script to display IP addresses in the taskbar and enables unlimited scrollback in the terminal.
If your network interfaces are named differently, edit the script located in `/opt/ctftoolkit/templates/display_ips.sh`.

![Mate Desktop](./img/mate-desktop.png)

I recently added a script to install the Mate desktop environment on Kali as well.
Check the contents of the `kali` folder for further information.

# Setup

```
git clone https://github.com/FelixSchuster/ctftoolkit.git
cd ctftoolkit
sudo chmod +x ctftoolkit.sh
sudo ./ctftoolkit.sh
```
Note that `ctftoolkit.sh` relies on resources located in `./templates`.
Ensure to clone the entire repository, as if the script fails to resolve dependencies, it will not function as intended.

# Disclaimer

I am not responsible for any damage caused to your system.
Some of the changes made by the script might be considered insecure.
It is recommended run the script in virtual machines only.

This script is inspired by [pimpmykali](https://github.com/Dewalt-arch/pimpmykali.git) created by Dewalt.
