
To successfully run the tasks in the labs you will need to have a few tools installed.
For this purpose, we recommend setting up a modern x86_64/amd64 Debian-based virtual machine. This is not mandatory: if you are willing to spend the effort, you may attempt to install the tools in your own environment; Docker containers are provided for the tools with a less standard deployment, which should facilitate their usage in any environment. If you are on a recent M1/M2 Mac, then install the arm64 version of the Debian-based system. Some Docker containers will only be available for x86, and will run slower or even experience unexpected errors when emulated on arm64; the default x86 emulation will be done by QEMU; if you use Parallels Desktop on a Mac, you may also configure the VM to use your host's Rosetta emulation.

# Configuration steps

1. Download the latest Kali Linux image (2023.4 as of late) ISO image or VM image and install it (keep the default software selection) with your favorite virtualization software such as [VirtualBox](https://www.virtualbox.org/). You may also run the virtual machine on the cloud. Most cloud services offer student discounts and sufficient credit for a few hours of experimentation. If in need, the instructors may also be able to offer additional Google Cloud credits.
2. As Kali is a rolling distro, make sure to update to the latest version:
``` bash
sudo apt update && sudo apt dist-upgrade
```
3. Clone this repository within your VM:
``` bash
git clone https://github.com/hpacheco/ses
```
3. Install additional tools:
``` bash
cd ses/vm
sh install.sh
```

# Additional configurations

* You may disable the lock screen feature in your VM by changing `Settings > Privacy > Screen Lock`.
* If you experience network issues inside your VM, try [this](https://stackoverflow.com/a/55072881) solution.
* If you have difficulties installing packages, you may try to install them manually from <https://http.kali.org/kali/pool/main/l/linux/>.



