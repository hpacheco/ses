
To successfully run the tasks in the labs you will need to have a few tools installed.
For this purpose, we recommend setting up a modern x86_64/amd64 Debian-based virtual machine. This is not mandatory: if you are willing to spend the effort, you may attempt to install the tools in your own environment; Docker containers are provided for the tools with a less standard deployment, which should facilitate their usage in any environment.

# Configuration steps

1. Download the latest Kali Linux 2023.4 (ISO image or VM image) and install it (keep the default software selection) with your favorite virtualization software such as [VirtualBox](https://www.virtualbox.org/). You may also run the virtual machine on the cloud. Most cloud services offer student discounts and sufficient credit for a few hours of experimentation. If in need, the instructors may also be able to offer additional Google Cloud credits.
2. Clone this repository within your VM:
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
* If you have difficulties installing packages, you may try to install or manually from <https://http.kali.org/kali/pool/main/l/linux/>.



