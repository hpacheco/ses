
To successfully run the tasks in the labs you will need to have a few tools installed.
For this purpose, we recommend setting up a modern x86_64/amd64 Debian-based virtual machine.

# Configuration steps

1. Download [Kali Linux 2022.1](https://cdimage.kali.org/kali-2022.1/kali-linux-2022.1-installer-amd64.iso) and install it (keep the default software selection) with your favorite virtualization software such as [VirtualBox](https://www.virtualbox.org/). You may also run the virtual machine on the cloud. Most cloud services offer student discounts and sufficient credit for a few hours of experimentation. If in need, the instructors may also be able to offer additional Google Cloud credits.
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

* You may disable the lock screen feature in your VM by going to `Settings > Power Manager > Security`, changing `Automatically lock the session` to `Never` and unticking the `Lock screen when system is going to sleep` option.
* If you experience network errors in Docker inside your VM, try [this](https://stackoverflow.com/a/55072881) solution.



