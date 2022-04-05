wget https://packages.microsoft.com/config/ubuntu/20.04/packages-microsoft-prod.deb -O packages-microsoft-prod.deb
sudo dpkg -i packages-microsoft-prod.deb
sudo apt update && sudo apt install apt-transport-https
sudo apt update && sudo apt install dotnet-sdk-5.0
git clone https://github.com/microsoft/restler-fuzzer
cd restler-fuzzer
sudo mkdir /usr/bin/restler
sudo python ./build-restler.py --dest_dir /usr/bin/restler
echo 'export PATH=$PATH:/usr/bin/restler/restler' >> ~/.profile
source ~/.profile
