#!/bin/bash

#Create the instance:
#Create the instance:
. nokia-openrc.sh

time openstack image create debian-9 \
  --file /home/nokia/images/debian-9.5.5-20181004-openstack-amd64.qcow2 \
  --disk-format qcow2 --container-format bare \
  --public


openstack security group delete openvpn_server
openstack security group create openvpn_server
openstack security group rule create --proto icmp openvpn_server
openstack security group rule create --proto tcp --dst-port 22 openvpn_server
openstack security group rule create --proto tcp --dst-port 123 openvpn_server
openstack security group rule create --proto udp --dst-port 123 openvpn_server
openstack security group rule create --proto tcp --dst-port 5000 openvpn_server
openstack security group rule create --proto udp --dst-port 5000 openvpn_server

net_id1=$(openstack network show extnet01 | grep "| id " | awk -F "|" '{print $3}' | sed 's/ //g') && echo $net_id1
ip_net1=10.2.1.198
openstack server create --flavor m1.large --image debian-9 \
   --nic net-id=$net_id1,v4-fixed-ip=$ip_net1 \
   --security-group openvpn_server --key-name key01 openvpn_server



openstack server list
#openstack server add floating ip openvpn_server 10.2.1.81
#Connect into the server:
ssh debian@10.2.1.81
sudo su - 

#Update system and install required libraries:
apt update -y && apt upgrade -y && apt install -y openjdk-8-jdk wget procps zlib1g-dev libjpeg-dev libfreetype6-dev libgif-dev build-essential swftools openssl default-jre default-jdk ntp openvpn iptables-persistent



#Prepare iptables:
iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
iptables -t nat -A POSTROUTING -o eth1 -j MASQUERADE
dpkg-reconfigure iptables-persistent

#IP forward and disable ipv6:
cat << EOF >> /etc/sysctl.conf
net.ipv4.ip_forward=1
net.ipv6.conf.eth0.disable_ipv6 = 1
net.ipv6.conf.eth1.disable_ipv6 = 1
EOF

net.ipv4.ip_forward=1
net.ipv6.conf.eth0.disable_ipv6 = 1
net.ipv6.conf.eth1.disable_ipv6 = 1


#Configure routes:
cd /etc/iproute2

#Add to rt_tables:
10   outcenter
11   velox


#Add route tables:


reboot
####################################################################################################################################
#     CA certificates:                                                                                                             #
####################################################################################################################################

rm -rf /tmp/*
cd ~
rm -rf /root/ca 2>/dev/null
mkdir /root/ca
cd /root/ca
mkdir certs crl newcerts private
chmod 400 private
touch index.txt
touch index.txt.attr
#echo 9000 > serial
awk -v min=00000000 -v max=99999990 'BEGIN{srand(); print int(min+rand()*(max-min+1))}' > serial

#Edit the /root/ca/openssl.cnf  (use the sample file attached (openssl_ca.cnf)
#Local:
#wget --no-check-certificate https://efb.homelinux.org:9443/nextcloud/index.php/s/gsQsbEkS8qka1GI/download -O /root/ca/openssl.cnf

#Remote:
wget https://www.dropbox.com/s/eokrc3tjq5aynj9/openssl.cnf?dl=1 -O /root/ca/openssl.cnf


sed -i 's/\.key\.pem/\.key/g' /root/ca/openssl.cnf
sed -i 's/\.cert\.pem/\.crt/g' /root/ca/openssl.cnf

#Define subject variable:
export SUBJECT='/emailAddress=ca@ca.cloud.int/CN=<hostname>/O=ca/OU=int/L=Cabo_Verde/ST=Minas_Gerais/C=BR'

#Create the root key 
cd /root/ca

#Define private key password:
ca_pass=`openssl rand -hex 20`

echo $ca_pass > ca_pass
chmod 000 ca_pass

#Generating root key:
openssl genrsa -aes256 -out private/ca.key -passout pass:$ca_pass 4096
chmod 400 private/ca.key

#Create the root certificate
CN="ca.cloud.int"
sub=`echo $SUBJECT | sed "s/<hostname>/$CN/g"`
   
cd /root/ca
openssl req -config openssl.cnf \
      -key private/ca.key \
      -passin pass:$ca_pass \
      -new -x509 -days 7300 -sha512 -extensions v3_ca \
      -subj $sub \
      -out certs/ca.crt


#Change its privilege
chmod 400 certs/ca.crt

#Verify the root certificate
openssl x509 -noout -text -in certs/ca.crt



####################################################################################################################################
#  Create an intermediate CA:                                                                                                      #
####################################################################################################################################

mkdir /root/ca/intermediate

cd /root/ca/intermediate
mkdir certs crl csr newcerts private
chmod 400 private
touch index.txt
touch index.txt.attr
ser=`awk -v min=10000000 -v max=99999990 'BEGIN{srand(); print int(min+rand()*(max-min+1))}'`
echo $ser > serial
echo $ser > /root/ca/intermediate/crlnumber
echo $ser > /root/ca/intermediate/certs/intermediate.srl

#Edit the /root/ca/intermediate/openssl.cnf  (use the sample file attached (openssl_ca_intermediate.cnf)
#Local:
#wget --no-check-certificate https://efb.homelinux.org:9443/nextcloud/index.php/s/CXAmB8RlBS8xUho/download -O /root/ca/intermediate/openssl.cnf

#Remote:
wget https://www.dropbox.com/s/16zv9hxsnd1twe5/openssl_intermediate.cnf?dl=1 -O /root/ca/intermediate/openssl.cnf

sed -i 's/\.key\.pem/\.key/g' /root/ca/intermediate/openssl.cnf
sed -i 's/\.cert\.pem/\.crt/g' /root/ca/intermediate/openssl.cnf

#To allow alternate name:
#sed -i '/extendedKeyUsage = serverAuth/a subjectAltName = @alt_names\n\n[ alt_names ]\nDNS.1 = localhost\n\n' /root/ca/intermediate/openssl.cnf


#Create the intermediate key
CN="intermediate.ca.cloud.int"
sub=`echo $SUBJECT | sed "s/<hostname>/$CN/g"`

cd /root/ca
intca_pass=`openssl rand -hex 20`
echo $intca_pass > intca_pass
openssl genrsa -aes256 -out intermediate/private/intermediate.key -passout pass:$intca_pass 4096
chmod 400 intermediate/private/intermediate.key

#Create the intermediate certificate
cd /root/ca
openssl req -config intermediate/openssl.cnf -new -sha512 \
     -key intermediate/private/intermediate.key \
     -passin pass:$intca_pass \
     -subj $sub \
     -out intermediate/csr/intermediate.csr

#Check it:
openssl req -in intermediate/csr/intermediate.csr -text -noout

#To create an intermediate certificate, use the root CA with the v3_intermediate_ca extension to sign the intermediate CSR. 
#The intermediate certificate should be valid for a shorter period than the root certificate. Ten years would be reasonable.

cd /root/ca
openssl ca -batch -config openssl.cnf -extensions v3_intermediate_ca \
      -days 3650 -notext -md sha512 \
      -in intermediate/csr/intermediate.csr \
      -passin pass:$ca_pass \
      -out intermediate/certs/intermediate.crt

chmod 400 intermediate/certs/intermediate.crt

#Verify the intermediate certificate 
openssl x509 -noout -text -in intermediate/certs/intermediate.crt
      
#Verify the intermediate certificate against the root certificate. An OK indicates that the chain of trust is intact.
openssl verify -CAfile certs/ca.crt intermediate/certs/intermediate.crt

#Create the certificate chain file (optional)
cat intermediate/certs/intermediate.crt certs/ca.crt > intermediate/certs/ca-chain.crt
chmod 444 intermediate/certs/ca-chain.crt



#Openvpn install:
#Create a server key:
mkdir -pv /etc/openvpn/certs
cd /etc/openvpn/certs

#Create a certificate request for server:

#Private key:
openssl genrsa -out server.openvpn.key 4096

#Cert request:
subj="/emailAddress=eduardoefb@gmail.com/CN=server.openvpn/O=efb/OU=com/L=Cabo_Verde/ST=Minas_Gerais/C=BR"
subj="/CN=server.openvpn"
openssl req -new -key server.openvpn.key -out server.openvpn.csr -subj $subj -sha512

#Sign certificate:
openssl ca -batch \
   -config ~/ca/intermediate/openssl.cnf \
   -extensions server_cert \
   -days 3650 \
   -notext \
   -md sha512 \
   -in server.openvpn.csr \
   -passin pass:`cat ~/ca/intca_pass` \
   -out server.openvpn.crt


#Generate a Diffie-Hellman PEM
openssl dhparam 4096 > dh4096.pem

#Generate An HMAC Key
openvpn --genkey --secret ta.key

#Trusted store:
cat ~/ca/certs/ca.crt > ca.crt
cat ~/ca/intermediate/certs/intermediate.crt >> ca.crt

#Get The Base Config
#gunzip -c /usr/share/doc/openvpn/examples/sample-config-files/server.conf.gz > /etc/openvpn/server.conf

#Edit file:
cat << EOF > /etc/openvpn/server.conf
proto tcp
port 5000
dev tun
server 10.0.0.0 255.255.255.0
route 10.0.0.0 255.255.255.0
push "route 10.50.0.0 255.255.0.0"
push "route 10.51.0.0 255.255.0.0"
push "route 10.52.0.0 255.255.0.0"
push "route 10.2.1.30 255.255.255.0"
push "dhcp-option DNS 10.2.1.30"
comp-lzo
keepalive 10 120
float
max-clients 10
persist-key
persist-tun
log-append /var/log/openvpn.log
verb 6
tls-server
dh /etc/openvpn/certs/dh4096.pem
ca /etc/openvpn/certs/ca.crt
cert /etc/openvpn/certs/server.openvpn.crt
key /etc/openvpn/certs/server.openvpn.key
tls-auth /etc/openvpn/certs/ta.key
status /var/log/openvpn.stats 
script-security 3 
tls-verify "/etc/openvpn/verify-cn /etc/openvpn/white_list"
tls-cipher TLS-DHE-RSA-WITH-AES-256-GCM-SHA384:TLS-DHE-RSA-WITH-AES-128-GCM-SHA256:TLS-DHE-RSA-WITH-AES-256-CBC-SHA:TLS-DHE-RSA-WITH-CAMELLIA-256-CBC-SHA:TLS-DHE-RSA-WITH-AES-128-CBC-SHA:TLS-DHE-RSA-WITH-CAMELLIA-128-CBC-SHA
EOF



#Create the "verify script":
cat << EOF > /etc/openvpn/verify-cn
#!/usr/bin/python

import sys

if len(sys.argv) < 4:
   sys.exit("Usage: %s whitelist_file depth x509_subject" % sys.argv[0])

whitelist_file = sys.argv[1]
depth = int(sys.argv[2])
x509 = str(sys.argv[3])

if depth == -1:
   sys.exit(0)
	
cn = x509.replace(",", " ").replace(" = ", "=").split("CN=")[1].split()[0]

fp = open(whitelist_file, "r")

for f in fp.readlines():
   if f.strip() == cn.strip():		
      sys.exit(0)

fp.close()
sys.exit(1)
EOF

chmod +x /etc/openvpn/verify-cn

#Create the whitelist file for whitelisted cns:
touch /etc/openvpn/white_list

#Populate whitelist file (client01 is an example, the first two lines must e present)
cat << EOF >> /etc/openvpn/white_list
ca.cloud.int
intermediate.ca.cloud.int
eduardo.openvpn
wandelio.openvpn
EOF


#user openvpn
#group nogroup

#Set Up An OpenVPN User
#adduser --system --shell /usr/sbin/nologin --no-create-home openvpn


#Start openvpn:
systemctl enable openvpn
systemctl restart openvpn


#Client:

#Cert request:
mkdir /root/clients
cd /root/clients

#Private key:
openssl genrsa -out eduardo.openvpn.key 4096

subj="/emailAddress=eduardoefb@gmail.com/CN=eduardo.openvpn/O=efb/OU=com/L=Cabo_Verde/ST=Minas_Gerais/C=BR"
subj="/CN=eduardo.openvpn"
openssl req -new -key eduardo.openvpn.key -out eduardo.openvpn.csr -subj $subj -sha512

#Sign certificate:
openssl ca -batch \
   -config ~/ca/intermediate/openssl.cnf \
   -days 365 \
   -notext \
   -md sha512 \
   -in eduardo.openvpn.csr \
   -passin pass:`cat ~/ca/intca_pass` \
   -out eduardo.openvpn.crt


openssl verify -CAfile  ~/ca/certs/ca.crt -untrusted /root/ca/intermediate/certs/intermediate.crt eduardo.openvpn.crt

#Copy Diffie-Hellman:
cp /etc/openvpn/certs/dh4096.pem .
cp /etc/openvpn/certs/ta.key .
cp /etc/openvpn/certs/ca.crt .

#Trusted store:
cat ~/ca/certs/ca.crt > ca.crt
cat ~/ca/intermediate/certs/intermediate.crt >> ca.crt


mkdir /tmp/wandelio
cd /tmp/wandelio


openssl genrsa -out wandelio.openvpn.key 4096

subj="/CN=wandelio.openvpn"
openssl req -new -key wandelio.openvpn.key -out wandelio.openvpn.csr -subj $subj -sha512

#Sign certificate:
openssl ca -batch \
   -config ~/ca/intermediate/openssl.cnf \
   -days 365 \
   -notext \
   -md sha512 \
   -in wandelio.openvpn.csr \
   -passin pass:`cat ~/ca/intca_pass` \
   -out wandelio.openvpn.crt


openssl verify -CAfile  ~/ca/certs/ca.crt -untrusted /root/ca/intermediate/certs/intermediate.crt wandelio.openvpn.crt

#Copy Diffie-Hellman:
cp /etc/openvpn/certs/dh4096.pem .
cp /etc/openvpn/certs/ta.key .
cp /etc/openvpn/certs/ca.crt .

#Trusted store:
cat ~/ca/certs/ca.crt > ca.crt
cat ~/ca/intermediate/certs/intermediate.crt >> ca.crt



#Configure client:
cat << EOF > /etc/openvpn/client.conf
client
dev tun
proto tcp
remote 10.2.1.68
port 5000

#pull
comp-lzo
keepalive 10 120
float
tls-client
persist-tun
persist-key

dh /etc/openvpn/certs/dh4096.pem
ca /etc/openvpn/certs/ca.crt
cert /etc/openvpn/certs/eduardo.openvpn.crt
key /etc/openvpn/certs/eduardo.openvpn.key
tls-auth /etc/openvpn/certs/ta.key
route-method exe
route-delay 2
EOF


#Linux mint:

sudo apt-get install network-manager-openvpn-gnome network-manager-openvpn









subj="/CN=felipe.openvpn"
openssl genrsa -out felipe.openvpn.key 4096
openssl req -new -key felipe.openvpn.key -out felipe.openvpn.csr -subj $subj -sha512

#Sign certificate:
openssl ca -batch \
   -config ~/ca/intermediate/openssl.cnf \
   -days 365 \
   -notext \
   -md sha512 \
   -in felipe.openvpn.csr \
   -passin pass:`cat ~/ca/intca_pass` \
   -out felipe.openvpn.crt
