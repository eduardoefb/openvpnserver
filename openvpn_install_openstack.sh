#!/bin/bash

# Configure ansible:

# Change this to ignore key check:
sed -i 's/#host_key_checking = False/host_key_checking = False/g' /etc/ansible/ansible.cfg

cat << EOF >> /etc/hosts
10.2.1.198 openvpn_server
10.2.1.199 caserver
EOF

cat << EOF >> /etc/ansible/hosts
[openvpn]
openvpn_server

[ca]
caserver

EOF


#Create the instance:
. auth-rc
source <(openstack complete)


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

openstack keypair delete openvpn_key
openstack keypair create --public-key ~/.ssh/id_rsa.pub openvpn_key

net_id1=$(openstack network show extnet01 | grep "| id " | awk -F "|" '{print $3}' | sed 's/ //g') && echo $net_id1
ip_net1=10.2.1.198
image_name="ubuntu_1804"
openstack server delete openvpn_server
openstack server create --flavor m1.large --image ${image_name} \
   --nic net-id=$net_id1,v4-fixed-ip=$ip_net1 \
   --security-group openvpn_server --key-name openvpn_key openvpn_server
   
ip_net1=10.2.1.199
openstack server delete caserver
openstack server create --flavor m1.large --image ${image_name} \
   --nic net-id=$net_id1,v4-fixed-ip=$ip_net1 \
   --security-group openvpn_server --key-name openvpn_key caserver   

openstack server list

rm -f ~/.ssh/known_hosts
for n in openvpn_server caserver; do  ssh -o StrictHostKeyChecking=no ubuntu@${n} 'uname -n'; done

# Update:
cat << EOF > update.yml
- 
   name: Configure servers
   hosts: openvpn_server, caserver
   remote_user: ubuntu
   tasks:                                                              
      - name: Update (update -y)
        become: true
        apt:
           upgrade: yes
           update_cache: yes
           cache_valid_time: 86400
EOF
ansible-playbook update.yml

# Reboot after update:
for n in openvpn_server caserver; do  ssh -o StrictHostKeyChecking=no ubuntu@${n} 'sudo reboot'; done

# Check after reboot:
for n in openvpn_server caserver; do  ssh -o StrictHostKeyChecking=no ubuntu@${n} 'uname -n'; done

# Install packages:
cat << EOF > install.yml
- 
   name: Install
   hosts: openvpn_server, caserver
   remote_user: ubuntu
   vars:
      ansible_python_interpreter: /usr/bin/python3
      sysctl_config:
         net.ipv4.ip_forward: 1
         net.ipv4.conf.all.forwarding: 1
         net.ipv6.conf.eth0.disable_ipv6: 1      
   tasks:                                                              
      - name: Disable IPV6
        become: true
        shell:           
           echo "net.bridge.bridge-nf-call-ip6tables = 1 \nnet.bridge.bridge-nf-call-iptables = 1" > /etc/sysctl.d/k8s.conf &&  sysctl --system
           
      - name: Install packages
        become: true
        apt:        
           pkg: ['openjdk-8-jdk', 'wget', 'procps', 'zlib1g-dev', 'libjpeg-dev', 'libfreetype6-dev', 'libgif-dev', 'build-essential', 'swftools', 'openssl', 'default-jre', 'default-jdk', 'ntp', 'openvpn', 'git']      
     
      - name: Configure rc.local
        become: true
        shell:
           echo -e "#/bin/bash\n" > /etc/rc.local
           echo -e "iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE" >> /etc/rc.local
           chmod +x /etc/rc.local
      
      - name: Change sysctl
        become: true
        sysctl:
           name: '{{ item.key }}'
           value: '{{ item.value }}'
           sysctl_set: yes
           state: present
           reload: yes
           ignoreerrors: yes
        with_dict: '{{ sysctl_config }}'
      
      
EOF
ansible-playbook install.yml

####################################################################################################################################
#     CA certificates:                                                                                                             #
####################################################################################################################################

cat << EOF > configure_ca.yml
-
   name: Configure CA
   hosts: caserver
   remote_user: ubuntu
   vars:
      ansible_python_interpreter: /usr/bin/python3
      ca_subject: '/emailAddress=ca@ca.cloud.int/CN=ca.cloud.int/O=ca/OU=int/L=CBV/ST=MG/C=BR'
      int_ca_subject: '/emailAddress=ca@ca.cloud.int/CN=intermediate.ca.cloud.int/O=ca/OU=int/L=CBV/ST=MG/C=BR'
               
   tasks:
      - name: Configure CA
        become: true
        shell:            
           rm -rf /root/ca 2>/dev/null;                   
           mkdir /root/ca;
           cd /root/ca;
           mkdir certs crl newcerts private;
           chmod 400 private;
           touch index.txt;
           touch index.txt.attr;
           awk -v min=00000000 -v max=99999990 'BEGIN{srand(); print int(min+rand()*(max-min+1))}' > serial;
      
      - name: Remove clone directory      
        become: true
        file:
           path: /root/openvpnfiles
           state: absent
      
      - name: Clone config files
        become: true
        git:
           repo: "https://github.com/eduardoefb/openvpnserver.git"
           dest: /root/openvpnfiles
           clone: yes
      
      - name: Configure ca openssl.conf, create key
        become: true
        shell:           
           sed 's/\.key\.pem/\.key/g' /root/openvpnfiles/ca_config_sample/openssl.cnf > /root/ca/openssl.cnf;
           sed -i 's/\.cert\.pem/\.crt/g' /root/ca/openssl.cnf;
           openssl rand -hex 20 > /root/ca/ca_pass;
           chmod 000 /root/ca/ca_pass;
           openssl genrsa -aes256 -out /root/ca/private/ca.key -passout pass:\$(cat /root/ca/ca_pass) 4096;
           chmod 400 /root/ca/private/ca.key;
           openssl req -config /root/ca/openssl.cnf -key /root/ca/private/ca.key -passin pass:\$(cat /root/ca/ca_pass) -new -x509 -days 3650 -sha512 -extensions v3_ca -subj {{ca_subject}} -out /root/ca/certs/ca.crt;           

      - name: Create Directories
        become: true
        file:
           path: /root/ca/intermediate
           state: directory
           mode: 700

      - name: Create Directories
        become: true           
        file:
           path: /root/ca/intermediate/certs
           state: directory
           mode: 700         

      - name: Create Directories
        become: true
        file:
           path: /root/ca/intermediate/crl
           state: directory
           mode: 700         

      - name: Create Directories
        become: true
        file:
           path: /root/ca/intermediate/csr
           state: directory
           mode: 700         

      - name: Create Directories
        become: true
        file:
           path: /root/ca/intermediate/newcerts
           state: directory
           mode: 700
                    
      - name: Create Directories
        become: true                    
        file:
           path: /root/ca/intermediate/private
           state: directory
           mode: 700    
           
      - name: Configure intermediate CA
        become: true
        shell:
           touch /root/ca/intermediate/index.txt;
           touch /root/ca/intermediate/index.txt.attr;
           awk -v min=10000000 -v max=99999990 'BEGIN{srand(); print int(min+rand()*(max-min+1))}' > /root/ca/intermediate/crlnumber;
           cat /root/ca/intermediate/crlnumber > /root/ca/intermediate/serial;
           cat /root/ca/intermediate/crlnumber > /root/ca/intermediate/certs/intermediate.srl;
           sed 's/\.key\.pem/\.key/g' /root/openvpnfiles/ca_config_sample/openssl_intermediate.cnf > /root/ca/intermediate/openssl.cnf;
           sed -i 's/\.cert\.pem/\.crt/g' /root/ca/intermediate/openssl.cnf;
           intca_pass=\$(openssl rand -hex 20);      
           echo \$intca_pass > /root/ca/intca_pass;
           openssl genrsa -aes256 -out /root/ca/intermediate/private/intermediate.key -passout pass:\$intca_pass 4096;
           chmod 400 /root/ca/intermediate/private/intermediate.key;
           openssl req -config /root/ca/intermediate/openssl.cnf -new -sha512 -key /root/ca/intermediate/private/intermediate.key -passin pass:\$intca_pass -subj {{int_ca_subject}} -out /root/ca/intermediate/csr/intermediate.csr;
           openssl ca -batch -config /root/ca/openssl.cnf -extensions v3_intermediate_ca -days 3650 -notext -md sha512 -in /root/ca/intermediate/csr/intermediate.csr -passin pass:\$(cat /root/ca/ca_pass) -out /root/ca/intermediate/certs/intermediate.crt;
           cat /root/ca/intermediate/certs/intermediate.crt /root/ca/certs/ca.crt > /root/ca/intermediate/certs/ca-chain.crt;
           chmod 444 /root/ca/intermediate/certs/ca-chain.crt;

EOF

ansible-playbook configure_ca.yml



cat << EOF > configure_openvpn.yml
-
   name: Configure Openvpn
   hosts: openvpn_server
   remote_user: ubuntu
   vars:
      ansible_python_interpreter: /usr/bin/python3
      openvpn_subject: '/emailAddress=openvpn@ca.cloud.int/CN=server.openvpn/O=ca/OU=int/L=CBV/ST=MG/C=BR'
               
   tasks:
      - name: Remove directory      
        become: true
        file:
           path: /etc/openvpn/certs
           state: absent
              
      - name: Create Directories
        become: true
        file:
           path: /etc/openvpn/certs
           state: directory
           mode: 700 
      
      - name: Create private key
        become: true
        shell:
           openssl genrsa -out /etc/openvpn/certs/server.openvpn.key 4096;
           openssl req -new -key /etc/openvpn/certs/server.openvpn.key -out /tmp/server.openvpn.csr -subj {{ openvpn_subject }} -sha512;
           
      - name: Get file from openvpn
        become: true
        fetch:
          src: /tmp/server.openvpn.csr
          dest: /tmp/  
      
-
   name: Sign certificate
   hosts: caserver
   remote_user: ubuntu
   vars:
      ansible_python_interpreter: /usr/bin/python3
      openvpn_subject: '/emailAddress=openvpn@ca.cloud.int/CN=server.openvpn/O=ca/OU=int/L=CBV/ST=MG/C=BR'
               
   tasks:
      - name: Transfer csr to server     
        become: true
        copy:
           src: /tmp/openvpn_server/tmp/server.openvpn.csr
           dest: /tmp/server.openvpn.csr
           owner: root
           group: root
           mode: '0644'
      
      - name: Sign the certificate
        become: true
        shell:
           openssl ca -batch -config /root/ca/intermediate/openssl.cnf -extensions server_cert -days 3650 -notext -md sha512 -in /tmp/server.openvpn.csr -passin pass:\$(cat /root/ca/intca_pass) -out /tmp/server.openvpn.crt        


      - name: Get file from openvpn
        become: true
        fetch:
          src: /tmp/server.openvpn.crt
          dest: /tmp/ 
          
      - name: Get ca-chain from ca
        become: true  
        fetch:
           src: /root/ca/intermediate/certs/ca-chain.crt
           dest: /tmp/          

-
   name: Final configuration
   hosts: openvpn_server
   remote_user: ubuntu
   vars:
      ansible_python_interpreter: /usr/bin/python3                     
   tasks:
      - name: Transfer crt to openvpn     
        become: true
        copy:
           src: /tmp/caserver/tmp/server.openvpn.crt
           dest: /etc/openvpn/certs/server.openvpn.crt
           owner: root
           group: root
           mode: '0644'

      - name: Transfer crt to openvpn     
        become: true
        copy:
           src: /tmp/caserver/root/ca/intermediate/certs/ca-chain.crt
           dest: /etc/openvpn/certs/ca-chain.crt
           owner: root
           group: root
           mode: '0644'           
           
      - name: Generate a Diffie-Hellman PEM
        become: true
        shell:           
           openssl dhparam -dsaparam -out /etc/openvpn/certs/dh4096.pem 4096           

      - name: Generate An HMAC Key
        become: true
        shell:
           openvpn --genkey --secret /etc/openvpn/certs/ta.key
           
      - name: Clone config files
        become: true
        git:
           repo: "https://github.com/eduardoefb/openvpnserver.git"
           dest: /root/openvpnfiles
           clone: yes  
           
      - name: Copy config files
        become: true
        shell:
           cp /root/openvpnfiles/openvpn_conf_sample/* /etc/openvpn/                    
                           
EOF

ansible-playbook configure_openvpn.yml



#Get The Base Config
#gunzip -c /usr/share/doc/openvpn/examples/sample-config-files/server.conf.gz > /etc/openvpn/server.conf

#Edit file:
#cat << EOF > /etc/openvpn/server.conf
cat << EOF > server.conf
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


cat << EOF > server.conf
proto tcp
port 5000
dev tun
server 172.16.0.0 255.240.0.0
route 172.16.0.0 255.240.0.0
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

cat << EOF > verify-cn
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

chmod +x verify-cn

#Create the whitelist file for whitelisted cns:
touch /etc/openvpn/white_list

#Populate whitelist file (client01 is an example, the first two lines must e present)
cat << EOF >> /etc/openvpn/white_list
ca.cloud.int
intermediate.ca.cloud.int
eduardo.openvpn
wandelio.openvpn
EOF


cat << EOF >> /etc/openvpn/white_list
ca.cloud.int
intermediate.ca.cloud.int
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
