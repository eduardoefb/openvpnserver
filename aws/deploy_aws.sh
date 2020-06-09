#!/bin/bash

# Configure ansible:
ssh-keygen -t rsa -f id_rsa
terraform init
terraform apply

rm -f ~/.ssh/known_hosts
for n in openvpn_server caserver; do  ssh -o StrictHostKeyChecking=no ubuntu@${n} 'uname -n'; done

# Update:
cat << EOF > update.yml
- 
   name: Configure servers
   hosts: openvpn, ca
   remote_user: ubuntu
   tasks:                                                              
      - name: Update (update -y)
        become: true
        apt:
           upgrade: yes
           update_cache: yes
           cache_valid_time: 86400
EOF
ansible-playbook update.yml --private-key id_rsa

# Reboot:
ssh -i id_rsa ubuntu@openvpn.coretelinfo.net 'sudo reboot'
ssh -i id_rsa ubuntu@ca.coretelinfo.net 'sudo reboot'

# Check
ssh -i id_rsa ubuntu@openvpn.coretelinfo.net 'uname -n'
ssh -i id_rsa ubuntu@ca.coretelinfo.net 'uname -n'

## Install packages:
cat << EOF > install.yml
- 
   name: Install
   hosts: openvpn, ca
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
ansible-playbook install.yml --private-key=id_rsa

####################################################################################################################################
#     CA certificates:                                                                                                             #
####################################################################################################################################

cat << EOF > configure_ca.yml
-
   name: Configure CA
   hosts: ca
   remote_user: ubuntu
   vars:   
      ansible_python_interpreter: /usr/bin/python3
      
      domain: 'coretelinfo.net'            
      ca_subject: '/emailAddress=ca@{{domain}}/CN=ca.{{domain}}/O=ca/OU=int/L=SJK/ST=SP/C=BR'
      int_ca_subject: '/emailAddress=ca@ca.{{domain}}/CN=intermediate.ca.{{domain}}/O=ca/OU=int/L=SJK/ST=SP/C=BR'
               
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
ansible-playbook configure_ca.yml --private-key=id_rsa

cat << EOF > configure_openvpn.yml
-
   name: Configure Openvpn
   hosts: openvpn
   remote_user: ubuntu
   vars:
      ansible_python_interpreter: /usr/bin/python3
      domain: 'coretelinfo.net'
      cn: 'openvpn.{{domain}}'       
      mail: 'openvpn@{{domain}}'
      openvpn_subject: '/emailAddress={{mail}}/CN=openvpn.{{cn}}/O=ca/OU=int/L=SJK/ST=SP/C=BR'
               
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
   hosts: ca
   remote_user: ubuntu
   vars:
      ansible_python_interpreter: /usr/bin/python3
      domain: 'coretelinfo.net'
      cn: 'openvpn.{{domain}}' 
      mail: 'openvpn@{{domain}}'
      openvpn_subject: '/emailAddress={{mail}}/CN={{cn}}/O=ca/OU=int/L=SJK/ST=SP/C=BR'
                                 
   tasks:
      - name: Transfer csr to server     
        become: true
        copy:
           src: /tmp/openvpn/tmp/server.openvpn.csr
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
   hosts: openvpn
   remote_user: ubuntu
   vars:
      ansible_python_interpreter: /usr/bin/python3  
      domain: 'coretelinfo.net'
      caserver: 'ca.{{domain}}'
      vpnserver: 'openvpn.{{domain}}'             
   tasks:
      - name: Transfer crt to openvpn     
        become: true
        copy:
           src: /tmp/ca/tmp/server.openvpn.crt
           dest: /etc/openvpn/certs/server.openvpn.crt
           owner: root
           group: root
           mode: '0644'

      - name: Transfer crt to openvpn     
        become: true
        copy:
           src: /tmp/ca/root/ca/intermediate/certs/ca-chain.crt
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

#ansible-playbook configure_openvpn.yml
ansible-playbook configure_openvpn.yml --private-key=id_rsa


# Reboot after update:
rm -f ~/.ssh/known_hosts
for n in openvpn ca; do  ssh -i id_rsa -o StrictHostKeyChecking=no ubuntu@${n} 'sudo reboot'; done

# Check after reboot:
for n in openvpn ca; do  ssh -i id_rsa -o StrictHostKeyChecking=no ubuntu@${n} 'uname -n'; done

# Create cert request:
cat << EOF > request.yml
-
   name: Create and sign certificate
   hosts: ca
   remote_user: ubuntu
   vars:
      ansible_python_interpreter: /usr/bin/python3
      cn: '#CN#'
      subject: '/emailAddress={{cn}}@openvpn.net/CN={{cn}}/O=efb/OU=com/L=CBV/ST=MG/C=BR'   

   tasks:
      - name: Remove clone directory      
        become: true
        file:
           path: /root/clients
           state: absent

   tasks:
      - name: Create cert request and sign
        become: true
        shell:
           mkdir /root/clients;           
           openssl genrsa -out /root/clients/{{cn}}.key 4096;           
           touch /root/.rnd;
           openssl req -new -key /root/clients/{{cn}}.key -out /root/clients/{{cn}}.csr -subj {{subject}} -sha512;           
           openssl ca -batch -config /root/ca/intermediate/openssl.cnf -days 3650 -notext -md sha512 -in /root/clients/{{cn}}.csr -passin pass:\$(cat /root/ca/intca_pass)  -out /root/clients/{{cn}}.crt;
        
      - name: Get file from openvpn
        become: true
        fetch:
          src: /root/clients/{{cn}}.crt
          dest: /tmp/ 
          
      - name: Get file from ca
        become: true
        fetch:
          src: /root/clients/{{cn}}.key
          dest: /tmp/   

-
   name: Create and sign certificate
   hosts: openvpn
   remote_user: ubuntu
   vars:
      ansible_python_interpreter: /usr/bin/python3
      cn: '#CN#'
      subject: '/emailAddress={{cn}}@openvpn.net/CN={{cn}}/O=efb/OU=com/L=CBV/ST=MG/C=BR'   
          
   tasks:                
      - name: Get file from openvpn
        become: true
        fetch:
          src: /etc/openvpn/certs/ta.key
          dest: /tmp/                      

      - name: Get file from openvpn
        become: true
        fetch:
          src: /etc/openvpn/certs/dh4096.pem
          dest: /tmp/   

      - name: Get file from openvpn
        become: true
        fetch:
          src: /etc/openvpn/certs/ca-chain.crt
          dest: /tmp/               
          
-
   name: Add cn to the allowed
   hosts: openvpn
   remote_user: ubuntu
   vars:
      ansible_python_interpreter: /usr/bin/python3
      cn: '#CN#'
      
   tasks:   
      - name: Remove clone directory      
        become: true
        shell:
           echo {{cn}} >> /etc/openvpn/white_list;           
EOF

cn="agwtest01.trial"
sed -i "s/#CN#/${cn}/g" request.yml
ansible-playbook request.yml


# Copy files:
rm -rf /tmp/magma
mkdir /tmp/magma

cp /tmp/caserver/root/clients/${cn}.crt /tmp/magma/client.crt
cp /tmp/caserver/root/clients/${cn}.key /tmp/magma/client.key
cp /tmp/openvpn_server/etc/openvpn/certs/* /tmp/magma/

openssl x509 -in /tmp/magma/client.crt -text -noout
openssl x509 -in /tmp/magma/ca-chain.crt -text -noout

ls -lhtr /tmp/magma/



# Create docker:
su - 
cd /home/eduabati/Documents/openstack/agw_auto_install/
bash run.sh


# Check in openvpn server:
grep "MULTI: Learn:" /var/log/openvpn.log | awk '{print $10" "$12}'
grep "MULTI: Learn:" /var/log/openvpn.log | awk '{gsub("/", " ");print $11" "$13}' | sort -u

# SSH to ne:
cd /root
sed -i 's/GRUB_CMDLINE_LINUX=""/GRUB_CMDLINE_LINUX="net.ifnames=0 biosdevname=0"/g' /etc/default/grub
grub-mkconfig -o /boot/grub/grub.cfg
sed -i 's/enp1s0/eth0/g' /etc/network/interfaces
sed -i 's/ens3/eth0/g' /etc/network/interfaces
sed -i 's/enp9s0/eth0/g' /etc/network/interfaces
reboot

su -   
wget -O agw_install.sh http://out.homelinux.org:8888/agw_install.sh
bash agw_install.sh

