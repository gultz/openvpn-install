#! /bin/bash
function isRoot() {
	if [ "$EUID" -ne 0 ]; then
		return 1
	fi
}

function tunAvailable() {
	if [ ! -e /dev/net/tun ]; then
		return 1
	fi
}

function initialCheck() {
	if ! isRoot; then
		echo "you need to run this as root"
		exit 1
	fi
	if ! tunAvailable; then
		echo "TUN is not available"
		exit 1
	fi
}

function checkOS(){
    if [[ -e /etc/system-release ]]; then
        source /etc/os-release
        if [[ $ID == "amzn" ]]; then
			OS="amzn"
			if [[ $VERSION_ID != "2" ]]; then
				echo "⚠️ Your version of Amazon Linux is not supported."
				echo ""
				echo "However, if you're using Amazon Linux >= 2023 or beta, then you can continue"
				echo ""
			fi
		fi
    fi
}

function installOpenVPN() {
    PORT=1194
    PROTOCOL="udp"
    CIPHER="AES-128-GCM"
	CERT_CURVE="prime256v1"
	CC_CIPHER="TLS-ECDHE-ECDSA-WITH-AES-128-GCM-SHA256"
	DH_CURVE="prime256v1"
	HMAC_ALG="SHA256"

    #PUBLIC IP by IMDSv2 aws
	TOKEN=`curl -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 21600"`
	PUBLIC_IP=$(curl -H "X-aws-ec2-metadata-token: $TOKEN" -v http://169.254.169.254/latest/meta-data/public-ipv4)

    ENDPOINT=${ENDPOINT:-$PUBLIC_IP}

    # Get the "public" interface from the default route
	NIC=$(ip -4 route ls | grep default | grep -Po '(?<=dev )(\S+)' | head -1)


    # $NIC can not be empty for script rm-openvpn-rules.sh
	if [[ -z $NIC ]]; then
		echo
		echo "Can not detect public interface."
		echo "This needs for setup MASQUERADE."
		until [[ $CONTINUE =~ (y|n) ]]; do
			read -rp "Continue? [y/n]: " -e CONTINUE
		done
		if [[ $CONTINUE == "n" ]]; then
			exit 1
		fi
	fi

    ##Install Openvpn
    if [[ ! -e /etc/openvpn/server.conf ]]; then
        if [[ $VERSION_ID == "2023" ]]; then
				# Add Fedora 36 repository because Amazon Linux 2023 is based on Fedora 34, 35, 36
				sudo tee /etc/yum.repos.d/fedora.repo <<EOF
[fedora]
name=Fedora 36 - $basearch
baseurl=https://archives.fedoraproject.org/pub/archive/fedora/linux/releases/36/Everything/\$basearch/os/
enabled=1
metadata_expire=7d
gpgcheck=1
gpgkey=https://getfedora.org/static/fedora.gpg
       https://src.fedoraproject.org/rpms/fedora-repos/raw/f36/f/RPM-GPG-KEY-fedora-36-primary
skip_if_unavailable=False
EOF
        yum install -y iptables openssl wget ca-certificates
    	yum install -y openvpn pkcs11-helper --enablerepo=fedora
			else
				amazon-linux-extras install -y epel
				yum install -y openvpn iptables openssl wget ca-certificates curl
			fi
        # An old version of easy-rsa was available by default in some openvpn packages
        if [[ -d /etc/openvpn/easy-rsa/ ]]; then
			rm -rf /etc/openvpn/easy-rsa/
		fi
    fi

    # Find out if the machine uses nogroup or nobody for the permissionless group
    if grep -qs "^nogroup:" /etc/group; then
		NOGROUP=nogroup
	else
		NOGROUP=nobody
	fi

    # Install the latest version x`x`of easy-rsa from source, if not already installed.
	if [[ ! -d /etc/openvpn/easy-rsa/ ]]; then
        local version="3.1.2"
        wget -O ~/easy-rsa.tgz https://github.com/OpenVPN/easy-rsa/releases/download/v${version}/EasyRSA-${version}.tgz
		mkdir -p /etc/openvpn/easy-rsa
		tar xzf ~/easy-rsa.tgz --strip-components=1 --no-same-owner --directory /etc/openvpn/easy-rsa
		rm -f ~/easy-rsa.tgz

        cd /etc/openvpn/easy-rsa/ || return

        #CERT CURVE
        echo "set_var EASYRSA_ALGO ec" >vars
		echo "set_var EASYRSA_CURVE $CERT_CURVE" >>vars

        # Generate a random, alphanumeric identifier of 16 characters for CN and one for server name
		SERVER_CN="cn_$(head /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 16 | head -n 1)"
		echo "$SERVER_CN" >SERVER_CN_GENERATED
		SERVER_NAME="server_$(head /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 16 | head -n 1)"
		echo "$SERVER_NAME" >SERVER_NAME_GENERATED

        # Create the PKI, set up the CA, the DH params and the server certificate
        ./easyrsa init-pki
        EASYRSA_CA_EXPIRE=3650 ./easyrsa --batch --req-cn="$SERVER_CN" build-ca nopass
        EASYRSA_CERT_EXPIRE=3650 ./easyrsa --batch build-server-full "$SERVER_NAME" nopass
        EASYRSA_CRL_DAYS=3650 ./easyrsa gen-crl

        #generate tls-crypt key
        openvpn --genkey --secret /etc/openvpn/tls-crypt.key
    else
        #if easy-rsa is already installed. grab the generated SERVER_NAME

        cd etc/openvpn/easy-rsa/ || return
        SERVER_NAME=$(cat SERVER_NAME_GENERATED)
    fi

    # Move all the generated files
	cp pki/ca.crt pki/private/ca.key "pki/issued/$SERVER_NAME.crt" "pki/private/$SERVER_NAME.key" /etc/openvpn/easy-rsa/pki/crl.pem /etc/openvpn

    chmod 644 /etc/openvpn/crl.pem

    #generate server.conf
    echo "port $PORT" >/etc/openvpn/server.conf
    echo "proto $PROTOCOL" >>/etc/openvpn/server.conf


	#For Amazon Linux 2023, create /etc/systemd/system/openvpn@.service.
	if [[ $OS == 'amzn'&& $VERSION_ID == "2023" ]]; then
		echo "[Unit]
Description=OpenVPN Robust And Highly Flexible Tunneling Application On %I
After=network.target
[Service]
Type=notify
PrivateTmp=true
ExecStart=/usr/sbin/openvpn --cd /etc/openvpn/ --config %i.conf
[Install]
WantedBy=multi-user.target" >/usr/lib/systemd/system/openvpn@.service
sudo systemctl daemon-reload
fi

	#Enable split tunneling

	until [[ -n "$VPC_RANGE" ]]; do
		read -rp "type AWS_VPC_RANGE ex) 10.0.0.0 255.255.0.0 : " -e -i "10.0.0.0 255.255.0.0" VPC_RANGE
	done

	echo -e "push \"route $VPC_RANGE\"" >> /etc/openvpn/server.conf

    echo "dev tun
user nobody
group $NOGROUP
persist-key
persist-tun
keepalive 10 120
topology subnet
server 10.8.0.0 255.255.255.0
ifconfig-pool-persist ipp.txt" >>/etc/openvpn/server.conf


	#echo 'push "redirect-gateway def bypass-dhcp"' >>/etc/openvpn/server.conf

	#Use AWS DNS not local dns server
	IFS='.' read -r -a ip_array <<< "$VPC_RANGE"
	ip_array[3]=2
	NEW_IP="${ip_array[0]}.${ip_array[1]}.${ip_array[2]}.${ip_array[3]}"
	echo "push \"dhcp-option DNS $NEW_IP\"" >> /etc/openvpn/server.conf

	echo "dh none" >>/etc/openvpn/server.conf
	echo "ecdh-curve $DH_CURVE" >>/etc/openvpn/server.conf
	echo "tls-crypt tls-crypt.key" >>/etc/openvpn/server.conf

	echo "crl-verify crl.pem
ca ca.crt
cert $SERVER_NAME.crt
key $SERVER_NAME.key
auth $HMAC_ALG
cipher $CIPHER
ncp-ciphers $CIPHER
tls-server
tls-version-min 1.2
tls-cipher $CC_CIPHER
client-config-dir /etc/openvpn/ccd
status /var/log/openvpn/status.log
verb 3" >>/etc/openvpn/server.conf

#user/pass 를 이용한 인증에는 추가 필요 - START
echo "plugin /usr/lib64/openvpn/plugins/openvpn-plugin-auth-pam.so openvpn" >> /etc/openvpn/server.conf
echo "auth    required        pam_unix.so    shadow    nodelay" > /etc/pam.d/openvpn
echo "auth    requisite       pam_succeed_if.so uid >= 500 quiet" >> /etc/pam.d/openvpn
echo "auth    requisite       pam_succeed_if.so user ingroup vpnuser quiet" >> /etc/pam.d/openvpn
echo "account required        pam_unix.so" >> /etc/pam.d/openvpn

	# Create client-config-dir dir
	mkdir -p /etc/openvpn/ccd
	# Create log dir
	mkdir -p /var/log/openvpn
	# Enable routing
	echo 'net.ipv4.ip_forward=1' >/etc/sysctl.d/99-openvpn.conf
	# Apply sysctl rules
	sysctl --system

	# Finally, restart and enable OpenVPN
	# Don't modify package-provided service
	cp /lib/systemd/system/openvpn\@.service /etc/systemd/system/openvpn\@.service

	# Workaround to fix OpenVPN service on OpenVZ
	sed -i 's|LimitNPROC|#LimitNPROC|' /etc/systemd/system/openvpn\@.service
	# Another workaround to keep using /etc/openvpn/
	sed -i 's|/etc/openvpn/server|/etc/openvpn|' /etc/systemd/system/openvpn\@.service

	systemctl daemon-reload
	systemctl enable openvpn@server
	systemctl restart openvpn@server

	# Add iptables rules in two scripts
	mkdir -p /etc/iptables
	echo "#!/bin/sh

iptables -t nat -A POSTROUTING -o $NIC -j MASQUERADE
iptables -I FORWARD 1 -i $NIC -o tun0 -j ACCEPT
iptables -I FORWARD 1 -i tun0 -o $NIC -j ACCEPT
iptables -I INPUT 1 -i $NIC -p $PROTOCOL --dport $PORT -j ACCEPT" >/etc/iptables/add-openvpn-rules.sh

	# Script to remove rules
	echo "#!/bin/sh
iptables -t nat -D POSTROUTING -o $NIC -j MASQUERADE
iptables -D FORWARD -i $NIC -o tun0 -j ACCEPT
iptables -D FORWARD -i tun0 -o $NIC -j ACCEPT
iptables -D INPUT -i $NIC -p $PROTOCOL --dport $PORT -j ACCEPT" >/etc/iptables/rm-openvpn-rules.sh

chmod +x /etc/iptables/add-openvpn-rules.sh
chmod +x /etc/iptables/rm-openvpn-rules.sh

# Handle the rules via a systemd script
	echo "[Unit]
Description=iptables rules for OpenVPN
Before=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=/etc/iptables/add-openvpn-rules.sh
ExecStop=/etc/iptables/rm-openvpn-rules.sh
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target" >/etc/systemd/system/iptables-openvpn.service

# Enable service and apply rules
	systemctl daemon-reload
	systemctl enable iptables-openvpn
	systemctl start iptables-openvpn

	# If the server is behind a NAT, use the correct IP address for the clients to connect to
	if [[ $ENDPOINT != "" ]]; then
		IP=$ENDPOINT
	fi
		# client-template.txt is created so we have a template to add further users later
		echo "client" >/etc/openvpn/client-template.txt
	if [[ $PROTOCOL == 'udp' ]]; then
		echo "proto udp" >>/etc/openvpn/client-template.txt
		echo "explicit-exit-notify" >>/etc/openvpn/client-template.txt
	fi

	echo "remote $IP $PORT
dev tun
resolv-retry infinite
nobind
persist-key
persist-tun
remote-cert-tls server
verify-x509-name $SERVER_NAME name
auth $HMAC_ALG
auth-nocache
cipher $CIPHER
tls-client
tls-version-min 1.2
tls-cipher $CC_CIPHER
ignore-unknown-option block-outside-dns
setenv opt block-outside-dns # Prevent Windows 10 DNS leak
verb 3" >>/etc/openvpn/client-template.txt


    #Generate client

    echo ""
	echo "Tell me a name for the client."
	echo "The name must consist of alphanumeric character. It may also include an underscore or a dash."

    

	until [[ $CLIENT =~ ^[a-zA-Z0-9._-]+$ ]]; do
		read -rp "Client name: " -e -i ndsvpn CLIENT
	done

    groupadd vpnuser
	GROUP=ec2-user
    OWNER=ec2-user

    USER_COUNT=2
    USERS[0]=$CLIENT
    USERS[1]=vertexid


    for (( i=0; i<$USER_COUNT; i++ )); do
        # add user
        useradd -g vpnuser -d /home/vpnuser/ -s /sbin/nologin "${USERS[$i]}"

        # create random password
        PASSWORDS[$i]=$(tr -dc 'a-zA-Z0-9' < /dev/urandom | fold -w 10 | head -n 1)

        # set password
        echo ${PASSWORDS[$i]} | passwd ${USERS[$i]} --stdin
    done

    for (( i=0 ; i<$USER_COUNT ; i++ )) do
        echo 'ovpn user info || id: '${USERS[$i]}' pw: '${PASSWORDS[$i]}
    done


    EASYRSA_CERT_EXPIRE=3650 ./easyrsa --batch build-client-full "$CLIENT" nopass


    # Home directory of the user, where the client configuration will be written
	if [ -e /home/${CLIENT} ]; then
		# if $1 is a user name
		homeDir="/home/${CLIENT}"
	elif [ "${SUDO_USER}" ]; then
		# if not, use SUDO_USER
		if [ "${SUDO_USER}" == "root" ]; then
			# If running sudo as root
			homeDir="/root"
		else
			homeDir="/home/${SUDO_USER}"
		fi
	else
		# if not SUDO_USER, use /root
		homeDir="/root"
	fi


	# Generates the custom client.ovpn
	cp /etc/openvpn/client-template.txt "$homeDir/$CLIENT.ovpn"
	{
		echo "<ca>"
		cat "/etc/openvpn/easy-rsa/pki/ca.crt"
		echo "</ca>"

		echo "<cert>"
		awk '/BEGIN/,/END CERTIFICATE/' "/etc/openvpn/easy-rsa/pki/issued/$CLIENT.crt"
		echo "</cert>"

		echo "<key>"
		cat "/etc/openvpn/easy-rsa/pki/private/$CLIENT.key"
		echo "</key>"


		echo "<tls-crypt>"
		cat /etc/openvpn/tls-crypt.key
		echo "</tls-crypt>"

		echo "remote-cert-tls server"
		echo "auth-nocache"
		echo "auth-user-pass"
		echo "reneg-sec 84600"

	}>>"$homeDir/$CLIENT.ovpn"

	chown $OWNER:$GROUP $homeDir/$CLIENT.ovpn

	echo ""
	echo "The configuration file has been written to $homeDir/$CLIENT.ovpn."
	echo "Download the .ovpn file and import it in your OpenVPN client."
	exit 0
}

function newClient() {
	echo ""
	echo "Tell me a name for the client."
	echo "The name must consist of alphanumeric character. It may also include an underscore or a dash."

	until [[ $CLIENT =~ ^[a-zA-Z0-9._-]+$ ]]; do
		read -rp "Client name: " -e -i ndsvpn CLIENT
	done

	# 사용자 존재 여부 확인
	if [[ $(id "$CLIENT" 2>/dev/null) ]]; then
    	echo "User $CLIENT exists."
		exit 0
	else
		useradd -g vpnuser -d /home/vpnuser/ -s /sbin/nologin "${CLIENT}"
		PASSWORDS=$(tr -dc 'a-zA-Z0-9' < /dev/urandom | fold -w 10 | head -n 1)
		echo ${PASSWORDS} | passwd ${CLIENT} --stdin
		echo 'ovpn user info || id: '${CLIENT}' pw: '${PASSWORDS}

		echo "Client $CLIENT added."
		echo "If you want to add more clients, you simply need to run this script another time!"
	fi
}

function revokeClient() {
	echo ""
	echo "Tell me a name for the client."
	echo "The name must consist of alphanumeric character. It may also include an underscore or a dash."

	until [[ $CLIENT =~ ^[a-zA-Z0-9._-]+$ ]]; do
		read -rp "Client name: " -e -i ndsvpn CLIENT
	done

	if [[ $(id "$CLIENT" 2>/dev/null) ]]; then
		userdel "$CLIENT"
    	echo "User $CLIENT has been deleted."
	else
		echo "$CLIENT not exists"
		exit 0
	fi
}


function removeOpenVPN() {
	echo ""
	read -rp "Do you really want to remove OpenVPN? [y/n]: " -e -i n REMOVE
	if [[ $REMOVE == 'y' ]]; then
		# Get OpenVPN port from the configuration
		PORT=$(grep '^port ' /etc/openvpn/server.conf | cut -d " " -f 2)
		PROTOCOL=$(grep '^proto ' /etc/openvpn/server.conf | cut -d " " -f 2)

		# remove linux user in vpnuser group
		group_info=$(getent group vpnuser)
		group_id=$(echo "$group_info" | cut -d: -f3)
		users=$(getent passwd | awk -F: -v gid="$group_id" '$4 == gid {print $1}')

		for user in $users; do
    		echo "delete User: $user"
			userdel $user
		done

		groupdel vpnuser
		rm -rf /home/vpnuser


		# Stop OpenVPN

			systemctl disable openvpn@server
			systemctl stop openvpn@server
			# Remove customised service
			rm /etc/systemd/system/openvpn\@.service

		# Remove the iptables rules related to the script
		systemctl stop iptables-openvpn
		# Cleanup
		systemctl disable iptables-openvpn
		rm /etc/systemd/system/iptables-openvpn.service
		systemctl daemon-reload
		rm /etc/iptables/add-openvpn-rules.sh
		rm /etc/iptables/rm-openvpn-rules.sh

		yum remove -y openvpn

		# Cleanup
		find /home/ -maxdepth 2 -name "*.ovpn" -delete
		find /root/ -maxdepth 1 -name "*.ovpn" -delete
		rm -rf /etc/openvpn
		rm -rf /usr/share/doc/openvpn*
		rm -f /etc/sysctl.d/99-openvpn.conf
		rm -rf /var/log/openvpn

		echo ""
		echo "OpenVPN removed!"
	else
		echo ""
		echo "Removal aborted!"
	fi
}

function manageMenu() {
	echo "Welcome to OpenVPN-install!"
	echo ""
	echo "It looks like OpenVPN is already installed."
	echo ""
	echo "What do you want to do?"
	echo "   1) Add a new user"
	echo "   2) Revoke existing user"
	echo "   3) Remove OpenVPN"
	echo "   4) Exit"
	until [[ $MENU_OPTION =~ ^[1-4]$ ]]; do
		read -rp "Select an option [1-4]: " MENU_OPTION
	done

	case $MENU_OPTION in
	1)
		newClient
		;;
	2)
		revokeClient
		;;
	3)
		removeOpenVPN
		;;
	4)
		exit 0
		;;
	esac
}

# Check for root, TUN, OS...
initialCheck
checkOS

# Check if OpenVPN is already installed
if [[ -e /etc/openvpn/server.conf ]]; then
	manageMenu
else
	installOpenVPN
fi
