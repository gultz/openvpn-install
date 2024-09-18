# OpenVPN installer for Amazon Linux2, Amazon linux 2023

Compatibility

The script supports these Linux distributions:



support

amazon-linux-2023

✅      

amazon-linux-2

✅      

특이사항

amazon linux 2023은 현재 epel을 지원하지 않음. 따라서 amazon linux 2023에서 epel을 통해 openvpn을 받아 올 수 없으며, 다른 저장소를 임의적으로 추가하여 openvpn을 설치해야함.

amazon linux 2023은 fedora 34,35,36 기반으로 만들어져있음으로 fedora 저장소를 추가하고 그쪽에서 openvpn을 설치하여 dependency 문제를 해결.


Usage


소스 대상 확인 중지 필수 (NAT)

기존의 openvpn과 모든 기능 동일

vpc range를 꼭 적어줘야하며, default 10.0.0.0 255.255.0.0


amazon

wget https://media.cloud.nongshim.co.kr/ndsutils/openvpn/amazon_openvpn_v2.sh
sudo -s
chmod +x amazon_openvpn_v2.sh
./amazon_openvpn_v2.sh

vpc대역대 입력 ex 172.30.0.0 255.255.0.0 

