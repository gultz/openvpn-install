

# OpenVPN Installer for Amazon Linux 2 and Amazon Linux 2023

## Problem Description

The script needs modification to include support for the Amazon Linux 2023 configuration. Without this update, users cannot utilize the script with the latest Amazon Linux settings.

## Proposed Solution

Update the script to recognize and handle the Amazon Linux 2023 configuration properly. Since Amazon Linux 2023 is based on Fedora 34, 35, and 36, modify the script to install OpenVPN from the corresponding Fedora packages. I have verified that OpenVPN works correctly when installed from these Fedora packages on Amazon Linux 2023. Additionally, since Amazon Linux 2023 does not support Extra Packages for Enterprise Linux (EPEL), the repository needs to be added manually.

## Relationship to Fedora

For more information on the relationship between Amazon Linux 2023 and Fedora, refer to the following documentation:

- [Relationship to Fedora](https://docs.aws.amazon.com/linux/al2023/ug/relationship-to-fedora.html)
- [Comparison with Amazon Linux 2](https://docs.aws.amazon.com/linux/al2023/ug/compare-with-al2.html)

## Linux Distribution and Version

- **Amazon Linux 2023**

## OpenVPN Version

- **2.56**

## Compatibility

The script supports the following Linux distributions:

- **Amazon Linux 2023**
- **Amazon Linux 2**


## Changes 

- Support Amazon Linux 2023
- dulpicate cn -> Added the duplicate-cn option. This will allow multiple clients using the same certificate or username to connect concurrently
- Local DNS -> Using Local DNS not public known DNS (8.8.8.8)
- enable Linux User certificate
- split tunneling
- Use IMVDBSv2
  

## Usage

Before using the script, ensure the **Source/Destination Check** is disabled when configuring NAT.

```bash
git clone https://github.com/gultz/openvpn-install.git
sudo -s
chmod +x amazon_openvpn_v2.sh
./amazon_openvpn_v2.sh
```

--- 

