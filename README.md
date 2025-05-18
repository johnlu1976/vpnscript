# v2rayWizard.sh

## Overview

**V2RayWizard.sh** is a powerful and user-friendly bash script designed to simplify the installation, configuration, and management of V2Ray with WebSocket (ws) and TLS support. It provides a one-key solution for setting up V2Ray on Linux systems, making it ideal for both beginners and advanced users.

This script is part of the **vpnscript** repository hosted at [https://github.com/johnlu1976/vpnscript](https://github.com/johnlu1976/vpnscript).

## Features

- **One-Key Installation**: Quickly install V2Ray with WebSocket and TLS or HTTP/2 support.
- **Automatic Configuration**: Configure UUID, ports, camouflage paths, and TLS settings with ease.
- **Nginx Integration**: Automatically install and configure Nginx for reverse proxy and TLS.
- **SSL Certificate Management**: Generate and manage SSL certificates using Let's Encrypt.
- **System Optimization**: Includes basic system optimizations for better performance.
- **Log Monitoring**: View real-time access and error logs for troubleshooting.
- **Customizable Settings**: Easily modify UUID, ports, TLS versions, and camouflage paths.
- **Uninstallation**: Cleanly remove V2Ray, Nginx, and related configurations.
- **Cron Job Support**: Automatically update SSL certificates with scheduled tasks.

## Supported Systems

- **Debian**: Version 9 and above  
- **Ubuntu**: Version 18.04 and above  
- **CentOS**: Version 7 and above  

## Prerequisites

Before running the script, ensure the following:
- You have root access to the server.
- Your domain name is properly configured with A/AAAA records pointing to your server's IP address.

## Installation

1. Clone the repository:
    ```bash
    git clone https://github.com/johnlu1976/vpnscript.git
    cd vpnscript
    ```

2. Make the script executable:
    ```bash
    chmod +x V2RayWizard.sh
    ```

3. Run the script:
    ```bash
    ./V2RayWizard.sh
    ```

## Usage

After running the script, you will be presented with a menu to choose various options:

### Installation Options:
- Install V2Ray with WebSocket and TLS
- Install V2Ray with HTTP/2

### Configuration Options:
- Change UUID
- Change port
- Change TLS version
- Change camouflage path

### Information and Logs:
- View real-time access logs
- View real-time error logs
- View V2Ray configuration details

### Other Options:
- Install BBR acceleration
- Update SSL certificates
- Uninstall V2Ray and related components
- Clear residual certificate files

## Example Workflow

1. Install V2Ray with WebSocket and TLS.
2. Configure your domain and SSL certificates.
3. Modify UUID, ports, or camouflage paths as needed.
4. Monitor logs to ensure everything is working correctly.

## Uninstallation

To completely remove V2Ray and related components:
1. Run the script and select the **Uninstall** option from the menu.
2. Optionally, delete SSL certificates and residual files.

## Troubleshooting

- Ensure your domain's DNS records are correctly configured.
- Check logs for errors using the menu options.
- Verify that ports are not blocked by firewalls.

## License

This script is open-source and distributed under the **MIT License**. Feel free to modify and use it as needed.

## Credits

- **Original Author**: [wulabing](https://github.com/wulabing)  
- **Repository Maintainer**: [johnlu1976](https://github.com/johnlu1976)  
- **Documentation**: Based on the official V2Ray documentation: [www.v2ray.com](https://www.v2ray.com)

## Disclaimer

This script is provided as-is. Use it at your own risk. The original author and maintainer are not responsible for any issues or damages caused by using this script.
