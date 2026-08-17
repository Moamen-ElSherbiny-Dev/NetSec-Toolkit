# Port -> Service Mapping

services = {
    # Web Services
    80: "HTTP",
    443: "HTTPS",
    8080: "HTTP Proxy",
    8443: "HTTPS Alternate",

    # Email Services
    25: "SMTP",
    587: "SMTP",
    465: "SMTPS",

    # Email Receiving
    109: "POP2",
    110: "POP3",
    995: "POP3S",

    # Email Sync
    143: "IMAP",
    220: "IMAP3",
    993: "IMAPS",

    # Remote Access
    22: "SSH",
    23: "TELNET",
    3389: "RDP",

    # File Transfer
    20: "FTP-DATA",
    21: "FTP",
    69: "TFTP",

    # Database Services
    3306: "MySQL",
    5432: "PostgreSQL",
    1521: "Oracle DB",
    1433: "MSSQL",

    # Gaming / Real-time Services
    27015: "Steam",
    7777: "Unreal Engine Servers",
    25565: "Minecraft",

    # Network Utilities Services
    53: "DNS",
    67: "DHCP Server",
    68: "DHCP Client",
    123: "NTP",
    161: "SNMP",

    # Enterprise Auth
    1812: "RADIUS Authentication",
    1813: "RADIUS Accounting",

    # VPN & Security Services
    1194: "OpenVPN",
    1701: "L2TP",
    1723: "PPTP",
    
    # Windows / File Sharing
    135: "RPC",
    139: "NetBIOS",
    445: "SMB",
    2049: "NFS",
}