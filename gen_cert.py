# Script to generate tokened certificate for RDP token
# (C) 2024 Thinkst Applied Research, PTY
# Author: Jacob Torrey

from typing import Optional

REG_TEMPLATE = f"""
Windows Registry Editor Version 5.00

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp]
"SSLCertificateSHA1Hash"=hex:{hex}
"""

def generate_certificate(token_url : str, name : str = 'Microsoft Windows') -> Optional[str]:
    '''
    Generates a certificate with the token_url set as the CRL URL
    Returns: Filename for .p12 certificate and private key
    '''
    pass

def generate_reg_file(cert_file : str) -> Optional[str]:
    '''
    Generates a .reg file for a certificate
    Returns: Filename for .reg file to import
    '''
    pass