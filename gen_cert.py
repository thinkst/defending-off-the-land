#!/usr/bin/env python3
# Script to generate tokened certificate for RDP token
# (C) 2024 Thinkst Applied Research, PTY
# Author: Jacob Torrey

from typing import Optional
import crypto_helper, sys

REG_TEMPLATE = """Windows Registry Editor Version 5.00

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp]
"SSLCertificateSHA1Hash"=hex:{thumbprint}
"""

def generate_bundle(token_url : str, name : str = 'Microsoft Windows', filename : str = 'token.p12', reg_filename : str = 'token.reg') -> Optional[str]:
    '''
    Generates a certificate with the token_url set as the CRL URL
    Returns: Filename for .p12 certificate and private key
    '''
    (key, cert) = crypto_helper.generate_cert(token_url, computer_name=name)
    digest = crypto_helper.get_digest(cert)
    generate_reg_file(digest, reg_filename)
    crypto_helper.export_p12(key, cert, filename)


def generate_reg_file(digest : str, filename):
    '''
    Generates a .reg file for a certificate
    Returns: Filename for .reg file to import
    '''
    encoded_dgt = ','.join([digest[i:i+2] for i in range(0, len(digest), 2)])
    reg = REG_TEMPLATE.format(thumbprint=encoded_dgt)
    with open(filename, 'w') as fp:
        fp.write(reg)

if __name__ == '__main__':
    print("This script will generate a tokened certificate for use in the RDP token")
    token_url = str(input("Please enter the URL for the token: "))
    if token_url == '':
        print("A token URL is required.")
        sys.exit()
    cname = str(input("Please provide the computer name that will be tokened (or nothing to use the default): "))
    if cname == '':
        cname = 'Microsoft Windows'
    print(f"Generating a certificate (token.p12 & token.reg) for {cname} that is tokened to point to {token_url}")
    generate_bundle(token_url=token_url, name=cname)
