# Windows RDP & WinRM token

## Quick-start

First a tokened certificate must be generated. With Python and the `cryptography` module installed, run:
`./gen_cert.py` 
and provide it both the token web-bug URL, and the hostname of the system this token will be deployed on.

Then run either `.\install-rdp.ps1` or `.\install-winrm.ps1` on the host you want to deploy to (with the `.p12` and `.reg` files in the same directory) to install the RDP or WinRM tokens, respectively.

## RDP Details

This is a prototype token for Windows endpoints that, without installing any agent or software:

 * Adds a new, AIA-tokened certificate to the Windows certificate store
 * Configures the RDP service to serve that certificate to clients
 * (Optionally) disables any users from actually logging in via RDP
 * Enables the RDP service

In essence, this token reconfigures Windows to expose the RDP service and if anyone tries to connect/login to that endpoint, alerts with the client's IP address.

#### Tokened certificate

The Windows CryptoAPI will try to validate certificates, even if they are not rooted in a trusted CA. This means that the AIA flag for a certificate will cause the CryptoAPI to browse to the URL in the flag---triggering the token.

The `gen_cert.py` script generates a certificate with a self-signed CA that has the token URL as the AIA parameter. The script also outputs that certificate as a `.p12` archive with the password of "password". The certificate's fingerprint is added to the `.reg` file which upon import instructs Windows to use that certificate for RDP sessions.

#### Installer script

The `install-rdp.ps1` script installs the generated certificate (and `.reg` file), as well as disables RDP logins for all users, and finally enables the RDP service with the tokened certificate as the served certificate.

It must be run as an Administrator.

#### Important caveats
1. If the endpoint is a Hyper-V VM, enhanced sessions will no longer work as they use RDP under the hood. Only basic sessions will continue to operate.
2. If there are additional users added after the token is installed, they will be able to RDP in, which could open up risks.
3. **TO EXPLORE:** It may be possible that an AD-joined endpoint would allow users that have AD permissions but have not logged in prior to token installation would be able to login, adding additional risks.

## WinRM details

This is a prototype token for Windows endpoints that, without installing any agent or software:

 * Adds a new, AIA-tokened certificate to the Windows certificate store (and temporarily adds a non-trusted root CA cert for the AIA-tokened cert)
 * Configures the WinRM service to serve that certificate to clients
 * Disables any users from actually logging in via WinRM
 * Enables the WinRM HTTPS service

In essence, this token reconfigures Windows to expose the WinRM (HTTPS) service and if anyone tries to connect/login to that endpoint, alerts with the client's IP address.

#### Tokened certificate

The Windows CryptoAPI will try to validate certificates, even if they are not rooted in a trusted CA. This means that the AIA flag for a certificate will cause the CryptoAPI to browse to the URL in the flag---triggering the token.

The `gen_cert.py` script generates a certificate with a self-signed CA that has the token URL as the AIA parameter (`token.p12` and `root.p12`). The script also outputs that certificate as a `.p12` archive with the password of "password". The fingerprint of this certificate is embedded into `token.reg` which is used to configure the OS to serve that certificate.

#### Installer script

The `install-winrm.ps1` script installs the generated certificate, as well as disables WinRM logins for all users, and finally enables the HTTPS WinRM service with the tokened certificate as the served certificate.

It must be run as an Administrator.

#### Important caveats
1. The SDDL permissions will deny any future modification or visiblity into the WinRM subsystem. To remove the SDDL to alter WinRM, delete the following Registry key: `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\WSMAN\Service\rootSDDL`.
