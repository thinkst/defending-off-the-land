# Unconstrained Kerberos Delegation Decoy

**NB: It’s important to treat the Ghost Server machine account as any other Domain Admin or DC account. Monitor it for changes, and ensure when any organizational changes are made to AD that the account ownership doesn’t get inherited by other OUs or groups.**

This script creates a AD machine object that supports Unconstrained Delegation (with Kerberos) and sets the DNS and SPN records for a domain-joined honeypot. :
- Create a Ghost Server AD object (though we suggest not naming it Ghost Server 😛) named $GhostServerName
- Configure the Ghost Server’s AD object to support Unconstrained Delegation and restrict its ACLs to writable only by Domain Admins (same permissions as the DC machine object)
- Point the Ghost Server’s DNS at an IP or machine (CNAME) of your choosing (i.e., the domain-joined honeypot–we recommend Canary 👍)
- Add SPN records for the Ghost Server and associated network services to the machine account of the honeypot

## Installer script

Run `New-KerberosDelegationCanary` as domain administrator passing the following arguments:
- `-GhostServerName` - The machine name for the newly-created AD computer object
- `-GhostServerDomain` - The domain it should be created under
- `-CanaryName` - The machine name of the domain-joined honeypot/decoy/Canary
- `-CanaryIP` - The IP address of the domain-joined honeypot/decoy/Canary

