# Helper functions for X.509 operations
# (C) 2024 Thinkst Applied Research, PTY
# Author: Jacob Torrey

import datetime
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import BestAvailableEncryption, pkcs12
from cryptography.x509.oid import NameOID
from cryptography import x509

CERT_VALID_YEARS = 10
KEY_USAGE = {
    'digital_signature': True,
    'content_commitment': False,
    'key_encipherment': True,
    'data_encipherment': False,
    'key_agreement': False,
    'key_cert_sign': True,
    'crl_sign': True,
    'encipher_only': False,
    'decipher_only': False
}

def get_digest(cert : x509.Certificate) -> str:
    '''
    Returns the hex thumb/fingerprint of the cert as a string
    '''
    return cert.fingerprint(hashes.SHA1()).hex()

def export_p12(key : rsa.RSAPrivateKey, cert : x509.Certificate, filename : str = 'cert.p12'):
    with open(filename, 'wb') as fp:
        fp.write(pkcs12.serialize_key_and_certificates(b'tokencert', key, cert, None, BestAvailableEncryption(b'password')))

def generate_cert(token_url : str, org_name : str = 'Thinkst', computer_name : str = 'Microsoft Windows') -> tuple[rsa.RSAPrivateKey, x509.Certificate]:
    '''
    Generates a tokened key and certificate with token_url as the CRL distribution point
    '''
    token_cert_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    root_key, root_cert = _generate_root_ca(org_name=org_name)

    # Export the root CA for possible use on trusted clients to silence the AIA fetch
    export_p12(root_key, root_cert, 'root.p12')
    
    subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, 'US'),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, 'California'),
        x509.NameAttribute(NameOID.LOCALITY_NAME, 'San Francisco'),
        x509.NameAttribute(NameOID.COMMON_NAME, computer_name)
    ])

    token_cert : x509.Certificate = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(token_cert_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.now(datetime.timezone.utc))
        .not_valid_after(datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=365 * CERT_VALID_YEARS))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.KeyUsage(**KEY_USAGE), critical=True)
        #.add_extension(_generate_crl(token_url), critical=True) # CRL doesn't seem to fire
        .add_extension(_generate_aia(token_url), critical=True)
        .add_extension(x509.ExtendedKeyUsage([x509.ExtendedKeyUsageOID.CLIENT_AUTH, x509.ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(token_cert_key.public_key()), critical=False)
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(root_cert.extensions.get_extension_for_class(x509.SubjectKeyIdentifier).value), critical=False)
        .sign(root_key, hashes.SHA256())
    )

    return (token_cert_key, token_cert)

def _generate_crl(token_url : str) -> x509.CRLDistributionPoints:
    '''
    Generates a CRLDistrubtionPoints object pointing to the token_url
    '''
    entry = x509.DistributionPoint(full_name=[x509.UniformResourceIdentifier(token_url)], relative_name=None, reasons=None, crl_issuer=None)
    return x509.CRLDistributionPoints([entry])

def _generate_aia(token_url : str) -> x509.AuthorityInformationAccess:
    '''
    Generates an AIA extension pointing to the token_url
    '''
    am = x509.OID_CA_ISSUERS
    al = x509.UniformResourceIdentifier(token_url)
    aia = x509.AccessDescription(am, al)
    return x509.AuthorityInformationAccess([aia])

def _generate_root_ca(org_name : str) -> tuple[rsa.RSAPrivateKey, x509.Certificate]:
    '''
    Generates a root CA to sign the leaf cert with
    Returns a tuple (root_key, root_cert)
    '''
    root_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, 'ZA'),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, 'Western Cape'),
        x509.NameAttribute(NameOID.LOCALITY_NAME, 'Cape town'),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, org_name),
        x509.NameAttribute(NameOID.COMMON_NAME, org_name + ' Root CA')
    ])

    root_cert : x509.Certificate = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(root_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.now(datetime.timezone.utc))
        .not_valid_after(datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=365 * CERT_VALID_YEARS))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(x509.KeyUsage(**KEY_USAGE), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(root_key.public_key()), critical=False)
        .sign(root_key, hashes.SHA256())
    )
    
    return (root_key, root_cert)
