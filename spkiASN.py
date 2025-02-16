import os
# import random
import datetime
import argparse
from pyasn1.type import univ, namedtype, char, useful
from pyasn1.codec.der import encoder
import subprocess
import base64


# Define ASN.1 structures for SPKI Certificates

class Validity(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('notBefore', useful.UTCTime()),
        namedtype.NamedType('notAfter', useful.UTCTime())
    )
    
class AlgorithmIdentifier(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('algorithm', univ.ObjectIdentifier()),
        namedtype.OptionalNamedType('parameters', univ.Any())
    )

class PublicKeyInfo(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('algorithm', AlgorithmIdentifier()),
        namedtype.NamedType('key', univ.BitString())
    )    

class Signature(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('algorithm', AlgorithmIdentifier()),
        namedtype.NamedType('signatureValue', univ.BitString())
    )

class NameCertificate(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('version', univ.Integer()),
        namedtype.NamedType('issuer', char.PrintableString()),
        namedtype.NamedType('identifier', char.PrintableString()),
        namedtype.NamedType('subject', char.PrintableString()),
        namedtype.NamedType('validity', Validity()),
        namedtype.NamedType('publicKey', PublicKeyInfo()),
        namedtype.NamedType('signature', Signature())
    )

class AuthorizationCertificate(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('version', univ.Integer()),
        namedtype.NamedType('issuer', char.PrintableString()),
        namedtype.NamedType('identifier', char.PrintableString()), # called "tag"
        namedtype.NamedType('subject', char.PrintableString()),
        namedtype.NamedType('validity', Validity()),
        namedtype.NamedType('publicKey', PublicKeyInfo()),
        namedtype.NamedType('signature', Signature()),
        namedtype.NamedType('delegation', univ.Boolean())
    )

# Helper Functions
def generate_random_oid():
    """Generate a random OBJECT IDENTIFIER."""
    return univ.ObjectIdentifier('1.2.840.113549.1.1.1')  # Example: RSA OID

def generate_random_key():
    """Generate a random public key as a BIT STRING."""
    return univ.BitString("'1010101010101010'B")

def generate_random_signature():
    """Generate a random signature as a BIT STRING."""
    return univ.BitString("'1111000011110000'B")

def generate_random_validity():
    """Generate random validity period."""
    now = datetime.datetime.now(datetime.UTC)
    not_before = useful.UTCTime(now.strftime("%y%m%d%H%M%SZ"))
    not_after = useful.UTCTime((now + datetime.timedelta(days=365)).strftime("%y%m%d%H%M%SZ"))
    return not_before, not_after

def generate_spki_certificate(issuer, identifier, subject, is_auth=False, delegation=False):
    """Generate an SPKI certificate (Name or Authorization)."""
    not_before, not_after = generate_random_validity()
    validity = Validity()
    validity.setComponentByName('notBefore', not_before)
    validity.setComponentByName('notAfter', not_after)

    public_key_info = PublicKeyInfo()
    public_key_info.setComponentByName('algorithm', generate_random_oid())
    public_key_info.setComponentByName('key', generate_random_key())

    signature = Signature()
    signature.setComponentByName('algorithm', generate_random_oid())
    signature.setComponentByName('signatureValue', generate_random_signature())

    if is_auth:  # Authorization Certificate
        cert = AuthorizationCertificate()
        cert.setComponentByName('delegation', delegation)
    else:  # Name Certificate
        cert = NameCertificate()

    cert.setComponentByName('version', 1)
    cert.setComponentByName('issuer', issuer)
    cert.setComponentByName('identifier', identifier)
    cert.setComponentByName('subject', subject)
    cert.setComponentByName('validity', validity)
    cert.setComponentByName('publicKey', public_key_info)
    cert.setComponentByName('signature', signature)
    
    # print(encoder.encode(cert))

    return encoder.encode(cert)

def generate_spki_asn1(issuer, identifier, subject, is_auth=False, delegation=False):
    """Generate an SPKI certificate in ASN.1 format."""
    not_before = datetime.datetime.now(datetime.UTC).strftime("%y%m%d%H%M%SZ")
    not_after = (datetime.datetime.now(datetime.UTC) + datetime.timedelta(days=365)).strftime("%y%m%d%H%M%SZ")
    
    asn1_template = f"""
[default]
asn1 = SEQUENCE:spki_cert

[spki_cert]
version = INTEGER:1
issuer = PRINTABLESTRING:"{issuer}"
identifier = PRINTABLESTRING:"{identifier}"
subject = PRINTABLESTRING:"{subject}"
validity = SEQUENCE:validity_section
publicKey = SEQUENCE:public_key_section
signature = SEQUENCE:signature_section
"""

    if is_auth:
        asn1_template += f"""delegation = BOOLEAN:{str(delegation).upper()}
"""

    asn1_template += f"""
[validity_section]
notBefore = UTCTIME:"{not_before}"
notAfter = UTCTIME:"{not_after}"

[public_key_section]
algorithm = OBJECT:1.2.840.113549.1.1.1
key = BITSTRING:1010101010101010B

[signature_section]
algorithm = OBJECT:1.2.840.113549.1.1.11
signatureValue = BITSTRING:1111000011110000B
"""

    return asn1_template

def generate_x509_config(spki_asn1):    
    encoded_spki = spki_asn1.encode("ascii")

    base64_bytes = base64.b64encode(encoded_spki)
    base64_string = base64_bytes.decode("ascii")
    
    """Generate an SPKI certificate in ASN.1 format."""
    
    config_template = f"""
[ req ]
default_bits        = 2048
default_md          = sha256
prompt             = no
distinguished_name = dn
x509_extensions    = v3_ext  # Extensions for self-signed certificate
req_extensions     = v3_ext  # Extensions for CSR

[ dn ]
C  = IN
ST = Maharashtra
L  = Mumbai
O  = MyOrganization
OU = MyUnit
CN = mydomain.com
emailAddress = admin@mydomain.com

[ v3_ext ]
# Standard Extensions
subjectAltName        = @alt_names
basicConstraints      = critical,CA:FALSE
keyUsage              = critical,digitalSignature, keyEncipherment
extendedKeyUsage      = serverAuth,clientAuth
subjectKeyIdentifier  = hash  # Generates a unique identifier for the subject

# Custom Extension (String Data)
1.2.3.4.5.6 = ASN1:UTF8String: "{base64_string}"

[ alt_names ]
DNS.1 = mydomain.com
DNS.2 = www.mydomain.com
IP.1  = 192.168.1.1
"""

    return config_template

def save_asn1_to_der(asn1_data, output_file):
    """Save ASN.1 to a DER encoded file using OpenSSL."""
    asn1_file = output_file.replace(".der", ".asn1")

    # Ensure directory exists
    os.makedirs(os.path.dirname(asn1_file), exist_ok=True)
    
    with open(asn1_file, "w") as f:
        f.write(asn1_data)
        
    # output_file = output_file.replace(" ", "")
    
    cmd = f"openssl asn1parse -genconf {asn1_file} -out {output_file}"
    subprocess.run(cmd, shell=True, check=True)
    
    os.remove(asn1_file)  # Cleanup ASN.1 file
    print(f"Saved ASN.1 DER: {output_file}")

def generate_x509_certificate(issuer, subject, output_folder, spki_asn1):
    """Generate an X.509 certificate and embed the SPKI certificate as an extension using OpenSSL."""
    key_file = os.path.join(output_folder, f"{subject}_key.key")
    cert_file = os.path.join(output_folder, f"{subject}_cert.pem")
    # ext_file = os.path.join(output_folder, f"{subject}_ext.cnf")

    # Ensure output directory exists
    os.makedirs(output_folder, exist_ok=True)

    # Generate RSA key
    subprocess.run(f"openssl genpkey -algorithm RSA -out {key_file} -pkeyopt rsa_keygen_bits:2048", shell=True, check=True)

    # Generate CSR (Certificate Signing Request)
    csr_file = os.path.join(output_folder, f"{issuer}_{subject}.csr")
    cnf_file = os.path.join(output_folder, f"{issuer}_{subject}.cnf")
    
    config_template = generate_x509_config(spki_asn1)
    with open(cnf_file, "w") as f:
        f.write(config_template)
    
    subprocess.run(
        f"openssl req -new -key {key_file} -out {csr_file} -config {cnf_file}",
        shell=True, check=True
    )

    # Generate X.509 certificate with SPKI extension
    subprocess.run(
        f"openssl x509 -req -in {csr_file} -signkey {key_file} -out {cert_file} -days 365 -extfile {cnf_file} -extensions v3_ext",
        shell=True, check=True
    )

    print(f"Saved X.509 Certificate: {cert_file}")
    
    # Cleaning extra files
    os.remove(csr_file) # delete csr file 
    os.remove(cnf_file) # delete cnf file 

def parse_certificate_file(file_path, output_folder):
    """Parse the input .txt file and generate X.509 certificates embedding SPKI."""
    with open(file_path, 'r') as file:
        lines = file.readlines()

    for line in lines:
        line = line.strip()
        if '->' not in line:
            continue

        parts = line.split('->')
        
        leftHandSide = parts[0].strip()
        issuer = leftHandSide.split(' ')[0].strip()
        identifier = ' '.join(leftHandSide.split()[1:]).strip()
        
        rest = parts[1].strip()
        
        ### MOD

        if '[' in rest and ']' in rest:  # Authorization Certificate
            subject, delegation_bit = rest.split('[')
            subject = subject.replace(" ", "")
            delegation = bool(int(delegation_bit.strip('[]')))
            # identifier = "AuthCert"
            spki_asn1 = generate_spki_asn1(issuer, identifier, subject.strip(), is_auth=True, delegation=delegation)
            spki_der_file = os.path.join(output_folder, f"{subject.strip()}_auth.der")
        else:  # Name Certificate
            subject = rest
            subject = subject.replace(" ", "")
            spki_asn1 = generate_spki_asn1(issuer, identifier.strip(), subject.strip())
            spki_der_file = os.path.join(output_folder, f"{subject.strip()}_name.der")
            
        # generate_spki_certificate(issuer, identifier, subject, is_auth=False, delegation=False)
        save_asn1_to_der(spki_asn1, spki_der_file)
        generate_x509_certificate(issuer, subject.strip(), output_folder, spki_asn1)

# Command-line Argument Handling
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Generate X.509 certificates embedding SPKI certificates.")
    parser.add_argument("file", type=str, help="Path to the certificate text file.")
    parser.add_argument("output_folder", type=str, help="Folder to store generated certificates.")
    args = parser.parse_args()

    parse_certificate_file(args.file, args.output_folder)
