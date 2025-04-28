import os
import datetime
import argparse
import subprocess
import base64
from pyasn1.type import univ, namedtype, char, useful
from pyasn1.codec.der import encoder


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
        # namedtype.NamedType('version', univ.Integer()),
        namedtype.NamedType('issuer', char.PrintableString()),
        namedtype.NamedType('identifier', char.PrintableString()),
        namedtype.NamedType('subject', char.PrintableString()),
        namedtype.NamedType('validity', Validity()),
        namedtype.NamedType('publicKey', PublicKeyInfo()),
        namedtype.NamedType('signature', Signature())
    )

class AuthorizationCertificate(univ.Sequence):
    componentType = namedtype.NamedTypes(
        # namedtype.NamedType('version', univ.Integer()),
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

    # Create AlgorithmIdentifier
    algorithm_id = AlgorithmIdentifier()
    algorithm_id.setComponentByName('algorithm', generate_random_oid())

    # Create PublicKeyInfo
    public_key_info = PublicKeyInfo()
    public_key_info.setComponentByName('algorithm', algorithm_id)  # FIXED
    public_key_info.setComponentByName('key', generate_random_key())

    # Create Signature
    signature_algo = AlgorithmIdentifier()
    signature_algo.setComponentByName('algorithm', generate_random_oid())

    signature = Signature()
    signature.setComponentByName('algorithm', signature_algo)  # FIXED
    signature.setComponentByName('signatureValue', generate_random_signature())

    # Determine certificate type
    if is_auth:
        cert = AuthorizationCertificate()
        cert.setComponentByName('delegation', delegation)
    else:
        cert = NameCertificate()

    # cert.setComponentByName('version', 1)
    cert.setComponentByName('issuer', issuer)
    cert.setComponentByName('identifier', identifier)
    cert.setComponentByName('subject', subject)
    cert.setComponentByName('validity', validity)
    cert.setComponentByName('publicKey', public_key_info)
    cert.setComponentByName('signature', signature)
    
    return encoder.encode(cert)

def save_asn1_to_der(asn1_encoded, der_file):
    """Save ASN.1 encoded certificate to a DER file."""
    os.makedirs(os.path.dirname(der_file), exist_ok=True)
        
    with open(der_file, "wb") as f:
        f.write(asn1_encoded)

def convert_der_to_base64(der_file):
    """Convert DER file to Base64 encoded string."""
    with open(der_file, "rb") as f:
        der_data = f.read()
        
    res = base64.b64encode(der_data).decode("utf-8")
    return res


# generate X.509 certificate and make use of the extension to embed the SPKI certificate
def generate_x509_certificate(issuer, subject, output_folder, spki_b64):
    """Generate an X.509 certificate and embed the SPKI certificate as an extension using OpenSSL."""
    key_folder = os.path.join(output_folder, f"keys")
    cert_folder = os.path.join(output_folder, f"certs")
    
    key_file = os.path.join(key_folder, f"{issuer}_key.key")
    cert_file = os.path.join(cert_folder, f"{issuer}_{subject}_cert.pem")
    cnf_file = os.path.join(output_folder, f"{subject}_ext.cnf")

    os.makedirs(output_folder, exist_ok=True)
    
    os.makedirs(key_folder, exist_ok=True)
    os.makedirs(cert_folder, exist_ok=True)

    # Generate RSA key
    subprocess.run(f"openssl genpkey -algorithm RSA -out {key_file} -pkeyopt rsa_keygen_bits:2048", shell=True, check=True)

    # Create OpenSSL extension configuration
    config_template = f"""
[req]
distinguished_name = req_distinguished_name
x509_extensions = v3_ext
prompt = no

[req_distinguished_name]
CN = {subject}

[v3_ext]
1.2.3.4.5.6 = ASN1:UTF8String:{spki_b64}
"""
    with open(cnf_file, "w") as f:
        f.write(config_template)

    # Generate self-signed X.509 certificate
    subprocess.run(
        f"openssl req -new -x509 -key {key_file} -out {cert_file} -days 365 -config {cnf_file}",
        shell=True, check=True
    )

    print(f"Saved X.509 Certificate: {cert_file}")

    os.remove(cnf_file)  # Clean up extension file


def parse_certificate_file(file_path, output_folder):
    """Parse the input .txt file and generate X.509 certificates embedding SPKI."""
    with open(file_path, 'r') as file:
        lines = file.readlines()

    for line in lines:
        line = line.strip()
        if '->' not in line:
            continue

        parts = line.split('->')
        issuer = parts[0].split()[0].strip()
        identifier = ' '.join(parts[0].split()[1:]).strip()
        rest = parts[1].strip()

        if '[' in rest and ']' in rest:  # Authorization Certificate
            subject, delegation_bit = rest.split('[')
            subject = subject.strip()
            subject = subject.replace(" ", "#")
            delegation = bool(int(delegation_bit.strip('[]')))
            spki_asn1 = generate_spki_certificate(issuer, identifier, subject, is_auth=True, delegation=delegation)
        else:  # Name Certificate
            subject = rest.strip()
            subject = subject.replace(" ", "#")
            spki_asn1 = generate_spki_certificate(issuer, identifier, subject)

        der_folder = os.path.join(output_folder, f"ders")
        os.makedirs(der_folder, exist_ok=True)
        der_file = os.path.join(der_folder, f"{issuer}_{subject}.der")
        save_asn1_to_der(spki_asn1, der_file)
        
        spki_b64 = convert_der_to_base64(der_file)

        generate_x509_certificate(issuer, subject, output_folder, spki_b64)


# Command-line Argument Handling
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Generate X.509 certificates embedding SPKI certificates.")
    parser.add_argument("file", type=str, help="Path to the certificate text file.")
    parser.add_argument("output_folder", type=str, help="Folder to store generated certificates.")
    args = parser.parse_args()

    parse_certificate_file(args.file, args.output_folder)
