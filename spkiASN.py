import random
import datetime
from pyasn1.type import univ, namedtype, char, tag
from pyasn1.codec.der import encoder, decoder

class NameCertificate(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('subject', char.UTF8String()),
        namedtype.NamedType('issuer', char.UTF8String()),
        namedtype.NamedType('identifier', char.UTF8String()),
        namedtype.NamedType('validity', univ.Sequence(
            componentType=namedtype.NamedTypes(
                namedtype.NamedType('notBefore', char.UTF8String()),
                namedtype.NamedType('notAfter', char.UTF8String())
            )
        )),
        namedtype.NamedType('signature', univ.OctetString())
    )

class AuthorizationCertificate(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('subject', char.UTF8String()),
        namedtype.NamedType('issuer', char.UTF8String()),
        namedtype.NamedType('permissions', char.UTF8String()),
        namedtype.NamedType('delegation', univ.Boolean()),
        namedtype.NamedType('validity', univ.Sequence(
            componentType=namedtype.NamedTypes(
                namedtype.NamedType('notBefore', char.UTF8String()),
                namedtype.NamedType('notAfter', char.UTF8String())
            )
        )),
        namedtype.NamedType('signature', univ.OctetString())
    )

def generate_random_signature():
    """Generate a random signature as a hex string."""
    return bytes(random.getrandbits(8) for _ in range(20))

def generate_random_validity():
    """Generate random validity period."""
    now = datetime.datetime.utcnow()
    not_before = now.strftime("%Y-%m-%dT%H:%M:%SZ")
    not_after = (now + datetime.timedelta(days=365)).strftime("%Y-%m-%dT%H:%M:%SZ")
    return not_before, not_after

def generate_name_certificate(subject, issuer, identifier):
    """Generate a Name Certificate in ASN.1 format."""
    not_before, not_after = generate_random_validity()
    signature = generate_random_signature()

    cert = NameCertificate()
    cert.setComponentByName('subject', subject)
    cert.setComponentByName('issuer', issuer)
    cert.setComponentByName('identifier', identifier)
    
    validity = cert.getComponentByName('validity')
    validity.setComponentByName('notBefore', not_before)
    validity.setComponentByName('notAfter', not_after)
    
    cert.setComponentByName('validity', validity)
    cert.setComponentByName('signature', signature)
    
    return encoder.encode(cert)

def generate_authorization_certificate(subject, issuer, permissions, delegation):
    """Generate an Authorization Certificate in ASN.1 format."""
    not_before, not_after = generate_random_validity()
    signature = generate_random_signature()

    cert = AuthorizationCertificate()
    cert.setComponentByName('subject', subject)
    cert.setComponentByName('issuer', issuer)
    cert.setComponentByName('permissions', permissions)
    cert.setComponentByName('delegation', delegation)
    
    validity = cert.getComponentByName('validity')
    validity.setComponentByName('notBefore', not_before)
    validity.setComponentByName('notAfter', not_after)
    
    cert.setComponentByName('validity', validity)
    cert.setComponentByName('signature', signature)
    
    return encoder.encode(cert)

def parse_certificate_file(file_path):
    """Parse the input .txt file and generate certificates."""
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
        print(identifier)
        
        rest = parts[1].strip()

        if '[' in rest and ']' in rest:  # Authorization Certificate
            subject, delegation_bit = rest.split('[')
            delegation = bool(int(delegation_bit.strip('[]')))
            permissions = "Read, Write, Execute"  # Example permissions
            encoded_auth_cert = generate_authorization_certificate(subject.strip(), issuer, permissions, delegation)
            print(f"Authorization Certificate: {encoded_auth_cert.hex()}")

        else:  # Name Certificate
            subject = rest
            encoded_name_cert = generate_name_certificate(subject.strip(), issuer, identifier.strip())
            print(f"Name Certificate: {encoded_name_cert.hex()}")

# Example Usage
if __name__ == "__main__":
    file_path = "certificates.txt"  # Replace with the path to your .txt file
    parse_certificate_file(file_path)
