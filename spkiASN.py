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

def generate_name_certificate(subject, issuer, identifier, not_before, not_after, signature):
    """
    Generate a Name Certificate in ASN.1 format.

    :param subject: Subject name of the certificate.
    :param issuer: Issuer name of the certificate.
    :param identifier: Unique identifier for the certificate.
    :param not_before: Start of the validity period (string format).
    :param not_after: End of the validity period (string format).
    :param signature: Signature in octet string format.
    :return: ASN.1 DER-encoded Name Certificate.
    """
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

def generate_authorization_certificate(subject, issuer, permissions, delegation, not_before, not_after, signature):
    """
    Generate an Authorization Certificate in ASN.1 format.

    :param subject: Subject name of the certificate.
    :param issuer: Issuer name of the certificate.
    :param permissions: Permissions granted to the subject (string format).
    :param delegation: Delegation bit (boolean).
    :param not_before: Start of the validity period (string format).
    :param not_after: End of the validity period (string format).
    :param signature: Signature in octet string format.
    :return: ASN.1 DER-encoded Authorization Certificate.
    """
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

def parse_name_certificate(encoded_cert):
    """
    Parse an ASN.1 DER-encoded Name Certificate.

    :param encoded_cert: DER-encoded certificate bytes.
    :return: Parsed Name Certificate fields as a dictionary.
    """
    cert, _ = decoder.decode(encoded_cert, asn1Spec=NameCertificate())
    return {
        'subject': cert.getComponentByName('subject').prettyPrint(),
        'issuer': cert.getComponentByName('issuer').prettyPrint(),
        'identifier': cert.getComponentByName('identifier').prettyPrint(),
        'validity': {
            'notBefore': cert.getComponentByName('validity').getComponentByName('notBefore').prettyPrint(),
            'notAfter': cert.getComponentByName('validity').getComponentByName('notAfter').prettyPrint(),
        },
        'signature': cert.getComponentByName('signature').prettyPrint()
    }

def parse_authorization_certificate(encoded_cert):
    """
    Parse an ASN.1 DER-encoded Authorization Certificate.

    :param encoded_cert: DER-encoded certificate bytes.
    :return: Parsed Authorization Certificate fields as a dictionary.
    """
    cert, _ = decoder.decode(encoded_cert, asn1Spec=AuthorizationCertificate())
    return {
        'subject': cert.getComponentByName('subject').prettyPrint(),
        'issuer': cert.getComponentByName('issuer').prettyPrint(),
        'permissions': cert.getComponentByName('permissions').prettyPrint(),
        'delegation': cert.getComponentByName('delegation').prettyPrint(),
        'validity': {
            'notBefore': cert.getComponentByName('validity').getComponentByName('notBefore').prettyPrint(),
            'notAfter': cert.getComponentByName('validity').getComponentByName('notAfter').prettyPrint(),
        },
        'signature': cert.getComponentByName('signature').prettyPrint()
    }

# Example usage
if __name__ == "__main__":
    # Name Certificate Example
    subject = "John Doe"
    issuer = "Trusted CA"
    identifier = "123456789"
    not_before = "2025-01-01T00:00:00Z"
    not_after = "2025-12-31T23:59:59Z"
    signature = b"\x45\xa0\x3c..."

    encoded_name_cert = generate_name_certificate(subject, issuer, identifier, not_before, not_after, signature)
    print(f"Encoded Name Certificate: {encoded_name_cert.hex()}")

    parsed_name_cert = parse_name_certificate(encoded_name_cert)
    print(f"Parsed Name Certificate: {parsed_name_cert}")

    # Authorization Certificate Example
    permissions = "Read, Write, Execute"
    delegation = True

    encoded_auth_cert = generate_authorization_certificate(subject, issuer, permissions, delegation, not_before, not_after, signature)
    print(f"Encoded Authorization Certificate: {encoded_auth_cert.hex()}")

    parsed_auth_cert = parse_authorization_certificate(encoded_auth_cert)
    print(f"Parsed Authorization Certificate: {parsed_auth_cert}")
