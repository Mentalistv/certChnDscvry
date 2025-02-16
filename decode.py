import subprocess
import sys
import base64
import re

def extract_and_decode_b64(cert_file, output_der):
    try:
        # Run OpenSSL command to get certificate details
        result = subprocess.run(
            ["openssl", "x509", "-in", cert_file, "-text", "-noout"],
            capture_output=True, text=True, check=True
        )

        output = result.stdout

        # Search for the OID 1.2.3.4.5.6 in the certificate output
        match = re.search(r"1\.2\.3\.4\.5\.6:\s*\n\s*(.+)", output)

        if match:
            b64_string = match.group(1).strip()

            # Decode Base64 and write to a DER file
            decoded_data = base64.b64decode(b64_string)

            with open(output_der, "wb") as f:
                f.write(decoded_data)

            print(f"Extracted Base64 String:\n{b64_string}\n")
            print(f"Decoded DER file saved as: {output_der}")

            # Decode the DER file using OpenSSL
            decode_der(output_der)

        else:
            print("OID 1.2.3.4.5.6 not found in the certificate.")

    except subprocess.CalledProcessError as e:
        print(f"Error running OpenSSL: {e}")

def decode_der(der_file):
    """Decodes the DER file and prints its content."""
    try:
        result = subprocess.run(
            ["openssl", "asn1parse", "-in", der_file, "-inform", "DER"],
            capture_output=True, text=True, check=True
        )
        print("\nDecoded DER Content:\n")
        print(result.stdout)

    except subprocess.CalledProcessError as e:
        print(f"Error decoding DER file: {e}")

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python extract_and_decode_der.py <certificate.crt> <output.der>")
        sys.exit(1)

    cert_file = sys.argv[1]
    output_der = sys.argv[2]
    
    extract_and_decode_b64(cert_file, output_der)
