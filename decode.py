import subprocess
import sys
import base64
import re

def extract_and_decode_b64(cert_file):
    try:
        # Run OpenSSL command to get certificate details
        result = subprocess.run(
            ["openssl", "x509", "-in", cert_file, "-text", "-noout"],
            capture_output=True, text=True, check=True
        )

        output = result.stdout

        # Search for the OID 1.2.3.4.5.6 in the certificate
        match = re.search(r"1\.2\.3\.4\.5\.6:\s*\n\s*(.+)", output)

        if match:
            b64_string = match.group(1).strip()

            # Decode Base64
            decoded_data = base64.b64decode(b64_string).decode("utf-8", errors="ignore")

            print(f"Extracted Base64 String:\n{b64_string}\n")
            print(f"Decoded Data:\n{decoded_data}\n")
        else:
            print("OID 1.2.3.4.5.6 not found in the certificate.")

    except subprocess.CalledProcessError as e:
        print(f"Error running OpenSSL: {e}")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python extract_b64_from_cert.py <certificate.crt>")
        sys.exit(1)

    cert_file = sys.argv[1]
    extract_and_decode_b64(cert_file)
