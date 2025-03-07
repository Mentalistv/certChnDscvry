import subprocess
import sys
import base64
import re
import os

def extract_and_decode_b64(cert_file, output_der, output_txt):
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
            decoded_data = base64.b64decode(b64_string[2:])

            with open(output_der, "wb") as f:
                f.write(decoded_data)

            print(f"Extracted Base64 String from {cert_file}:\n{b64_string}\n")
            print(f"Decoded DER file saved as: {output_der}")

            # Decode the DER file using OpenSSL and save to .txt file
            decode_der(output_der, output_txt)

        else:
            print(f"OID 1.2.3.4.5.6 not found in {cert_file}.")

    except subprocess.CalledProcessError as e:
        print(f"Error running OpenSSL: {e}")

def decode_der(der_file, output_txt):
    """Decodes the DER file and saves its content to a text file."""
    try:
        result = subprocess.run(
            ["openssl", "asn1parse", "-in", der_file, "-inform", "DER"],
            capture_output=True, text=True, check=True
        )

        decoded_content = result.stdout
        print(f"\nDecoded DER Content saved in {output_txt}\n")

        # Save decoded content to a text file
        with open(output_txt, "w") as f:
            f.write(decoded_content)

    except subprocess.CalledProcessError as e:
        print(f"Error decoding DER file: {e}")

def process_folder(input_folder, output_folder):
    """Processes all certificate files in the input folder."""
    if not os.path.exists(output_folder):  
        os.makedirs(output_folder)  # Create output folder if it doesn't exist

    for cert_file in os.listdir(input_folder):
        cert_path = os.path.join(input_folder, cert_file)
        if cert_file.endswith(".crt") or cert_file.endswith(".pem"):  
            cert_name = os.path.splitext(cert_file)[0]  
            output_der = os.path.join(output_folder, f"{cert_name}.der")  
            output_txt = os.path.join(output_folder, f"{cert_name}.txt")  
            
            print(f"\nProcessing Certificate: {cert_file}")

            extract_and_decode_b64(cert_path, output_der, output_txt)
            os.remove(output_der)

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python extract_and_decode_folder.py <input_folder> <output_folder>")
        sys.exit(1)

    input_folder = sys.argv[1]
    output_folder = sys.argv[2]

    process_folder(input_folder, output_folder)
