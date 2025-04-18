import os
import argparse
import subprocess
import base64

def generate_x509_certificate(issuer, subject, output_folder, url):
    """Generate an X.509 certificate and embed the SPKI certificate as an extension using OpenSSL."""
    key_folder = os.path.join(output_folder, "keys")
    cert_folder = os.path.join(output_folder, "certs")
    os.makedirs(key_folder, exist_ok=True)
    os.makedirs(cert_folder, exist_ok=True)
    
    urlbase64 = base64.b64encode(url.encode()).decode("utf-8")
    
    key_file = os.path.join(key_folder, f"{issuer}_key.key")
    cert_file = os.path.join(cert_folder, f"{issuer}_{subject}_cert.pem")
    cnf_file = os.path.join(output_folder, f"{subject}_ext.cnf")
    
    # Generate RSA key
    subprocess.run([
        "openssl", "genpkey", "-algorithm", "RSA", "-out", key_file, "-pkeyopt", "rsa_keygen_bits:2048"
    ], check=True)
    
    # Create OpenSSL extension configuration
    config_template = f"""
[req]
distinguished_name = req_distinguished_name
x509_extensions = v3_ext
prompt = no

[req_distinguished_name]
CN = {subject}

[v3_ext]
1.2.3.4.5.6 = ASN1:UTF8String:{urlbase64}
"""
    
    with open(cnf_file, "w") as f:
        f.write(config_template)
    
    # Generate self-signed X.509 certificate
    subprocess.run([
        "openssl", "req", "-new", "-x509", "-key", key_file, "-out", cert_file, "-days", "365", "-config", cnf_file
    ], check=True)
    
    print(f"Saved X.509 Certificate: {cert_file}")
    
    os.remove(cnf_file)  # Clean up extension file


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Generate X.509 certificates embedding SPKI certificates.")
    parser.add_argument("url", type=str, help="URL to the certificate GitHub repository.")
    parser.add_argument("output_folder", type=str, help="Folder to store generated certificates.")
    
    args = parser.parse_args()
    
    issuer = "issuer"
    subject = "subject"
    
    generate_x509_certificate(issuer, subject, args.output_folder, args.url)
