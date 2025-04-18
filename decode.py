import subprocess
import sys
import os


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

    for der_file in os.listdir(input_folder):
        der_path = os.path.join(input_folder, der_file)
        if der_file.endswith(".der"):  
            cert_name = os.path.splitext(der_file)[0]
            output_txt = os.path.join(output_folder, f"{cert_name}.txt")  
            
            print(f"\nProcessing .der file: {der_file}")

            decode_der(der_path, output_txt)
            # os.remove(output_der)

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python extract_and_decode_folder.py <input_folder> <output_folder>")
        sys.exit(1)

    input_folder = sys.argv[1]
    output_folder = sys.argv[2]

    process_folder(input_folder, output_folder)
