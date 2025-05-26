import zipfile
import os

def create_der_zip(file_list, output_zip_path):
    """
    Create a ZIP archive containing the specified .der files.

    Parameters:
    - file_list: list of strings, paths to .der files
    - output_zip_path: string, path for the output .zip file

    Returns:
    - True if zip created successfully, False otherwise
    """
    if not file_list:
        print("No files provided.")
        return False

    try:
        with zipfile.ZipFile(output_zip_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
            for file_path in file_list:
                if os.path.isfile(file_path) and file_path.endswith(".der"):
                    zipf.write(file_path, arcname=os.path.basename(file_path))
                else:
                    print(f"Skipping invalid or non-existent file: {file_path}")
        print(f"Created ZIP file: {output_zip_path}")
        return True
    except Exception as e:
        print(f"Error creating zip: {e}")
        return False

# Example usage
if __name__ == "__main__":
    files = [
        "/path/to/cert1.der",
        "/path/to/cert2.der",
        "/path/to/cert3.der",
    ]
    create_der_zip(files, "certificates.zip")
