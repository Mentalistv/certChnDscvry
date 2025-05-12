import socket
from res import name_resolution, Proof, print_cert
import os

HOST = '127.0.0.1'
PORT = 65432

# Prepare the single-line message
initial_message = input("What resource do you want to access? (e.g., 'resource1'): ").strip()

received_lines = []

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
    client_socket.connect((HOST, PORT))

    # Send the single-line message
    client_socket.sendall(initial_message.encode())

    # Receive the file data from server
    data = b""
    client_socket.settimeout(1.0)
    try:
        while True:
            chunk = client_socket.recv(1024)
            if not chunk:
                break
            data += chunk
    except socket.timeout:
        pass  # assume end of transmission

    file_content = data.decode()
    received_lines = file_content.splitlines()

    print("Allowed public keys for the resource:")
    for line in received_lines:
        print(f"> {line}")
        
    pk_to_be_used = input("Enter the public key to generate proof: ")
    
    output_folder = "delete_dir"
    os.makedirs(output_folder, exist_ok=True)
    proof_chain, res_certs = name_resolution(initial_message, output_folder, pk_to_be_used)
    
    multiline_message = """"""
    
    print("\nProof chain:")
    for cert in res_certs:
        multiline_message += print_cert(cert) + "\n"
    
    # Send the multiline message back to server
    client_socket.sendall(multiline_message.encode())
    
    data2 = b""
    try:
        while True:
            chunk = client_socket.recv(1024)
            if not chunk:
                break
            data2 += chunk
    except socket.timeout:
        pass  # assume end of transmission

    # Decode and save to file
    file_content = data2.decode()
    received_lines = file_content.splitlines()

    print("Allowed public keys for the resource:")
    for line in received_lines:
        print(f"> {line}")

    with open("received_file.txt", "w", encoding="utf-8") as f:
        f.write(file_content)

    print("File saved as 'received_file.txt'")
