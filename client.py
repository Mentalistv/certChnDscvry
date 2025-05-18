import socket
from res import name_resolution, print_cert
import os
import sys

# redirects the print stmt output from name resolution
import io
from contextlib import redirect_stdout

HOST = '127.0.0.1'
PORT = 65432
END_MARKER = "__END_OF_MESSAGE__"

def receive_until_marker(sock):
    """ Helper to receive data until the END_MARKER is found. """
    buffer = ""
    try:
        while True:
            chunk = sock.recv(1024).decode()
            if not chunk:
                raise ConnectionResetError("Connection closed by server.")
            buffer += chunk
            if END_MARKER in buffer:
                break
    except (socket.timeout, ConnectionResetError) as e:
        print(f"\n[ERROR] Connection issue: {e}")
        sys.exit(1)
    return buffer.replace(END_MARKER, "").strip()

try:
    resource_name = input("What resource do you want to access? (e.g., 'resource1'): ").strip()

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
        client_socket.settimeout(5.0)  # Optional: prevent hanging
        client_socket.connect((HOST, PORT))

        # Send request
        client_socket.sendall(resource_name.encode())

        # Receive file data
        print("\n[INFO] Waiting for allowed public keys...")
        buffer = receive_until_marker(client_socket)
        lines = buffer.splitlines()
        
        allowed_public_keys = []

        for line in lines:
            # print(f"> {line}")
            allowed_public_keys.append(line.strip())
            
        print("\nAllowed public keys for the resource:")
        for pk in allowed_public_keys:
            print(f"> {pk}")

        # Generate proof chain
        output_folder = "delete_dir"
        os.makedirs(output_folder, exist_ok=True)

        print("\n[INFO] Checking possible chains/proofs...")
        f = io.StringIO()
        with redirect_stdout(f):
            proof_chain, certs = name_resolution(resource_name, output_folder)
            
        res_public_keys = []
        for proof in proof_chain:
            res_public_keys.append(proof.subject.principal.key)
            
        # intersection of allowed public keys and resource public keys
        available_public_keys = list(set(res_public_keys) & set(allowed_public_keys))
            
        print("\nThese are the available options: ")
        for pk in available_public_keys:
            print(f"> {pk}")
        
        pk = input("\nEnter the public key to generate proof: ").strip()
        
        print("\nGenerated Proof Chain:")
        multiline = ""
        for proof in proof_chain:
            if pk == proof.subject.principal.key:
                for cert_id in proof.cert_ids:
                    cert_line = print_cert(certs[cert_id])
                    # print(cert_line)
                    multiline += cert_line + "\n"

        # multiline = ""
        client_socket.sendall((multiline + END_MARKER).encode())

        # Receive secret file
        print("\n[INFO] Waiting for secret file from server...")
        buffer = receive_until_marker(client_socket)

        print("\nReceived secret file content:")
        for line in buffer.splitlines():
            print(f"> {line}")

        with open("received_file.txt", "w") as f:
            f.write(buffer)
        print("\nSaved as 'received_file.txt'")

except (ConnectionRefusedError, socket.timeout) as e:
    print(f"\n[ERROR] Could not connect to server at {HOST}:{PORT}: {e}")
except KeyboardInterrupt:
    print("\n[INFO] Client closed by user.")
except Exception as e:
    print(f"\n[UNEXPECTED ERROR] {e}")
