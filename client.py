import socket
from res import name_resolution, print_cert
import os
import sys

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

        print("\nAllowed public keys for the resource:")
        for line in lines:
            print(f"> {line}")

        # Generate proof chain
        pk = input("\nEnter the public key to generate proof: ").strip()
        output_folder = "delete_dir"
        os.makedirs(output_folder, exist_ok=True)

        proof_chain, certs = name_resolution(resource_name, output_folder, pk)

        print("\nGenerated Proof Chain:")
        multiline = ""
        for cert in certs:
            cert_line = print_cert(cert)
            # print(cert_line)
            multiline += cert_line + "\n"

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
