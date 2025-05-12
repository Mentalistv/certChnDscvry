import socket
import threading

class Proof:
    def __init__(self, type, name, subject):
        self.type = type
        self.name = name
        self.subject = subject

HOST = '127.0.0.1'
PORT = 65432
END_MARKER = "__END_OF_MESSAGE__"

def handle_client(conn, addr):
    print(f"Connected by {addr}")
    try:
        # 1. Receive a single-line message
        single_line = conn.recv(1024).decode().strip()
        print(f"[{addr}] Requested resource: {single_line}")

        file_name = f"{single_line.replace(' ', '')}.txt"

        # 2. Read and send resource file
        try:
            with open(file_name, 'r') as f:
                data = f.read()
            conn.sendall((data + f"\n{END_MARKER}\n").encode())
        except FileNotFoundError:
            conn.sendall((f"ERROR: File '{file_name}' not found.\n{END_MARKER}\n").encode())
            return

        # 3. Receive multiline proof message
        data = ""
        while True:
            chunk = conn.recv(1024).decode()
            data += chunk
            if END_MARKER in data:
                break

        data = data.replace(END_MARKER, "").strip()
        received_lines = data.splitlines()
        proof_chain = []

        print(f"\n[{addr}] Proof received from client:")
        for line in received_lines:
            try:
                type_part, arrow_part = line.split(":", 1)
                name, subject = arrow_part.strip().split("->")
                p = Proof(type_part.strip(), name.strip(), subject.strip())
                proof_chain.append(p)
                print(f"{p.type}: {p.name} -> {p.subject}")
            except ValueError:
                print(f"Invalid proof format: {line}")

        # 4. Verify the proof chain
        proof_verified = True
        
        
        
        # 5. Send secret file
        if proof_verified:
            secret_file = f"{single_line.replace(' ', '')}_secret.txt"
            try:
                with open(secret_file, 'r') as f:
                    secret_data = f.read()
                conn.sendall((secret_data + f"\n{END_MARKER}\n").encode())
                print(f"[{addr}] Secret file sent.")
            except FileNotFoundError:
                conn.sendall((f"ERROR: File '{secret_file}' not found.\n{END_MARKER}\n").encode())
        else:
            conn.sendall(("Proof isnt correct!" + f"\n{END_MARKER}\n").encode())            
            
    finally:
        conn.close()
        print(f"[{addr}] Connection closed.")

def start_server():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
        server_socket.bind((HOST, PORT))
        server_socket.listen()
        print(f"Server listening on {HOST}:{PORT}...")

        while True:
            conn, addr = server_socket.accept()
            threading.Thread(target=handle_client, args=(conn, addr)).start()

if __name__ == "__main__":
    start_server()
