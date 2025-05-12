import socket
import threading

class Proof:
    def __init__(self, type, name, subject):
        self.type = type
        self.name = name
        self.subject = subject

HOST = '127.0.0.1'
PORT = 65432

def handle_client(conn, addr):
    print(f"Connected by {addr}")
    try:
        # 1. Receive a single-line message
        single_line = conn.recv(1024).decode().strip()
        print(f"[{addr}] Received from client: {single_line}")

        file_name = f"{single_line}.txt"

        # 2. Read file and send multiline data
        try:
            with open(file_name, 'r') as f:
                lines = f.readlines()
            multiline_data = ''.join(lines)
            conn.sendall(multiline_data.encode())
        except FileNotFoundError:
            error_msg = f"File '{file_name}' not found."
            conn.sendall(error_msg.encode())
            return

        # 3. Receive multiline message from client
        data = b""
        while True:
            chunk = conn.recv(1024)
            if not chunk:
                break
            data += chunk
        recieved_lines = data.decode().splitlines()
                
        proof_chain = []
        for line in recieved_lines:
            partitioned_line = line.split(":")
            
            type = partitioned_line[0].strip()
            local_name = partitioned_line[1].split("->")[0].strip()
            subject = partitioned_line[1].split("->")[1].strip()
            
            p = Proof(type, local_name, subject)
            proof_chain.append(p)
            
        print(f"\n[{addr}] Proof received from client:")
        
        for proof in proof_chain:
            print(f"{proof.type}: {proof.name} -> {proof.subject}")
            
        # 4. Read file and send multiline data
        file_name = f"{single_line}.txt"
        
        try:
            with open(file_name, 'r') as f:
                lines = f.readlines()
            multiline_data = ''.join(lines)
            conn.sendall(multiline_data.encode())
            print("File sent.")
        except FileNotFoundError:
            error_msg = f"File '{file_name}' not found."
            conn.sendall(error_msg.encode())
            return
        
    finally:
        conn.close()
        print(f"[{addr}] Connection closed.")

def start_server():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
        server_socket.bind((HOST, PORT))
        server_socket.listen()
        print(f"Multithreaded server listening on {HOST}:{PORT}...")

        while True:
            conn, addr = server_socket.accept()
            client_thread = threading.Thread(target=handle_client, args=(conn, addr))
            client_thread.start()

if __name__ == "__main__":
    start_server()
