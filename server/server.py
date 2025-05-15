import socket
import threading

from fetchFilesGitHub import fetch_der_files
from decode import process_folder

import tempfile
import os
import shutil
# from fetchFilesGitHub import list_der_files, download_file
# from decode import decode_der
# from res import parse_certificate, cert_pool

class Proof:
    def __init__(self, type, name, subject):
        self.type = type
        self.name = name
        self.subject = subject
        
    def __eq__(self, other):
        return (self.name == other.name and self.subject == other.subject and self.type == other.type)

HOST = '127.0.0.1'
PORT = 65432
END_MARKER = "__END_OF_MESSAGE__"

def der_to_Proof(file_path):
    with open(file_path, 'r', encoding="utf-8") as file:
        lines = file.readlines()
    
    issuer = lines[1].strip().split(':')[-1].strip()
    local_name = issuer + " "
    local_name += lines[2].strip().split(':')[-1].strip()
    
    subject_issuer = lines[3].strip().split(':')[-1].strip().split('#')[0].strip()
    subject_local_name = subject_issuer + " "
    subject_local_name += ' '.join(lines[3].strip().split(':')[-1].strip().replace('#', ' ').strip().split()[1:])
    
    # last_line = lines[-2].strip()
    type = "AUTH" if "BOOLEAN" in last_line else "NAME"
    # delegation_bit = 1 if "255" in last_line else 0
    
    # cert_id = str(uuid.uuid4())
    # issuer_principal = Principal(issuer)
    # name = Name(issuer_principal, local_name)
    
    # if("#" in lines[3]):
    #     subject = Subject(False, name=Name(Principal(subject_issuer), subject_local_name))
    # else:
    #     subject_principal = Principal(subject_issuer)
    #     subject = Subject(True, principal=subject_principal)
        
    proof = Proof(type, local_name, subject_local_name)
    
    return proof

def verify_proof_chain(proof_chain, temp_base="./temp_verify"):
    owner = "VarnG"
    branch = "main"
    
    os.makedirs(temp_base, exist_ok=True)
    temporary_folder = os.path.join(temp_base, "temp")
    os.makedirs(temporary_folder, exist_ok=True)
    
    # fetch_cert_set = set()
    
    for proof in proof_chain:
        repo = proof.name.split()[0]
        folder_path = "/".join(proof.name.split()[1:])
        
        fetch_der_files(owner, repo, branch, folder_path, temp_base)        
        process_folder(temp_base, temporary_folder)
        
        for file in temporary_folder:
            file_path = os.path.join(folder_path, file)
            
            if os.path.isfile(file_path):
                p = der_to_Proof(file_path)
                
                if proof == p:
                    continue
                else:
                    return False
                
            shutil.rmtree(temporary_folder)
                
    return True
    
    # for cert_id in proof.cert_ids:
    #     cert = cert_pool[cert_id]
    #     issuer = cert.name.issuer.key
    #     repo = issuer
    #     branch = "main"
    #     folder = cert.name.local_names.split(" ", 1)[1]  # e.g. "Distributors"
        
    #     print(f"verify_proof_chain() :: Verifying for repo={repo}, folder={folder}")
        
    #     # Get .der file list from folder (non-recursively)
    #     der_files = list_der_files(repo, folder, branch=branch)
        
    #     match_found = False
    #     for der_file in der_files:
    #         try:
    #             temp_der_path = os.path.join(temp_base, der_file)
    #             download_file(repo, folder + '/' + der_file, temp_der_path, branch=branch)
                
    #             decoded_txt_path = temp_der_path.replace('.der', '.txt')
    #             decode_der(temp_der_path, decoded_txt_path)
                
    #             parsed_cert = parse_certificate(decoded_txt_path)
                
    #             # Compare the fields
    #             if (parsed_cert.name.local_names == cert.name.local_names and
    #                 parsed_cert.subject == cert.subject and
    #                 parsed_cert.delegation_bit == cert.delegation_bit and
    #                 parsed_cert.cert_type == cert.cert_type):
    #                 match_found = True
    #                 break
    #         except Exception as e:
    #             print(f"verify_proof_chain() :: Error decoding/verifying {der_file}: {e}")
    #             continue
        
    #     if not match_found:
    #         print(f"verify_proof_chain() :: No matching cert found for {cert_id}")
    #         return False

    # print("verify_proof_chain() :: All certificates verified successfully.")
    # return True

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
        # proof_verified = verify_proof_chain(proof_chain)

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
