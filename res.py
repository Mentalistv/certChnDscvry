import os
import sys
import uuid
import hashlib
from collections import defaultdict

# Data Types
# class CertType:
    # NAME = "NAME"
    # AUTH = "AUTH"

class Principal:
    def __init__(self, key):
        self.key = key
    
    def __eq__(self, other):
        return self.key == other.key
    
    def __hash__(self):
        return hash(self.key)

class Name:
    def __init__(self, issuer, local_names):
        self.issuer = issuer
        self.local_names = local_names
    
    def __eq__(self, other):
        return self.issuer == other.issuer and self.local_names == other.local_names
    
    def __hash__(self):
        return hash((self.issuer, self.local_names))

class Subject:
    def __init__(self, flag, principal=None, name=None):
        self.is_principal = flag
        self.principal = principal
        self.name = name
    
    def __eq__(self, other):
        return (self.is_principal == other.is_principal and self.principal == other.principal) or (self.name == other.name)
    
    def __hash__(self):
        return hash((self.is_principal, self.principal if self.is_principal else self.name))

class Certificate:
    def __init__(self, cert_id, cert_type, name, subject, delegation_bit):
        self.cert_id = cert_id
        self.cert_type = cert_type
        self.name = name
        self.subject = subject
        self.delegation_bit = delegation_bit
    
    def __eq__(self, other):
        return self.cert_id == other.cert_id
    
    def __hash__(self):
        return hash(self.cert_id)

class Proof:
    def __init__(self, name, subject, cert_ids, delegation_bit=0):
        self.name = name
        self.subject = subject
        self.cert_ids = cert_ids
        self.delegation_bit = delegation_bit
    
    def __eq__(self, other):
        return (self.name == other.name and self.subject == other.subject and 
                self.cert_ids == other.cert_ids and self.delegation_bit == other.delegation_bit)
    
    def __hash__(self):
        return hash((self.name, self.subject, tuple(self.cert_ids), self.delegation_bit))

# Hash Tables
check = defaultdict(set)
value = defaultdict(set)
compatible = defaultdict(set)
cert_pool = {}
loaded_value = set()

# reads certs fron the folder
def parse_certificate(file_path):
    with open(file_path, 'r', encoding="utf-8") as file:
        lines = file.readlines()
    
    issuer = lines[1].strip().split(':')[-1].strip()
    local_name = lines[2].strip().split(':')[-1].strip()
    subject_issuer = lines[3].strip().split(':')[-1].strip().split('#')[0].strip()
    subject_local_name = ' '.join(lines[3].strip().split(':')[-1].strip().replace('#', ' ').strip().split()[1:])
    
    last_line = lines[-2].strip()
    cert_type = "AUTH" if "BOOLEAN" in last_line else "NAME"
    delegation_bit = 1 if "255" in last_line else 0
    
    cert_id = str(uuid.uuid4())
    issuer_principal = Principal(issuer)
    name = Name(issuer_principal, local_name)
    subject = Subject(False, name=Name(Principal(subject_issuer), subject_local_name))
        
    cert = Certificate(cert_id, cert_type, name, subject, delegation_bit)
    
    return cert

def load_certificates_from_folder(folder_path):
    for file_name in os.listdir(folder_path):
        file_path = os.path.join(folder_path, file_name)
        if os.path.isfile(file_path):
            cert = parse_certificate(file_path)
            cert_pool[cert.cert_id] = cert


def compatible_add_prefix(proof):
    temp = []
    for name in proof.subject.name.local_names:
        temp.append(name)
        compatible[tuple(temp)].add(proof)

def return_prefix(name):
    res, temp = [], []
    for part in name:
        temp.append(part)
        res.append(temp.copy())
    return res

def cert_to_proof(cert):
    return Proof(cert.name, cert.subject, [cert.cert_id], cert.delegation_bit)

def compose(proof_a, proof_b):
    p = Proof(Name(Principal("composed"), proof_a.name.local_names), None, proof_a.cert_ids + proof_b.cert_ids)
    if proof_a.subject.name.local_names == proof_b.name.local_names:
        p.subject = proof_b.subject
    else:
        p.subject = Subject(name=Name(Principal(""), proof_b.subject.name.local_names + proof_a.subject.name.local_names[len(proof_b.name.local_names):]))
    return p

def insert(proof):
    key = (proof.name, proof.subject)
    if key not in check:
        check[key].add(proof)
        if not proof.subject.is_principal:
            compatible_add_prefix(proof)
            for prefix in return_prefix(proof.subject.name.local_names):
                load_value(prefix)
                for other_proof in value[tuple(prefix)]:
                    insert(compose(proof, other_proof))
        else:
            value[tuple(proof.name.local_names)].add(proof)
            for comp_proof in compatible[tuple(proof.name.local_names)]:
                insert(compose(comp_proof, proof))

def load_value(name):
    if tuple(name) not in loaded_value:
        loaded_value.add(tuple(name))
        for cert in cert_pool.values():
            if cert.name.local_names == name:
                insert(cert_to_proof(cert))


# // MOD ::  made name string
def name_resolution(name):
    load_value(name)
    return value[name]

def print_cert(cert):
    issuer_key = cert.name.issuer.key if isinstance(cert.name.issuer, Principal) else cert.name.issuer
    subject = (
        cert.subject.principal.key 
        if cert.subject.is_principal 
        else f"{cert.subject.name.issuer.key if isinstance(cert.subject.name.issuer, Principal) else cert.subject.name.issuer} {cert.subject.name.local_names}"
    )
    print(f"{cert.cert_type}: {issuer_key} {cert.name.local_names} -> {subject}")

def print_chain(proof):
    for cert_id in proof.cert_ids:
        print_cert(cert_pool[cert_id])

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python script.py <folder_path>")
        exit(1)
    
    folder_path = sys.argv[1]
    load_certificates_from_folder(folder_path)
    
    for cert in cert_pool.values():
        print_cert(cert)
        
    print("\n--------------------------------------------------------------------------------\n")
    
    name_under_consideration = input("Enter the certificate ID to resolve: ")
    
    res = name_resolution(name_under_consideration)
    print(f"Name Resolution for {name_under_consideration}:")
    
    # print(len(res))
        
    
    for proof in res:
        print(proof.subject.principal.key if proof.subject.is_principal else ' '.join(proof.subject.name.issuer.key, proof.subject.name.local_names))
        # print_chain(proof)
        # print()
