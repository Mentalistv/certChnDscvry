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

# in cpp
# unordered_map<pair<Name, Subject>, unordered_set<Proof>> check;
# unordered_map<vector<string>, unordered_set<Proof>> value;
# unordered_map<vector<string>, unordered_set<Proof>> compatible;
# unordered_map<string, Certificate> certPool;
# unordered_set<vector<string>> loadedValue;

# reads certs fron the folder
def parse_certificate(file_path):
    with open(file_path, 'r', encoding="utf-8") as file:
        lines = file.readlines()
    
    issuer = lines[1].strip().split(':')[-1].strip()
    local_name = issuer + " "
    local_name += lines[2].strip().split(':')[-1].strip()
    
    subject_issuer = lines[3].strip().split(':')[-1].strip().split('#')[0].strip()
    subject_local_name = subject_issuer + " "
    subject_local_name += ' '.join(lines[3].strip().split(':')[-1].strip().replace('#', ' ').strip().split()[1:])
    
    last_line = lines[-2].strip()
    cert_type = "AUTH" if "BOOLEAN" in last_line else "NAME"
    delegation_bit = 1 if "255" in last_line else 0
    
    cert_id = str(uuid.uuid4())
    issuer_principal = Principal(issuer)
    name = Name(issuer_principal, local_name)
    
    if("#" in lines[3]):
        subject = Subject(False, name=Name(Principal(subject_issuer), subject_local_name))
    else:
        subject_principal = Principal(subject_issuer)
        subject = Subject(True, principal=subject_principal)
        
    cert = Certificate(cert_id, cert_type, name, subject, delegation_bit)
    
    return cert

def load_certificates_from_folder(folder_path):
    for file_name in os.listdir(folder_path):
        file_path = os.path.join(folder_path, file_name)
        if os.path.isfile(file_path):
            cert = parse_certificate(file_path)
            cert_pool[cert.cert_id] = cert

# return the prefixes of the name
def return_prefix(name):
    words = name.split()
    return [' '.join(words[:i]) for i in range(1, len(words) + 1)][1:]

# convert certificate to proof
def cert_to_proof(cert):
    return Proof(cert.name, cert.subject, [cert.cert_id], cert.delegation_bit)

# compose two proofs
def compose(proof_a, proof_b):
    p = Proof(Name(proof_a.name.issuer, proof_a.name.local_names), Subject(False, Principal(""), Name(Principal(""), "")), proof_a.cert_ids + proof_b.cert_ids, proof_a.delegation_bit)
    
    print("compose() :: Composing proofs with names:", proof_a.name.local_names, "->", proof_a.subject.name.local_names, " and ", proof_b.name.local_names, "->", proof_b.subject.principal.key if proof_b.subject.is_principal else proof_b.subject.name.local_names)
    
    if proof_a.subject.name.local_names == proof_b.name.local_names:
        if(proof_b.subject.is_principal):
            p.subject.is_principal = True
            p.subject.principal = proof_b.subject.principal
        else:
            p.subject.is_principal = False
            p.subject = proof_b.subject
    else:
        p.subject.is_principal = False
        
        if(not proof_b.subject.is_principal):
            p.subject = Subject(name=Name(Principal(proof_b.subject.name.issuer), proof_b.subject.name.local_names))
        else:
            p.subject.name.local_names += proof_b.subject.principal.key
            
        p.subject.name.local_names += proof_a.subject.name.local_names[len(proof_b.name.local_names):]
        p.subject.name.issuer = Principal("composed")
        
    return p

# insert the proof into the hash tables
def insert(proof):
    key = (proof.name, proof.subject)
    
    print("insert() :: called")
        
    if key not in check:
        print("insert() :: Inserting proof with name:", proof.name.local_names, "->", proof.subject.principal.key if proof.subject.is_principal else proof.subject.name.local_names)
        check[key].add(proof)
        
        
        if not proof.subject.is_principal:
            # compatible_add_prefix(proof)
            prefix = return_prefix(proof.subject.name.local_names)
            
            for p in prefix:
                compatible[p].add(proof)
                
            for p in prefix:
                load_value(p)
            
            for p in prefix:
                for other_proof in value[p]:
                    insert(compose(proof, other_proof))
        else:
            str = proof.name.local_names
            
            value[str].add(proof)
            
            for comp_proof in compatible[str]:
                insert(compose(comp_proof, proof))

# load the certifcates 
def load_value(name):
    if name not in loaded_value:
        loaded_value.add(name)
        
        print(f"load_value() :: Loading certificates for {name}")
        
        for cert in cert_pool.values():
            if cert.name.local_names == name:
                insert(cert_to_proof(cert))

# name resolution algorithm
def name_resolution(name):
    print(f"\nname_resolution() :: Resolving name: {name}")
    
    load_value(name)
    return value[name]

# print the certificates in the rewrite format
def print_cert(cert):
    subject = (
        cert.subject.principal.key 
        if cert.subject.is_principal 
        else cert.subject.name.local_names
    )
    print(f"{cert.cert_type}: {cert.name.local_names} -> {subject}")

# prints the chain of certificates
def print_chain(proof):
    for cert_id in proof.cert_ids:
        print_cert(cert_pool[cert_id])

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python script.py <folder_path>")
        exit(1)
    
    folder_path = sys.argv[1]
    load_certificates_from_folder(folder_path)
    
    print("------------------------------ Certificates Loaded -------------------------------\n")
    
    for cert in cert_pool.values():
        print_cert(cert)
        
    print("\n----------------------------------------------------------------------------------\n")
    
    name_under_consideration = input("Enter the certificate ID to resolve: ")
    
    res = name_resolution(name_under_consideration)
    print(f"\nName Resolution for {name_under_consideration}:")
    
    print(len(res))
        
    
    for proof in res:
        print(proof.subject.principal.key if proof.subject.is_principal else ' '.join(proof.subject.name.issuer, proof.subject.name.local_names))
        print_chain(proof)
        print()
