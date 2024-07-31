#include <iostream>
#include <unordered_map>
#include <unordered_set>
#include <vector>
#include <string>
#include <functional>

using namespace std;


// datatypes

enum CertType{
    NAME,
    AUTH
};

struct Principal {
    string key;

    bool operator==(const Principal& other) const {
        return key == other.key;
    }
};

struct Name {
    Principal issuer;
    vector<string> localNames;

    bool operator==(const Name& other) const {
        return issuer == other.issuer && localNames == other.localNames;
    }
};

struct Subject {
    bool isPrincipal;
    Principal principal;
    Name name;

    Subject() : isPrincipal(false) {}
    Subject(Principal p) : isPrincipal(true), principal(p) {}
    Subject(Name n) : isPrincipal(false), name(n) {}
};

struct Certificate {
    string certID;
    CertType certType;
    Name name;
    Subject subject;
    int delegationBit;

    bool operator==(const Certificate& other) const {
        return id == other.id && name == other.name;
    }
};

// Specialize std::hash for Certificate
namespace std {
    template <>
    struct hash<Certificate> {
        std::size_t operator()(const Certificate& cert) const {
            return std::hash<string>()(cert.certID);
        }
    };
}

void takeCertIp(Certificate* curr){
    string id = "";
    
    string ct = "";

    string pName = "";
    vector<string> lnName = {};

    bool iPSubject = false;
    string pSubject = "";

    string pNameSubject = "";
    vector<string> lnSubject = {};

    int dBit = 0;

    // MOD
    // take input and add to all hash table

}


// hash tables
unordered_map<Name, unordered_set<Certificate>> check;
unordered_map<vector<string>, unordered_set<Certificate>> value;
unordered_map<vector<string>, unordered_set<Certificate>> compatible;

// hash table to store cert with id
unordered_map<string, unordered_set<Certificate>> certPool;

// additional table for unres
// unordered_map<pair<Name, Subject>, unordered_set<Certificate>> check;


// utility functions

void compatibleAddPrefix(Certificate cert){
    vector<string> temp;
    vector<string> name = cert.subject.name.localNames;

    for(int i=0; i<name.size(); i++){
        temp.push_back(name[i]);

        compatible[temp].insert(cert);
    }
}

vector<vector<string>> returnPrefix(vector<string> name){
    vector<vector<string>> res;
    vector<string> temp;

    for(int i=0; i<name.size(); i++){
        temp.push_back(name[i]);
        res.push_back(temp);
    }

    return res;    
}


// insert function

vector<string> insertCert(Certificate newCert){
    if(check.count(newCert.name)){
        // add in check
        check[newCert.name].insert(newCert);

        // add in comaptible
        if(!newCert.subject.isPrincipal){
            compatibleAddPrefix(newCert);
        }

        // add in value

        vector<vector<string>> prefixName = returnPrefix(newCert.subject.name.localNames);

        value[newCert.name.localNames].insert(newCert);
        for(int i=0; i<prefixName.size(); i++){
            loadValue(prefixName[i]);
        }
        
        // unordered_set<Certificate> setCertValue;

    }
}


// load value function

void loadValue(vector<string> name){
    if(!value.count(name))  value[name] = {};
}


// name resolution

vector<string> nameResolution(){

}

















// Function to resolve names
void resolveName(const string& name, 
                 const unordered_map<string, vector<Certificate>>& certs, 
                 unordered_set<string>& resolved) {
    unordered_set<string> toResolve = {name};

    while (!toResolve.empty()) {
        string current = *toResolve.begin();
        toResolve.erase(current);

        if (resolved.find(current) == resolved.end()) {     // or if(!resolved.count(current))
            resolved.insert(current);

            if (certs.find(current) != certs.end()) {       // or if(certs.count(current))
                for (const Certificate& cert : certs.at(current)) {
                    if (resolved.find(cert.subject) == resolved.end()) {
                        toResolve.insert(cert.subject);
                    }
                }
            }
        }
    }
}

// Function to unresolve names
void unresolveName(const string& name, 
                   const unordered_map<string, vector<Certificate>>& certs, 
                   unordered_set<string>& resolved) {
    unordered_set<string> toUnresolve = {name};

    while (!toUnresolve.empty()) {
        string current = *toUnresolve.begin();
        toUnresolve.erase(current);

        if (resolved.find(current) != resolved.end()) {
            resolved.erase(current);

            if (certs.find(current) != certs.end()) {
                for (const Certificate& cert : certs.at(current)) {
                    if (resolved.find(cert.subject) != resolved.end()) {
                        toUnresolve.insert(cert.subject);
                    }
                }
            }
        }
    }
}















int main() {
    vector<Certificate> certificates = {
        {"Alice", "Bob"},
        {"Bob", "Carol"},
        {"Carol", "Dave"},
        {"Eve", "Frank"}
    };

    unordered_map<string, vector<Certificate>> certs;
    for (const Certificate& cert : certificates) {
        certs[cert.issuer].push_back(cert);
    }

    unordered_set<string> resolved;


    // resolve

    string startName = "Alice";
    resolveName(startName, certs, resolved);

    cout << "Resolved names for " << startName << ": ";
    for (const string& name : resolved) {
        cout << name << " ";
    }
    cout << endl;


    // unresolve

    startName = "Bob";
    unresolveName(startName, certs, resolved);

    cout << "Resolved names after unresolving " << startName << ": ";
    for (const string& name : resolved) {
        cout << name << " ";
    }
    cout << endl;

    return 0;
}
