#include <iostream>
#include <unordered_map>
#include <unordered_set>
#include <vector>
#include <string>
#include <functional>
#include <fstream>
#include <filesystem>

using namespace std;
namespace fs = std::filesystem;

// Data Types
enum CertType {
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

    bool operator==(const Subject& other) const {
        return (isPrincipal == other.isPrincipal && principal == other.principal) || (name == other.name);
    }
};

struct Certificate {
    string certID;
    CertType certType;
    Name name;
    Subject subject;
    int delegationBit;

    bool operator==(const Certificate& other) const {
        return certID == other.certID;
    }
};

struct Proof {
    Name name;
    Subject subject;
    vector<string> certIDs;
    int delegationBit;

    Proof() : delegationBit(0) {}

    bool operator==(const Proof& other) const {
        return name == other.name && subject == other.subject && certIDs == other.certIDs && delegationBit == other.delegationBit;
    }
};

// Specialization of std::hash
namespace std {
    template <>
    struct hash<pair<Name, Subject>> {
        std::size_t operator()(const pair<Name, Subject>& p) const {
            size_t h1 = hash<string>()(p.first.issuer.key);
            size_t h2 = 0;
            for (const auto& s : p.first.localNames) {
                h2 ^= hash<string>()(s) + 0x9e3779b9 + (h2 << 6) + (h2 >> 2);
            }
            size_t h3 = hash<string>()(p.second.isPrincipal ? p.second.principal.key : p.second.name.issuer.key);
            size_t h4 = 0;
            for (const auto& s : p.second.name.localNames) {
                h4 ^= hash<string>()(s) + 0x9e3779b9 + (h4 << 6) + (h4 >> 2);
            }
            return h1 ^ (h2 << 1) ^ (h3 << 2) ^ (h4 << 3);
        }
    };

    template <>
    struct hash<vector<string>> {
        size_t operator()(const vector<string>& p) const {
            string temp;
            for (const auto& x : p) temp += x;
            return hash<string>()(temp);
        }
    };

    template <>
    struct hash<Certificate> {
        size_t operator()(const Certificate& cert) const {
            return hash<string>()(cert.certID);
        }
    };

    template <>
    struct hash<Proof> {
        size_t operator()(const Proof& p) const {
            string temp;
            for (const auto& x : p.name.localNames) temp += x;
            temp += p.certIDs[0];
            for (const auto& x : p.subject.name.localNames) temp += x;
            return hash<string>()(temp);
        }
    };
}

// Hash Tables
unordered_map<pair<Name, Subject>, unordered_set<Proof>> check;
unordered_map<vector<string>, unordered_set<Proof>> value;
unordered_map<vector<string>, unordered_set<Proof>> compatible;
unordered_map<string, Certificate> certPool;
unordered_set<vector<string>> loadedValue;

// Input Functions
void takeCertIpFromFile(Certificate* curr, const string& filePath) {
    ifstream file(filePath);
    if (!file.is_open()) {
        cerr << "Could not open the file: " << filePath << endl;
        return;
    }

    string id, ct, pName, pSubject, pNameSubject;
    int nameSize, iPSubject, lnSubjectSize, dBit;
    vector<string> lnName, lnSubject;

    file >> id;
    curr->certID = id;

    file >> ct;
    curr->certType = (ct == "NAME") ? NAME : AUTH;

    file >> pName;
    curr->name.issuer.key = pName;

    file >> nameSize;
    lnName.resize(nameSize);
    for (int i = 0; i < nameSize; i++) file >> lnName[i];
    curr->name.localNames = lnName;

    file >> iPSubject;
    curr->subject.isPrincipal = iPSubject;

    if (iPSubject) {
        file >> pSubject;
        curr->subject.principal.key = pSubject;
    } else {
        file >> pNameSubject;
        curr->subject.name.issuer.key = pNameSubject;

        file >> lnSubjectSize;
        lnSubject.resize(lnSubjectSize);
        for (int i = 0; i < lnSubjectSize; i++) file >> lnSubject[i];

        curr->subject.name.localNames = lnSubject;
    }

    file >> dBit;
    curr->delegationBit = dBit;

    file.close();
}

void processCertificatesFromFolder(const string& folderPath) {
    for (const auto& entry : fs::directory_iterator(folderPath)) {
        if (entry.is_regular_file()) {
            Certificate cert;
            takeCertIpFromFile(&cert, entry.path().string());
            certPool[cert.certID] = cert;
        }
    }
}

// Utility Functions
void compatibleAddPrefix(const Proof& p) {
    vector<string> temp;
    vector<string> name = p.subject.name.localNames;

    for (size_t i = 0; i < name.size(); i++) {
        temp.push_back(name[i]);
        compatible[temp].insert(p);
    }
}

vector<vector<string>> returnPrefix(const vector<string>& name) {
    vector<vector<string>> res;
    vector<string> temp;

    for (size_t i = 0; i < name.size(); i++) {
        temp.push_back(name[i]);
        res.push_back(temp);
    }

    return res;
}

Proof certToProof(const Certificate& c) {
    Proof p;
    p.certIDs.push_back(c.certID);
    p.delegationBit = c.delegationBit;
    p.name = c.name;
    p.subject = c.subject;
    return p;
}

Proof compose(const Proof& a, const Proof& b) {
    Proof p;
    p.name.issuer.key = "composed";
    p.name.localNames = a.name.localNames;

    if (a.subject.name.localNames == b.name.localNames) {
        if (b.subject.isPrincipal) {
            p.subject.isPrincipal = true;
            p.subject.principal = b.subject.principal;
        } else {
            p.subject.isPrincipal = false;
            p.subject.name = b.subject.name;
        }
    } else{
        p.subject.isPrincipal = false;

        if(!b.subject.isPrincipal) p.subject.name.localNames = b.subject.name.localNames;
        else    p.subject.name.localNames.push_back(b.subject.principal.key);

        int nameSize = b.name.localNames.size();
        int subjectSize = a.subject.name.localNames.size();
        
        for(int i=nameSize; i<subjectSize; i++)
            p.subject.name.localNames.push_back(a.subject.name.localNames[i]);
    }

    p.delegationBit = a.delegationBit;
    p.certIDs.insert(p.certIDs.end(), a.certIDs.begin(), a.certIDs.end());
    p.certIDs.insert(p.certIDs.end(), b.certIDs.begin(), b.certIDs.end());

    return p;
}

void loadValue(const vector<string>& name);

void insert(const Proof& p) {
    if (!check.count({p.name, p.subject})) {
        check[{p.name, p.subject}].insert(p);

        if (!p.subject.isPrincipal) {
            compatibleAddPrefix(p);

            vector<vector<string>> prefixName = returnPrefix(p.subject.name.localNames);
            for (const auto& x : prefixName) loadValue(x);

            unordered_set<Proof> setProofValue;
            for (const auto& x : prefixName) {
                for (const auto& y : value[x]) setProofValue.insert(y);
            }

            for (const auto& x : setProofValue) insert(compose(p, x));
        } else {
            value[p.name.localNames].insert(p);

            unordered_set<Proof> setProofCompatible = compatible[p.name.localNames];
            for (const auto& x : setProofCompatible) insert(compose(x, p));
        }
    }
}

void loadValue(const vector<string>& name) {
    if (!loadedValue.count(name)) {
        loadedValue.insert(name);

        unordered_set<Proof> setCertToProof;
        for (const auto& x : certPool) {
            if (x.second.name.localNames == name) {
                setCertToProof.insert(certToProof(x.second));
            }
        }

        for (const auto& x : setCertToProof) insert(x);
    }
}

unordered_set<Proof> nameResolution(const vector<string>& name) {
    loadValue(name);
    return value[name];
}


void printCert(Certificate a){
    // cout<<a.certID<<endl;
    
    if(a.certType == NAME)  cout<<"NAME: ";
    else    cout<<"AUTH: ";

    for(auto x: a.name.localNames)  cout<<x<<" ";
    cout<<"-> ";

    if(a.subject.isPrincipal)   cout<<a.subject.principal.key<<endl;
    else{
        for(auto x: a.subject.name.localNames)  cout<<x<<" ";
        cout<<endl;
    }

    // cout<<a.delegationBit<<endl;
}

void printChain(Proof p){
    for(auto x: p.certIDs)  printCert(certPool[x]);
}

int main(int argc, char* argv[]) {
    string folderPath = "/home/varn/Downloads/certChnDscvry/certs/testcase" + to_string(1);
    processCertificatesFromFolder(folderPath);

    for(auto x: certPool){
        // cout<<x.first<<" "<<x.second.subject.isPrincipal<<endl;
        printCert(x.second);
    }
    cout<<endl;

    string certUnderConsideration = "cert2";
    unordered_set<Proof> res = nameResolution(certPool[certUnderConsideration].name.localNames);

    cout<<"--------------------------------------------------------------------------------"<<endl<<endl;

    cout<<"Name Resolution for ";
    for(auto x: certPool[certUnderConsideration].name.localNames)   cout<<x<<" ";
    cout<<":"<<endl<<endl;
    for(auto x: res){
        cout<<x.subject.principal.key<<endl;
        printChain(x);
        cout<<endl;
    }

    return 0;
}

