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
        return certID == other.certID;
    }
};

struct Proof{
    Name name;
    Subject subject;
    vector<string> certIDs;
    int delegationBit;

    Proof() : delegationBit(0) {}
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

namespace std {
    template <>
    struct hash<Proof> {
        std::size_t operator()(const Proof& p) const {
            string temp = "";
            for(auto x: p.certIDs)  temp += x;

            return std::hash<string>()(temp);
        }
    };
}

void takeCertIp(Certificate* curr){
    string id;
    
    string ct;

    string pName;
    int nameSize;
    vector<string> lnName;

    int iPSubject;
    string pSubject = "";

    string pNameSubject = "";
    int lnSubjectSize;
    vector<string> lnSubject;

    int dBit = 0;


    cin>>id;
    curr->certID = id;

    cin>>ct;
    if(ct == "NAME")   curr->certType = NAME;
    else    curr->certType = AUTH;

    cin>>pName;
    curr->name.issuer.key = pName;

    cin>>nameSize;
    lnName.resize(nameSize);
    for(int i=0; i<nameSize; i++){
        cin>>lnName[i];
    }

    cin>>iPSubject;
    curr->subject.isPrincipal = iPSubject;

    if(iPSubject){
        cin>>pSubject;
        curr->subject.principal.key = pSubject;
    }
    else{
        cin>>pNameSubject;
        curr->subject.name.issuer.key = pNameSubject;

        cin>>lnSubjectSize;
        for(int i=0; i<lnSubjectSize; i++){
            cin>>lnSubject[i];
        }
    }

    cin>>dBit;
}


// hash tables
unordered_map<pair<Name, Subject>, unordered_set<Proof>> check;
unordered_map<vector<string>, unordered_set<Proof>> value;
unordered_map<vector<string>, unordered_set<Proof>> compatible;

// hash table to store cert with id
unordered_map<string, Certificate> certPool;

// set to keep track of already loaded values
unordered_set<vector<string>> loadedValue;

// additional table for unres
// unordered_map<pair<Name, Subject>, unordered_set<Certificate>> check;


// utility functions

void compatibleAddPrefix(Proof p){
    vector<string> temp;
    vector<string> name = p.subject.name.localNames;

    for(int i=0; i<name.size(); i++){
        temp.push_back(name[i]);

        compatible[temp].insert(p);
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

Proof* certToProof(Certificate c){
    Proof* p = new Proof;
a.push_back(43);
    if(a == b)  cout<<"dsd";
    p->certIDs.push_back(c.certID);

    p->delegationBit = c.delegationBit;

    p->name = c.name;

    p->subject = c.subject;

    return p;
}


// compose function

Proof compose(Proof a, Proof b){
    Proof* p = new Proof;

    p->name.issuer.key = "composed";
    p->name.localNames = a.name.localNames;

    if(a.subject.name.localNames == b.name.localNames){
        if(b.subject.isPrincipal){
            p->subject.isPrincipal = true;
            p->subject.principal = b.subject.principal;
        }
        else{
            p->subject.isPrincipal = false;
            p->subject.name = b.subject.name;
        }
    }
    else{
        p->subject.isPrincipal = false;

        p->subject.name.localNames = b.subject.name.localNames;

        int nameSize = b.name.localNames.size();
        int subjectSize = a.subject.name.localNames.size();
        
        for(int i=nameSize; i<subjectSize; i++)
            p->subject.name.localNames.push_back(a.subject.name.localNames[i]);
    }

    p->delegationBit = a.delegationBit;

    for(auto x: a.certIDs)
        p->certIDs.push_back(x);

    for(auto x: b.certIDs)
        p->certIDs.push_back(x);

    return *p;
}


// insert function

vector<string> insert(Proof p){
    if(!check.count({p.name, p.subject})){
        // add in check
        check[{p.name, p.subject}].insert(p);

        // add in comaptible
        if(!p.subject.isPrincipal){
            compatibleAddPrefix(p);

            vector<vector<string>> prefixName = returnPrefix(p.subject.name.localNames);

            unordered_set<Proof> setProofValue;

            for(auto x: prefixName){
                for(auto y: value[x])
                    setProofValue.insert(y);
            }

            for(auto x: setProofValue)
                insert(compose(x, p));
        }


        else{
            // for isPrincipal true

            // add in value
            value[p.name.localNames].insert(p);

            unordered_set<Proof> setProofCompatible = compatible[p.name.localNames];

            for(auto x: setProofCompatible)
                insert(compose(x, p));            
        }
    }
}


// load value function

void loadValue(vector<string> name){
    // pick useful certs :: make proofs :: insert them :: return value[name] ::
    if(!loadedValue.count(name)){
        loadedValue.insert(name);

        for(auto x: certPool){
            if(x.second.name.localNames == name)
        }

    }
}


// name resolution

vector<string> nameResolution(vector<string> name){

}


int main() {
    int numberCert;
    cin>>numberCert;

    for(int i=0; i<numberCert; i++){
        Certificate *newCert = new Certificate;
        takeCertIp(newCert);

        if(certPool.count(newCert->certID))
            certPool[newCert->certID] = *newCert;
    }



    return 0;
}

