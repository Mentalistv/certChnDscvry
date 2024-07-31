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
unordered_map<Name, unordered_set<Certificate>> check;
unordered_map<vector<string>, unordered_set<Certificate>> value;
unordered_map<vector<string>, unordered_set<Certificate>> compatible;

// hash table to store cert with id
unordered_map<string, Certificate> certPool;

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


// compose function

void compose(){
    // rewrite rules?? add proofs?? as cert id vector?? 
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
        for(auto x: prefixName){
            loadValue(x);
        }
        
        unordered_set<Certificate> setCertValue;

        for(auto x: prefixName){
            compose
        }
    }
    else{
        // for isPrincipal true
    }
}


// load value function

void loadValue(vector<string> name){
    if(!value.count(name))  value[name] = {};
}


// name resolution

vector<string> nameResolution(){

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

