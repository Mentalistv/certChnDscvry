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

struct Proof{
    Name name;
    Subject subject;
    vector<string> certIDs;
    int delegationBit;

    Proof() : delegationBit(0) {}

    bool operator==(const Proof& other) const {
        return name == other.name && subject == other.subject && certIDs == other.certIDs && delegationBit == other.delegationBit;
    }
};

// Specialization of std::hash for pair<Name, Subject>
namespace std {
    template <>
    struct hash<pair<Name, Subject>> {
        std::size_t operator()(const pair<Name, Subject>& p) const {
            string temp = "";
            for (const auto& x : p.first.localNames)
                temp += x;
            for (const auto& x : p.second.name.localNames)
                temp += x;
            return std::hash<string>()(temp);
        }
    };
}

namespace std {
    template <>
    struct hash<vector<string>> {
        std::size_t operator()(const vector<string>& p) const {
            string temp = "";
            for (const auto& x : p)
                temp += x;
            return std::hash<string>()(temp);
        }
    };
}


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

            for(auto x: p.name.localNames)
                temp += x;

            temp += p.certIDs[0];

            for(auto x: p.subject.name.localNames)
                temp += x;

            return std::hash<string>()(temp);
        }
    };
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
// unordered_map<pair<Name, Subject>, unordered_set<Certificate>> ;


// input function

void takeCertIpFromFile(Certificate* curr, const string& filePath) {
    ifstream file(filePath);
    if (!file.is_open()) {
        cerr << "Could not open the file: " << filePath << endl;
        return;
    }

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

    file >> id;
    curr->certID = id;

    file >> ct;
    if (ct == "NAME") {
        curr->certType = NAME;
    } else {
        curr->certType = AUTH;
    }

    file >> pName;
    curr->name.issuer.key = pName;

    file >> nameSize;
    lnName.resize(nameSize);
    for (int i = 0; i < nameSize; i++) {
        file >> lnName[i];
    }
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
        for (int i = 0; i < lnSubjectSize; i++) {
            file >> lnSubject[i];
        }

        curr->subject.name.localNames = lnSubject;
    }

    file >> dBit;

    file.close();
}

void printCert(Certificate a){
    cout<<a.certID<<endl;
    
    if(a.certType == NAME)  cout<<"NAME"<<endl;
    else    cout<<"AUTH"<<endl;

    cout<<a.name.issuer.key<<endl;
    for(auto x: a.name.localNames)  cout<<x<<" ";
    cout<<endl;

    cout<<a.subject.isPrincipal<<endl;
    if(a.subject.isPrincipal)   cout<<a.subject.principal.key<<endl;
    else{
        cout<<a.subject.name.issuer.key<<endl;
        // cout<<"size: "<<a.subject.name.localNames.size()<<endl;
        for(auto x: a.subject.name.localNames)  cout<<x<<" ";
        cout<<endl;
    }

    cout<<a.delegationBit<<endl;
    cout<<"------------------------------------"<<endl;
}

void processCertificatesFromFolder(const string& folderPath) {
    for (const auto& entry : fs::directory_iterator(folderPath)) {
        if (entry.is_regular_file()) {
            Certificate cert;
            takeCertIpFromFile(&cert, entry.path().string());
            certPool[cert.certID] = cert;

            // Process the certificate (for example, print it or store it in a list)
            // cout << "Processed certificate ID: " << cert.certID << endl;
        }
    }
}


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

Proof certToProof(Certificate c){
    Proof* p = new Proof;

    p->certIDs.push_back(c.certID);

    p->delegationBit = c.delegationBit;

    p->name = c.name;

    p->subject = c.subject;

    return *p;
}


// // compose function

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


void loadValue(vector<string> name);

// // insert function

void insert(Proof p){
    if(!check.count({p.name, p.subject})){
        // add in check
        check[{p.name, p.subject}].insert(p);

        cout<<endl<<"insert: ";
        for(auto x: p.name.localNames)
            cout<<x<<" ";
        cout<<":: ";
        for(auto x: p.subject.name.localNames)  cout<<x<<" ";
        cout<<p.subject.principal.key;
        cout<<endl;

        // add in comaptible
        if(!p.subject.isPrincipal){
            compatibleAddPrefix(p);

            vector<vector<string>> prefixName = returnPrefix(p.subject.name.localNames);
            
            // loadValue(p.subject.name.localNames);

            for(auto x: prefixName) 
                loadValue(x);

            unordered_set<Proof> setProofValue;

            for(auto x: prefixName){
                for(auto y: value[x])
                    setProofValue.insert(y);
            }

            for(auto x: setProofValue)
                insert(compose(p, x));
        }


        else{
            // for isPrincipal true
            
            cout<<"value: ";
            for(auto x: p.name.localNames)  cout<<x<<" ";
            cout<<": "<<p.subject.principal.key<<endl;

            // add in value
            value[p.name.localNames].insert(p);

            unordered_set<Proof> setProofCompatible = compatible[p.name.localNames];

            for(auto x: setProofCompatible)
                insert(compose(x, p));            
        }
    }
}


// // load value function

void loadValue(vector<string> name){
    // pick useful certs :: make proofs :: insert them :: return value[name] ::
    if(!loadedValue.count(name)){
        loadedValue.insert(name);

        unordered_set<Proof> setCertToProof;

        for(auto x: certPool){
            if(x.second.name.localNames == name){
                cout<<"loadvalue: ";
                for(auto x: name)   cout<<x<<" ";
                cout<<":: ";
                for(auto x: x.second.subject.name.localNames)   cout<<x<<" ";
                cout<<x.second.subject.principal.key;
                cout<<endl;

                setCertToProof.insert(certToProof(x.second));
            }
        }

        for(auto x: setCertToProof)
            insert(x);
    }
}


// // name resolution

unordered_set<Proof> nameResolution(vector<string> name){
    loadValue(name);

    return value[name];
}


int main(int argc, char* argv[]) {
    // string temp = argv[0];

    string folderPath = "/home/varn/Downloads/MTP/code/certChnDscvry/certs/testcase" + to_string(2);
    processCertificatesFromFolder(folderPath);

    for(auto x: certPool){
        // cout<<x.first<<" "<<x.second.subject.isPrincipal<<endl;
        printCert(x.second);
    }
    cout<<endl;

    string certUnderConsideration = "cert7";

    unordered_set<Proof> res = nameResolution(certPool[certUnderConsideration].name.localNames);


    cout<<"table size: ";
    cout<<check.size()<<" ";
    cout<<value.size()<<" ";
    cout<<compatible.size()<<endl;

    cout<<endl<<"name to be resolved: ";
    for(auto x: certPool[certUnderConsideration].name.localNames){
        cout<<x<<" ";
    }
    cout<<endl;
    
    cout<<"name resolution result: ";
    for(auto x: res){
        cout<<x.subject.principal.key<<" ";
    }
    cout<<endl;

    // for(auto x: value){
    //     cout<<x.second.size()<<endl;
    // }

    // cout<<"loaded vlaue: "<<loadedValue.size()<<endl;
    // for(auto x: loadedValue){
    //     for(auto y: x)
    //         cout<<y<<" ";
    //     cout<<endl;
    // }
    // cout<<endl;


    return 0;
}

