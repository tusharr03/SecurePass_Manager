#include<iostream>
#include<vector>
#include<string>
#include<ctime>
#include<cstdlib>
#include<cstring>
#include<openssl/evp.h>

using namespace std;

class Credential {
    public:
    string serviceName;
    string username;
    string encryptedPassword;
    string notes;


    Credential(string service, string user, string password, string note="")
        :serviceName(service),username(user),encryptedPassword(password),notes(note){}
};

class Security{
    public:
    static string encryptPassword(const string& plaintext, unsigned char* key, unsigned char* iv);

    static string decryptPassword(const string& ciphertext, unsigned char* key, unsigned char* iv);

    static string generatePassword(int length);
};

class PasswordManager{
    private:
    vector<Credential> credentials;
    unsigned char key[32]="this_is_a_secret_key1234567890";
    unsigned char iv[16]="initialization";

    public:
    bool login();
    void addCredential();
    void viewCredentials();
    void searchCredential();
    void updateCredential();
    void deleteCredential();
};

bool PasswordManager::login(){
    string masterPassword = "admin123";
    string inputPassword;

    cout<<"Enter the master password: ";
    cin>>inputPassword;

    if(inputPassword==masterPassword){
        cout<<"Login Successful!\n";
        return true;
    }
    else{
        cout<<"Login Failed! Incorrect master password.\n";
        return false;
    }
}

string Security::generatePassword(int length){
    const char charset[]="abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*";
    const int charsetSize=sizeof(charset)-1;
    string Password;

    srand(time(0));
    for(int i=0;i<length;++i)
    {
        Password=Password+charset[rand()%charsetSize];
    }
    return Password;
}

string Security::encryptPassword(const string& plaintext, unsigned char* key, unsigned char* iv){
    EVP_CIPHER_CTX* ctx=EVP_CIPHER_CTX_new();
    if(!ctx) throw runtime_error("Failed to create encryption context");
    if(1!=EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(),NULL,key,iv))
    {
        throw runtime_error("Encryption Initialization Failed");
    }
    unsigned char ciphertext[1024];
    int len,ciphertextLen;
    
    if(1!=EVP_EncryptUpdate(ctx,ciphertext,&len, (unsigned char*)plaintext.c_str(),plaintext.length()))
    {
        throw runtime_error("Encryption Update Failed!");
    }
    ciphertextLen=len;

    if(1!=EVP_EncryptFinal_ex(ctx, ciphertext+len, &len))
    {
        throw runtime_error("Encryption Finalization Failed!");
    }
    ciphertextLen=ciphertextLen+len;

    EVP_CIPHER_CTX_free(ctx);

    return string((char*)ciphertext, ciphertextLen);
}

string Security::decryptPassword(const string& ciphertext, unsigned char* key, unsigned char* iv){
    EVP_CIPHER_CTX* ctx= EVP_CIPHER_CTX_new();
    if(!ctx){
        throw runtime_error("Failed to create decryption context");
    }

    if(1!=EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv)){
        throw runtime_error("Decryption Initialization Failed!");
    }

    unsigned char plaintext[1024];
    int len, plaintextLen;

    if(1!=EVP_DecryptUpdate(ctx, plaintext, &len, (unsigned char*)ciphertext.c_str(), ciphertext.length())){
        throw runtime_error("Decryption Update Failed!");
    }
    plaintextLen=len;

    if(1!=EVP_DecryptFinal_ex(ctx, plaintext+len, &len)){
        throw runtime_error("Decryption Finalization Failed!");
    }
    plaintextLen=plaintextLen+len;

    EVP_CIPHER_CTX_free(ctx);

    return string((char*)plaintext, plaintextLen);
}

void PasswordManager::addCredential(){
    string service, username, password, notes;
    cout<<"Enter service name: ";
    cin>>service;
    cout<<"Enter username: ";
    cin>>username;

    cout<<"Do you want to generate a random password? (y/n): ";
    char choice;
    cin>>choice;

    if(choice == 'y' || choice == 'Y'){
        password = Security::generatePassword(12);
        cout<<"Generated Password: "<<password<<endl;
    }
    else{
        cout<<"Enter Password: ";
        cin>>password;
    }

    cout<<"Enter Notes (optional): ";
    cin.ignore();
    getline(cin,notes);

    string encryptedPassword = Security::encryptPassword(password,key,iv);

    credentials.push_back(Credential(service, username, encryptedPassword, notes));
    cout<<"Credntial added successfully!\n";
}

void PasswordManager::viewCredentials(){
    if(credentials.empty()){
        cout<<"No credentials stored.\n";
        return;
    }

    cout<<"Stored Credentials:\n";
    for(const auto& cred : credentials){
        string decryptedPassword = Security::decryptPassword(cred.encryptedPassword,key,iv);
        cout<<"Service: "<<cred.serviceName
            <<"\nUsername: "<<cred.username
            <<"\nPassword: "<<decryptedPassword
            <<"\nNotes: "<<cred.notes
            <<"\n--------------------\n";
    }
}

void PasswordManager::searchCredential(){
    string query;
    cout<<"Enter the service name you want to search: ";
    cin>>query;

    bool found=false;
    for(const auto& cred : credentials){
        if(cred.serviceName==query){
            string decryptedPassword = Security::decryptPassword(cred.encryptedPassword, key, iv);
            cout<<"Service: "<<cred.serviceName
                <<"\nUsername: "<<cred.username
                <<"\nPassword: "<<decryptedPassword
                <<"\nNotes: "<<cred.notes
                <<"\n--------------------\n";
            found=true;
            break;
        }
    }
    if(!found){
        cout<<"Credential not found.\n";
    }
}

void PasswordManager::updateCredential(){
    string query;
    cout<<"Enter the service you want to update: ";
    cin>>query;
    for(auto& cred : credentials){
        if(cred.serviceName==query){
            string decryptedPassword = Security::decryptPassword(cred.encryptedPassword, key, iv);
            cout<<"Service: "<<cred.serviceName
                <<"\nUsername: "<<cred.username
                <<"\nPassword: "<<decryptedPassword
                <<"\nNotes: "<<cred.notes
                <<"\n--------------------\n";

            string newUsername, newPassword, newNotes;
            cout<<"Enter new username(or press enter to keep Current): ";
            cin.ignore();
            getline(cin,newUsername);

            cout<<"Enter new password(or press enter to keep Current): ";
            getline(cin,newPassword);

            cout<<"Enter new note(or press enter to keep Current): ";
            getline(cin,newNotes);

            if(!newUsername.empty())
            {
                cred.username=newUsername;
            }
            if(!newPassword.empty())
            {
                cred.encryptedPassword=Security::encryptPassword(newPassword,key,iv);
            }
            if(!newNotes.empty())
            {
                cred.notes=newNotes;
            }
            cout<<"Credential updated successfully!\n";
            return;
        }
    }
    cout<<"Credential not found.\n";
}

void PasswordManager::deleteCredential(){
    string query;
    cout<<"Enter the service name to delete: ";
    cin>>query;

    for(auto it=credentials.begin();it!=credentials.end();++it)
    {
        if(it->serviceName==query)
        {
            credentials.erase(it);
            cout<<"Credential deleted successfully!\n";
            return;
        }
    }
    cout<<"Credential not found.\n";
}

void displayMenu(){
    cout<<"Password Manager\n"
        <<"1.Add Credential\n"
        <<"2.View Credentials\n"
        <<"3.Generate Password\n"
        <<"4.Delete Credential\n"
        <<"5.Update Credential\n"
        <<"6.Search Credential\n"
        <<"7.Exit\n";
}

int main(){
    PasswordManager manager;
    Security set;
    int choice;
    string masterPassword;
    cout<<"Set Master Password: ";
    cin>>masterPassword;
    if(!manager.login()){
        cout<<"Access Denied. Exiting Program.\n";
        return 1;
    }

    do{
        displayMenu();
        cout<<"Enter your choice: ";
        cin>>choice;
        switch(choice){
            case 1:
                manager.addCredential();
                break;
            case 2:
                manager.viewCredentials();
                break;
            case 3:
                int length;
                cout<<"Enter the length of password: \n";
                cin>>length;
                set.generatePassword(length);
                break;
            case 4:
                manager.deleteCredential();
                break;
            case 5:
                manager.updateCredential();
                break;
            case 6:
                manager.searchCredential();
                break;
            case 7:
                cout<<"Exiting Password Manager. Goodbye!\n";
                break;
            default:
                cout<<"Invalid Choice. Please try again.\n";
        }
    }
    while(choice!=7);
    return 0;
}