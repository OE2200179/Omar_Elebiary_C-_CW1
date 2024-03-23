#include <iostream>
#include <string>
#include <fstream>
#include <openssl/evp.h>
#include <vector>
#include <cstring>

using namespace std;

const int MAX_PASSWORD_LENGTH = 256;
const int MAX_ENTRIES = 100;

struct Passwords {
    string application;
    string username;
    unsigned char password[MAX_PASSWORD_LENGTH];
};

vector<unsigned char> encryptPassword(const unsigned char* password, const int passwordLength, const string& key) {
    vector<unsigned char> iv(EVP_MAX_IV_LENGTH);
    vector<unsigned char> encrypted;

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, (const unsigned char*)key.c_str(), iv.data());

    int max_output_len = passwordLength + EVP_MAX_BLOCK_LENGTH;
    encrypted.resize(max_output_len);
    int encrypted_len;
    EVP_EncryptUpdate(ctx, encrypted.data(), &encrypted_len, password, passwordLength);
    int final_len;
    EVP_EncryptFinal_ex(ctx, encrypted.data() + encrypted_len, &final_len);

    EVP_CIPHER_CTX_free(ctx);

    encrypted.resize(encrypted_len + final_len);

    return encrypted;
}

vector<unsigned char> decryptPassword(const unsigned char* encryptedPassword, const int encryptedLength, const string& key) {
    vector<unsigned char> iv(EVP_MAX_IV_LENGTH);
    vector<unsigned char> decrypted;

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, (const unsigned char*)key.c_str(), iv.data());

    int max_output_len = encryptedLength + EVP_MAX_BLOCK_LENGTH;
    decrypted.resize(max_output_len);
    int decrypted_len;
    EVP_DecryptUpdate(ctx, decrypted.data(), &decrypted_len, encryptedPassword, encryptedLength);
    int final_len;
    EVP_DecryptFinal_ex(ctx, decrypted.data() + decrypted_len, &final_len);

    EVP_CIPHER_CTX_free(ctx);

    decrypted.resize(decrypted_len + final_len);

    return decrypted;
}

void savePasswordsToVault(const Passwords* new_pass, const int numEntries, const string& filename, const string& key) {
    ofstream file(filename, ios::binary);
    if (!file.is_open()) {
        cerr << "Error: Unable to open vault file for writing." << endl;
        return;
    }

    for (int i = 0; i < numEntries; ++i) {
        vector<unsigned char> encryptedPassword = encryptPassword(new_pass[i].password, strlen((char*)new_pass[i].password), key);
        file << new_pass[i].application << endl;
        file << new_pass[i].username << endl;
        file.write(reinterpret_cast<const char*>(encryptedPassword.data()), encryptedPassword.size());
        file << endl;
    }
    cout << "Passwords saved to vault: " << filename << endl;
}

void addPassword(Passwords* new_pass, int& entriesCount, const string& key) {
    Passwords entry;
    cout << "Enter the application: ";
    cin >> entry.application;

    for (int i = 0; i < entriesCount; ++i) {
        if (new_pass[i].application == entry.application) {
            cout << "Application already exists! Please choose a different application." << endl;
            return;
        }
    }

    cout << "Enter username: ";
    cin >> entry.username;
    cout << "Enter password: ";
    string password;
    cin >> password;
    strncpy((char*)entry.password, password.c_str(), MAX_PASSWORD_LENGTH);
    entriesCount++;
    new_pass[entriesCount - 1] = entry;
}

void getPassword(const Passwords* p_Database, const int numEntries, const string& application) {
    bool found = false;
    for (int i = 0; i < numEntries; ++i) {
        if (p_Database[i].application == application) {
            cout << "Username: " << p_Database[i].username << endl;
            cout << "Password: " << p_Database[i].password << endl;
            found = true;
            break;
        }
    }
    if (!found) {
        cout << "Password entry not found for this application: " << application << endl;
    }
}

void deletePassword(Passwords* new_pass, int& entriesCount, const string& application) {
    for (int i = 0; i < entriesCount; ++i) {
        if (new_pass[i].application == application) {
            for (int j = i; j < entriesCount - 1; ++j) {
                new_pass[j] = new_pass[j + 1];
            }
            entriesCount--;
            cout << "Password entry deleted successfully for this application: " << application << endl;
            return;
        }
    }
    cout << "Password entry not found for this application: " << application << endl;
}

void changePassword(Passwords* new_pass, const int entriesCount, const string& application, const string& key) {
    for (int i = 0; i < entriesCount; ++i) {
        if (new_pass[i].application == application) {
            cout << "Enter new password: ";
            string newPassword;
            cin >> newPassword;
            strncpy((char*)new_pass[i].password, newPassword.c_str(), MAX_PASSWORD_LENGTH);
            cout << "Password changed successfully for this application: " << application << endl;
            savePasswordsToVault(new_pass, entriesCount, "vault.bin", key);
            return;
        }
    }
    cout << "Password entry not found for this application: " << application << endl;
}

void displayAllPasswords(const Passwords* new_pass, const int numEntries) {
    if (numEntries == 0) {
        cout << "No passwords stored." << endl;
        return;
    }
    cout << "Stored Passwords:" << endl;
    for (int i = 0; i < numEntries; ++i) {
        cout << "Application: " << new_pass[i].application << ", Username: " << new_pass[i].username << ", Password: ";
        for (int j = 0; j < MAX_PASSWORD_LENGTH && new_pass[i].password[j] != '\0'; ++j) {
            cout << new_pass[i].password[j];
        }
        cout << endl;
    }
}

Passwords* loadPasswordsFromVault(const string& filename, const string& key, int& entriesCount) {
    Passwords* p_Database = new Passwords[MAX_ENTRIES];
    ifstream file(filename, ios::binary);
    if (!file.is_open()) {
        cerr << "Error: Unable to open vault file for reading." << endl;
        return nullptr;
    }

    string application, username, encryptedPassword;
    int index = 0;
    while (getline(file, application) && getline(file, username) && getline(file, encryptedPassword) && index < MAX_ENTRIES) {
        vector<unsigned char> decryptedPassword = decryptPassword(reinterpret_cast<const unsigned char*>(encryptedPassword.c_str()), encryptedPassword.size(), key);
        strncpy((char*)p_Database[index].password, (char*)decryptedPassword.data(), MAX_PASSWORD_LENGTH);
        p_Database[index].application = application;
        p_Database[index].username = username;
        index++;
    }
    entriesCount = index;
    cout << "Passwords loaded from vault: " << filename << endl;
    return p_Database;
}

int main() {
    Passwords* new_pass = new Passwords[MAX_ENTRIES];
    string key;
    cout << "Enter the encryption key: ";
    cin >> key;

    int entriesCount = 0;

    new_pass = loadPasswordsFromVault("vault.bin", key, entriesCount);

    while (true) {
        cout << "\nPassword Manager\n";
        cout << "1. Add Password\n";
        cout << "2. Retrieve Password\n";
        cout << "3. Delete Password\n";
        cout << "4. Change Password\n";
        cout << "5. Display All Passwords\n";
        cout << "6. Save Passwords to Vault\n";
        cout << "7. Exit\n";
        cout << "Enter your choice: ";

        int choice;
        cin >> choice;

        switch (choice) {
            case 1:
                addPassword(new_pass, entriesCount, key);
                break;
            case 2: {
                string application;
                cout << "Enter the application: ";
                cin >> application;
                getPassword(new_pass, entriesCount, application);
                break;
            }
            case 3: {
                string application;
                cout << "Enter the application to delete: ";
                cin >> application;
                deletePassword(new_pass, entriesCount, application);
                break;
            }
            case 4: {
                string application;
                cout << "Enter the application to change password: ";
                cin >> application;
                changePassword(new_pass, entriesCount, application, key);
                break;
            }
            case 5:
                displayAllPasswords(new_pass, entriesCount);
                break;
            case 6:
                savePasswordsToVault(new_pass, entriesCount, "vault.bin", key);
                break;
            case 7:
                cout << "Exiting...\n";
                delete[] new_pass;
                return 0;
            default:
                cerr << "Invalid choice! Please try again.\n";
        }
    }

    return 0;
}

