#include "applicationlayer.h"
#include <QDebug>
#include <cstring>
#include <cctype>

struct TrieNode{
    TrieNode* son[26];
    bool has_value;
    TrieNode(){
        for(int i=0;i<26;++i)son[i]=nullptr;
        has_value = false;
    }
    ~TrieNode(){
        for(int i=0;i<26;++i){
            if(son[i]!=nullptr)delete son[i];
        }
    }
};

struct Trie{
    TrieNode* root;

    Trie(){
        root = new TrieNode();
    }
    ~Trie(){
        delete root;
    }
    void insert(const char* s,int len){
        TrieNode *now = root;
        for(int i=0;i<len;++i){
            int index= s[i]-'A';
            if(now->son[index]==nullptr)now->son[index]=new TrieNode();
            now = now->son[index];
        }
        now->has_value = true;
    }

    bool query(const char* s,int len){
        TrieNode *now = root;
        for(int i=0;i<len;++i){
            int index = s[i] - 'A';
            if(now->son[index]==nullptr)return false;
            now = now->son[index];
        }
        return now->has_value;
    }
};

const int FTP_keys_num = 11;
const char* FTP_keys[] = {
    "ABOR","LIST","PASS","QUIT","RETR","STOR","SYST","TYPE","USER","AUTH","PWD"
};

bool checkFTPproto(const u_char *packet, int len){
    if(len < 4) return false;
    if(std::isdigit(packet[0]) && std::isdigit(packet[1]) && std::isdigit(packet[2]))return true;

    static bool is_init = false;
    static Trie trie;

    if(!is_init){
        is_init = true;
        for(int i=0;i<FTP_keys_num;++i){
            trie.insert(FTP_keys[i], std::strlen(FTP_keys[i]));
        }
    }

    int key_len = 0;
    while (key_len<len && packet[key_len]>='A' && packet[key_len]<='Z')++key_len;
    return trie.query((const char*)packet, key_len);
}

bool checkHTTPproto(const u_char *packet, int len){
    if(len < 7) return false;
    // HTTP Response
    if(packet[0]=='H'&&packet[1]=='T'&&packet[2]=='T'&&packet[3]=='P')return true;
    // HTTP request, method=GET、POST、HEAD、PUT、DELETE、OPTIONS、TRACE、CONNECT
    if(packet[0]=='G' && packet[1]=='E' && packet[2]=='T')return true;
    if(packet[0]=='P' && packet[1]=='O' &&packet[2]=='S' && packet[3]=='T')return true;
    if(packet[0]=='H' && packet[1]=='E' &&packet[2]=='A' && packet[3]=='D')return true;
    if(packet[0]=='P' && packet[1]=='U' &&packet[2]=='T')return true;
    if(packet[0]=='D' && packet[1]=='E' &&packet[2]=='L' && packet[3]=='E' && packet[4]=='T' && packet[5]=='E')return true;
    if(packet[0]=='O' && packet[1]=='P' &&packet[2]=='T' && packet[3]=='I' && packet[4]=='O' && packet[5]=='N' && packet[6]=='S')return true;
    if(packet[0]=='T' && packet[1]=='R' &&packet[2]=='A' && packet[3]=='C' && packet[4]=='E')return true;
    if(packet[0]=='C' && packet[1]=='O' &&packet[2]=='N' && packet[3]=='N' && packet[5]=='E' && packet[6]=='C' && packet[7]=='T')return true;
    return false;
}
