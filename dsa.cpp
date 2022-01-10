//g++ -g -O2 -std=c++11 -pthread -march=native test.cpp -o test -lntl -lgmp -lm -lssl -lcrypto

#include <iostream>
#include <NTL/ZZ.h>
#include <openssl/sha.h>
#include <cstring>
     

using namespace std;
using namespace NTL;

#define MESSAGE_SPACE 256

class DSA
{

private:
    ZZ p, q, a, b; // public key  
    ZZ d; // private key 

public:
    DSA() // Key Generation
    {
        q = GenPrime_ZZ(160); //q는 160bit 임의의 prime number
        ZZ l;
        
        do{
            l = RandomBits_ZZ(863);
        } while (NumBits(l) != 863);
        
        l = l << 1; 
        p = 2 * l * q + 1;

        do{
            RandomBits(l, 863);
            l << 1;
            p = 2 * l * q + 1;
        } while (NumBits(p) != 1024 || !ProbPrime(p));
        //p가 1024 bit의 prime number인지 확인
        //p가 prime number 라면 probprime(p) 값은 1

        do{
            ZZ g = RandomBnd(p);
            a = PowerMod(g,  (p-1)/q ,  p);    
        }while(a<2);
        //a 만들기  

        d = RandomBnd(q);
        b = PowerMod(a, d, p);
    }

    void signature(const ZZ M, ZZ & r, ZZ & s)
    {
        ZZ k;
        do
        {
            k = RandomBnd(q);
        } while (k == 0);

        r = AddMod(PowerMod(a, k, p), 0, q);
        s = MulMod(InvMod(k,q), AddMod(M, MulMod(r, d, q), q), q);
    }
    
    bool verification(const ZZ M, const ZZ r, const ZZ s)
    {
        ZZ w = InvMod(s,q);
        ZZ u1 = MulMod(w,M,q);
        ZZ u2 = MulMod(w,r,q);
        ZZ v = AddMod(MulMod(PowerMod(a,u1,p),PowerMod(b,u2,p),p),0,q);
        
        // cout << "v = " << v << endl;
        // cout << "r = " << r << endl;
        if(v == r) 
            return true;
        else
            return false;
    }
    
};


// void hextodecimal(const unsigned char * digest, const int length)
// {
//     ZZ num = ZZ(0);
//     ZZ count = ZZ(1);
    
//     for(int i = 1; i <=length ; i++)
//     {
//         if('A'<= digest[length - i] && digest[length - i] <= 'Z')
//             num += count * (digest[length - i] - 'A' + 10);

//         else
//             num += count * (digest[length - i] - '0');

//         count = count * 16;
//     }
//     cout << "num = " << num << endl;
// }

int main(int argc, char **argv)
{
    unsigned char msg[MESSAGE_SPACE]= "my name is hoo";
    unsigned char * digest = new unsigned char[SHA256_DIGEST_LENGTH];
    
    memset(digest, 0x00, SHA256_DIGEST_LENGTH);

    SHA256(msg, strlen((char*)msg), digest);

    cout << "msg = " << msg << endl;
    cout << "digest = ";
    for(int i = 0; i< SHA256_DIGEST_LENGTH; i++)
        printf("%02X", digest[i]);
    cout << endl;

    ZZ m = ZZFromBytes(digest, SHA256_DIGEST_LENGTH);
    cout << "m = " << m << endl;

    DSA dsa; 
    ZZ r, s;
    dsa.signature(m, r, s);

    if(dsa.verification(m,r,s))
        cout << "valid signature" << endl;
    else 
        cout << "invalid signature" << endl;
   
}


