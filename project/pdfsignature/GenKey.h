#pragma once
#include <podofo/podofo.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/x509v3.h>
#include <openssl/pem.h>
#include <openssl/sha.h>
#include <openssl/bio.h>
#include <openssl/err.h>

enum keytype
{
    RSA_key,
    DSA_key
};

EVP_PKEY* generatePubKey(int _bits, const keytype& key);
bool CreateX509Cert(X509** _x509, EVP_PKEY** _pkey, int _serial, int _days);
bool write_to_disk(EVP_PKEY* pkey, X509* x509);
EVP_PKEY* LoadKey(const char* pkey_file);
X509* LoadCert(const char* cert_file);