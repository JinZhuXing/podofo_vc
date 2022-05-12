#include "pch.h"
#include "GenKey.h"

EVP_PKEY* generatePubKey(int _bits, const keytype& key) {
    EVP_PKEY* pKey = EVP_PKEY_new();

    if (pKey == nullptr) {
        throw std::runtime_error("Cannot create evp public key");
        return nullptr;
    }

    if (key == RSA_key) {
        RSA* rsa = RSA_generate_key(
            _bits,          // so bit can tim
            RSA_F4,         // 0x10001
            nullptr,        // callback de xem tien do
            nullptr         // callback argument
        );

        if (!EVP_PKEY_assign_RSA(pKey, rsa)) {
            throw std::runtime_error("Unable to generate 2048-bit RSA key.");
            EVP_PKEY_free(pKey);
            return nullptr;
        }
    }
    else {
        DSA* dsa = DSA_new();
        if (DSA_generate_parameters_ex(dsa, 1024, nullptr, 0, nullptr, nullptr, nullptr) && DSA_generate_key(dsa)) {
            EVP_PKEY_assign_DSA(pKey, dsa);
        }
        else {
            DSA_free(dsa);
            return nullptr;
        }
    }

    return pKey;
}

bool CreateX509Cert(X509 **_x509, EVP_PKEY **_pkey, int _serial, int _days) {
    X509_NAME *name;
    X509 *cert = nullptr;
    EVP_PKEY *pKey = *_pkey;

    if ((_x509 == nullptr) || (*_x509 == nullptr)) {
        if ((cert = X509_new()) == nullptr) {
            throw std::runtime_error("Cannot create x509 certificate");
            return false;
        }
    }
    else {
        cert = *_x509;
    }

    // setup x509 cert
    ASN1_INTEGER_set(X509_get_serialNumber(cert), _serial);   // lay serial number

    // lay thoi gian 
    X509_gmtime_adj(X509_get_notBefore(cert), 0);
    X509_gmtime_adj(X509_get_notAfter(cert), (long)60 * 60 * 24 * _days);

    // chon public key
    X509_set_pubkey(cert, pKey);

    // lay ten cua subjectname cert cho issuer
    name = X509_get_subject_name(cert);
    X509_NAME_add_entry_by_txt(name, "C", MBSTRING_ASC, (unsigned char*)"VN", -1, -1, 0);
    X509_set_issuer_name(cert, name);

    // ky cho certificate do voi public key cua minh
    if (!X509_sign(cert, pKey, EVP_sha256())) {
        throw std::runtime_error("Cannot sign certificate");
        X509_free(cert);
        return false;
    }

    *_pkey = pKey;
    *_x509 = cert;
    return true;
}

bool write_to_disk(EVP_PKEY* pkey, X509* x509) {
    /* Open the PEM file for writing the key to disk. */
    FILE* pkey_file;
    CreateDirectory(L"keys", nullptr);
    if (fopen_s(&pkey_file, "keys/key.pem", "wb") != 0) {
        std::cerr << "Unable to open \"key.pem\" for writing." << std::endl;
        return false;
    }

    /* Write the key to disk. */
    int ret = PEM_write_PKCS8PrivateKey(pkey_file, pkey, nullptr, nullptr, 0, NULL, NULL);
    fclose(pkey_file);

    if (!ret) {
        std::cerr << "Unable to write private key to disk." << std::endl;
        return false;
    }

    // open and write cert to disk
    FILE* x509_file;
    fopen_s(&x509_file, "keys/cert.pem", "wb");
    if (!x509_file) {
        std::cerr << "Unable to open \"cert.pem\" for writing." << std::endl;
        return false;
    }
    ret = PEM_write_X509(x509_file, x509);
    fclose(x509_file);

    if (!ret) {
        std::cerr << "Unable to write certificate to disk." << std::endl;
        return false;
    }

    return true;
}

EVP_PKEY *LoadKey(const char* pkey_file) {
    EVP_PKEY* key;

    if (!pkey_file || !*pkey_file) {
        throw std::invalid_argument("No input file");
    }

    FILE* fp = NULL;
	fopen_s(&fp, pkey_file, "r");
    key = PEM_read_PrivateKey(fp, nullptr, nullptr, nullptr);
    if (key == nullptr) {
        throw std::invalid_argument("Cannot read the key file");
        return nullptr;
    }
    return key;
}

X509* LoadCert(const char* cert_file) {
    X509* x509;
    if (!cert_file || !*cert_file) {
        throw std::invalid_argument("No input file");
    }

    FILE* fp;
	fopen_s(&fp, cert_file, "r");
    x509 = PEM_read_X509(fp, nullptr, nullptr, nullptr);
    return x509;
}