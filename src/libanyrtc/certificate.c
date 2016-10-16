#include <openssl/err.h>
#include <openssl/rsa.h>
#include <openssl/bn.h>
#include <openssl/objects.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/asn1.h>
#include <openssl/asn1t.h>
#include <string.h>
#include <anyrtc.h>
#include "certificate.h"

#define DEBUG_MODULE "certificate"
#define DEBUG_LEVEL 7
#include <re_dbg.h>

/*
 * Print and flush the OpenSSL error queue.
 */
static int print_openssl_error(
        char const * const message,
        size_t const length,
        void* arg
) {
    (void) arg;
    DEBUG_WARNING("%b", message, length);

    // 1 to continue outputting the error queue
    return 1;
}

/*
 * Generates an n-bit RSA key pair.
 * Caller must call `EVP_PKEY_free(*keyp)` when done.
 */
static enum anyrtc_code generate_key_rsa(
        EVP_PKEY** const keyp, // de-referenced
        int const rsa_key_bits
) {
    enum anyrtc_code error = ANYRTC_CODE_UNKNOWN_ERROR;
    EVP_PKEY* key = NULL;
    RSA* rsa = NULL;
    BIGNUM* bn = NULL;

    // Check arguments
    if (!keyp) {
        return ANYRTC_CODE_INVALID_ARGUMENT;
    }

    // Create an empty EVP_PKEY structure
    key = EVP_PKEY_new();
    if (!key) {
        goto out;
    }

    // Initialise RSA structure
    rsa = RSA_new();
    if (!rsa) {
        goto out;
    }

    // Allocate BIGNUM
    // TODO: Use BN_secure_new when version is >= 1.1.0
    bn = BN_new();
    if (!bn) {
        goto out;
    }

    // Generate RSA key pair and store it in the RSA structure
    BN_set_word(bn, RSA_F4);
    if (!RSA_generate_key_ex(rsa, rsa_key_bits, bn, NULL)) {
        goto out;
    }

    // Store the generated RSA key pair in the EVP_PKEY structure
    if (!EVP_PKEY_set1_RSA(key, rsa)) {
        goto out;
    }

    // Done
    error = ANYRTC_CODE_SUCCESS;

out:
    if (rsa) {
        RSA_free(rsa);
    }
    if (bn) {
        BN_free(bn);
    }
    if (error) {
        if (key) {
            EVP_PKEY_free(key);
        }
        ERR_print_errors_cb(print_openssl_error, NULL);
    } else {
        *keyp = key;
    }
    return error;
}

/*
 * Generates an ECC key pair.
 * Caller must call `EVP_PKEY_free(*keyp)` when done.
 */
static enum anyrtc_code generate_key_ecc(
        EVP_PKEY** const keyp, // de-referenced
        char* const named_curve
) {
    enum anyrtc_code error = ANYRTC_CODE_UNKNOWN_ERROR;
    EVP_PKEY* key = NULL;
    int curve_group_nid;
    EC_KEY* ecc = NULL;

    // Check arguments
    if (!keyp || !named_curve) {
        return ANYRTC_CODE_INVALID_ARGUMENT;
    }

    // Create an empty EVP_PKEY structure
    key = EVP_PKEY_new();
    if (!key) {
        goto out;
    }

    // Get NID of named curve
    curve_group_nid = OBJ_txt2nid(named_curve);
    if (curve_group_nid == NID_undef) {
        goto out;
    }

    // Initialise EC structure for named curve
    ecc = EC_KEY_new_by_curve_name(curve_group_nid);
    if (!ecc) {
        goto out;
    }

    // This is needed to correctly sign the certificate
    EC_KEY_set_asn1_flag(ecc, OPENSSL_EC_NAMED_CURVE);

    // Generate the ECC key pair and store it in the EC structure
    if (EC_KEY_generate_key(ecc)) {
        goto out;
    }

    // Store the generated ECC key pair in the EVP_PKEY structure
    if (!EVP_PKEY_assign_EC_KEY(key, ecc)) {
        goto out;
    }

    // Done
    error = ANYRTC_CODE_SUCCESS;

out:
    if (ecc) {
        EC_KEY_free(ecc);
    }
    if (error) {
        if (key) {
            EVP_PKEY_free(key);
        }
        ERR_print_errors_cb(print_openssl_error, NULL);
    } else {
        *keyp = key;
    }
    return error;
}

/*
 * Generates a self-signed certificate.
 * Caller must call `X509_free(*certificatep)` when done.
 */
static enum anyrtc_code generate_self_signed_certificate(
        X509** const certificatep, // de-referenced
        EVP_PKEY* const key,
        char* const common_name,
        unsigned long valid_until
) {
    enum anyrtc_code error = ANYRTC_CODE_UNKNOWN_ERROR;
    X509* certificate = NULL;
    X509_NAME* name = NULL;

    // Check arguments
    if (!certificatep || !key || !common_name) {
        return ANYRTC_CODE_INVALID_ARGUMENT;
    }

    // Allocate and initialise x509 structure
    certificate = X509_new();
    if (!certificate) {
        goto out;
    }

    // Set x509 version
    // TODO: Why '2'?
    if (!X509_set_version(certificate, 2)) {
        goto out;
    }

    // Set the serial number randomly (doesn't need to be unique as we are self-signing)
    if (!ASN1_INTEGER_set(X509_get_serialNumber(certificate), rand_u32())) {
        goto out;
    }

    // Create an empty X509_NAME structure
    name = X509_NAME_new();
    if (!name) {
        goto out;
    }

    // Set common name field on X509_NAME structure
    if (!X509_NAME_add_entry_by_txt(
            name, "CN", MBSTRING_ASC, (unsigned char*) common_name,
            (int) strlen(common_name), -1, 0)) {
        goto out;
    }

    // Set issuer and subject name
    if (!X509_set_issuer_name(certificate, name)
            || !X509_set_subject_name(certificate, name)) {
        goto out;
    }

    // Certificate is valid from now (-1 day) until whatever has been provided in parameters
    if (!X509_gmtime_adj(X509_get_notBefore(certificate), -3600 * 24)
            || !X509_gmtime_adj(X509_get_notAfter(certificate), (long) valid_until)) {
        goto out;
    }

    // Set public key of certificate
    if (!X509_set_pubkey(certificate, key)) {
        goto out;
    }

    // Sign the certificate with our own key using SHA-256
    if (!X509_sign(certificate, key, EVP_sha256())) {
        goto out;
    }

    // No error
    error = ANYRTC_CODE_SUCCESS;

out:
    if (name) {
        X509_NAME_free(name);
    }
    if (error) {
        if (certificate) {
            X509_free(certificate);
        }
        ERR_print_errors_cb(print_openssl_error, NULL);
    } else {
        *certificatep = certificate;
    }
    return error;
}

/*
 * Create a certificate
 */
enum anyrtc_code anyrtc_certificate_create(

) {
    // TODO: Continue here
    return ANYRTC_CODE_NOT_IMPLEMENTED;
}
