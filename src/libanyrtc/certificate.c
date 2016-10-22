#include <openssl/err.h>
#include <openssl/rsa.h>
#include <openssl/bn.h>
#include <openssl/objects.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/asn1.h>
#include <openssl/asn1t.h>
#include <openssl/crypto.h>
#include <openssl/bio.h>
#include <openssl/pem.h>
#include <string.h>
#include <limits.h>
#include <anyrtc.h>
#include "certificate.h"
#include "utils.h"

#define DEBUG_MODULE "certificate"
#define DEBUG_LEVEL 7
#include <re_dbg.h>

/*
 * Print and flush the OpenSSL error queue.
 */
static int print_openssl_error(
        char const * const message,
        size_t const length,
        void* const arg
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
        uint_least32_t const modulus_length
) {
    enum anyrtc_code error = ANYRTC_CODE_UNKNOWN_ERROR;
    EVP_PKEY* key = NULL;
    RSA* rsa = NULL;
    BIGNUM* bn = NULL;

    // Check arguments
    if (!keyp || modulus_length > INT_MAX) {
        return ANYRTC_CODE_INVALID_ARGUMENT;
    }

    // Create an empty EVP_PKEY structure
    key = EVP_PKEY_new();
    if (!key) {
        DEBUG_WARNING("Could not create EVP_PKEY structure\n");
        goto out;
    }

    // Initialise RSA structure
    rsa = RSA_new();
    if (!rsa) {
        DEBUG_WARNING("Could not initialise RSA structure\n");
        goto out;
    }

    // Allocate BIGNUM
    // TODO: Use BN_secure_new when OpenSSL version is >= 1.1.0
    bn = BN_new();
    if (!bn) {
        DEBUG_WARNING("Could not allocate BIGNUM\n");
        goto out;
    }

    // Generate RSA key pair and store it in the RSA structure
    BN_set_word(bn, RSA_F4);
    if (!RSA_generate_key_ex(rsa, modulus_length, bn, NULL)) {
        DEBUG_WARNING("Could not generate RSA key pair\n");
        goto out;
    }

    // Store the generated RSA key pair in the EVP_PKEY structure
    if (!EVP_PKEY_set1_RSA(key, rsa)) {
        DEBUG_WARNING("Could not assign RSA key pair to EVP_PKEY structure\n");
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
        DEBUG_WARNING("Could not create EVP_PKEY structure\n");
        goto out;
    }

    // Get NID of named curve
    curve_group_nid = OBJ_txt2nid(named_curve);
    if (curve_group_nid == NID_undef) {
        DEBUG_WARNING("Could not determine group NID of named curve: %s\n", named_curve);
        goto out;
    }

    // Initialise EC structure for named curve
    ecc = EC_KEY_new_by_curve_name(curve_group_nid);
    if (!ecc) {
        DEBUG_WARNING("Could not initialise EC structure for named curve\n");
        goto out;
    }

    // This is needed to correctly sign the certificate
    EC_KEY_set_asn1_flag(ecc, OPENSSL_EC_NAMED_CURVE);

    // Generate the ECC key pair and store it in the EC structure
    if (!EC_KEY_generate_key(ecc)) {
        DEBUG_WARNING("Could not generate ECC key pair\n");
        goto out;
    }

    // Store the generated ECC key pair in the EVP_PKEY structure
    if (!EVP_PKEY_assign_EC_KEY(key, ecc)) {
        DEBUG_WARNING("Could not assign ECC key pair to EVP_PKEY structure\n");
        goto out;
    }

    // Done
    error = ANYRTC_CODE_SUCCESS;

out:
    if (error) {
        if (ecc) {
            EC_KEY_free(ecc);
        }
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
 * Get the corresponding EVP_MD* for signing the certificate.
 */
static EVP_MD const * const get_sign_function(
        enum anyrtc_certificate_sign_algorithm type
) {
    switch (type) {
        case ANYRTC_CERTIFICATE_SIGN_ALGORITHM_SHA256:
            return EVP_sha256();
        case ANYRTC_CERTIFICATE_SIGN_ALGORITHM_SHA384:
            return EVP_sha384();
        case ANYRTC_CERTIFICATE_SIGN_ALGORITHM_SHA512:
            return EVP_sha512();
        default:
            return NULL;
    }
}

/*
 * Generates a self-signed certificate.
 * Caller must call `X509_free(*certificatep)` when done.
 */
static enum anyrtc_code generate_self_signed_certificate(
        X509** const certificatep, // de-referenced
        EVP_PKEY* const key,
        char* const common_name,
        uint_least32_t const valid_until,
        enum anyrtc_certificate_sign_algorithm const sign_algorithm
) {
    enum anyrtc_code error = ANYRTC_CODE_UNKNOWN_ERROR;
    X509* certificate = NULL;
    X509_NAME* name = NULL;
    EVP_MD const* sign_function;

    // Check arguments
    if (!certificatep || !key || !common_name || valid_until > LONG_MAX) {
        return ANYRTC_CODE_INVALID_ARGUMENT;
    }

    // Get sign function
    sign_function = get_sign_function(sign_algorithm);
    if (!sign_function) {
        return ANYRTC_CODE_INVALID_ARGUMENT;
    }

    // Allocate and initialise x509 structure
    certificate = X509_new();
    if (!certificate) {
        DEBUG_WARNING("Could not initialise x509 structure\n");
        goto out;
    }

    // Set x509 version
    // TODO: Why '2'?
    if (!X509_set_version(certificate, 2)) {
        DEBUG_WARNING("Could not set x509 version\n");
        goto out;
    }

    // Set the serial number randomly (doesn't need to be unique as we are self-signing)
    if (!ASN1_INTEGER_set(X509_get_serialNumber(certificate), rand_u32())) {
        DEBUG_WARNING("Could not set x509 serial number\n");
        goto out;
    }

    // Create an empty X509_NAME structure
    name = X509_NAME_new();
    if (!name) {
        DEBUG_WARNING("Could not create x509_NAME structure\n");
        goto out;
    }

    // Set common name field on X509_NAME structure
    if (!X509_NAME_add_entry_by_txt(
            name, "CN", MBSTRING_ASC, (uint8_t*) common_name,
            (int) strlen(common_name), -1, 0)) {
        DEBUG_WARNING("Could not apply common name (%s) on certificate\n", common_name);
        goto out;
    }

    // Set issuer and subject name
    if (!X509_set_issuer_name(certificate, name)
            || !X509_set_subject_name(certificate, name)) {
        DEBUG_WARNING("Could not set issuer name on certificate\n");
        goto out;
    }

    // Certificate is valid from now (-1 day) until whatever has been provided in parameters
    if (!X509_gmtime_adj(X509_get_notBefore(certificate), -3600 * 24)
            || !X509_gmtime_adj(X509_get_notAfter(certificate), (long) valid_until)) {
        DEBUG_WARNING("Could not apply lifetime range to certificate\n");
        goto out;
    }

    // Set public key of certificate
    if (!X509_set_pubkey(certificate, key)) {
        DEBUG_WARNING("Could not set public key to certificate\n");
        goto out;
    }

    // Sign the certificate
    if (!X509_sign(certificate, key, sign_function)) {
        DEBUG_WARNING("Could not sign the certificate\n");
        goto out;
    }

    // Done
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
 * Destructor for existing certificate options.
 */
static void anyrtc_certificate_options_destroy(
        void* const arg
) {
    struct anyrtc_certificate_options* const options = arg;

    // Dereference
    mem_deref(options->named_curve);
    mem_deref(options->common_name);
}

/*
 * Create certificate options.
 *
 * All arguments but `key_type` are optional. Sane and safe default
 * values will be applied.
 *
 * If `common_name` is `NULL` the default common name will be applied.
 * If `valid_until` is `0` the default certificate lifetime will be
 * applied.
 * If the key type is `ECC` and `named_curve` is `NULL`, the default
 * named curve will be used.
 * If the key type is `RSA` and `modulus_length` is `0`, the default
 * amount of bits will be used. The same applies to the
 * `sign_algorithm` if it has been set to `NONE`.
 */
enum anyrtc_code anyrtc_certificate_options_create(
        struct anyrtc_certificate_options** const optionsp, // de-referenced
        enum anyrtc_certificate_key_type const key_type,
        char* common_name, // nullable, copied
        uint32_t valid_until,
        enum anyrtc_certificate_sign_algorithm sign_algorithm,
        char* named_curve, // nullable, copied, ignored for RSA
        uint_least32_t modulus_length // ignored for ECC
) {
    struct anyrtc_certificate_options* options;
    enum anyrtc_code error = ANYRTC_CODE_SUCCESS;

    // Check arguments
    if (!optionsp || valid_until > LONG_MAX || modulus_length > INT_MAX) {
        return ANYRTC_CODE_INVALID_ARGUMENT;
    }

    // Set defaults
    if (!common_name) {
        common_name = anyrtc_default_certificate_options.common_name;
    }
    if (!valid_until) {
        valid_until = anyrtc_default_certificate_options.valid_until;
    }
    // Check sign algorithm
    if (sign_algorithm == ANYRTC_CERTIFICATE_SIGN_ALGORITHM_NONE) {
        sign_algorithm = anyrtc_default_certificate_options.sign_algorithm;
    }

    // Set defaults depending on key type
    switch (key_type) {
        case ANYRTC_CERTIFICATE_KEY_TYPE_RSA:
            // Unset ECC vars
            named_curve = NULL;

            // Prevent user from being stupid
            if (modulus_length < ANYRTC_MODULUS_LENGTH_MIN) {
                modulus_length = anyrtc_default_certificate_options.modulus_length;
            }

            break;

        case ANYRTC_CERTIFICATE_KEY_TYPE_EC:
            // Unset RSA vars
            modulus_length = 0;

            // Set default named curve (if required)
            if (!named_curve) {
                named_curve = anyrtc_default_certificate_options.named_curve;
            }

            break;

        default:
            return ANYRTC_CODE_INVALID_STATE;
    }

    // Allocate
    options = mem_zalloc(sizeof(struct anyrtc_certificate_options),
                         anyrtc_certificate_options_destroy);
    if (!options) {
        return ANYRTC_CODE_NO_MEMORY;
    }

    // Set fields/copy
    options->key_type = key_type;
    if (common_name) {
        error = anyrtc_strdup(&options->common_name, common_name);
        if (error) {
            goto out;
        }
    }
    options->valid_until = valid_until;
    options->sign_algorithm = sign_algorithm;
    if (named_curve) {
        error = anyrtc_strdup(&options->named_curve, named_curve);
        if (error) {
            goto out;
        }
    }
    options->modulus_length = modulus_length;

out:
    if (error) {
        mem_deref(options);
    } else {
        // Set pointer
        *optionsp = options;
    }
    return error;
}

/*
 * Destructor for existing certificate.
 */
static void anyrtc_certificate_destroy(
        void* const arg
) {
    struct anyrtc_certificate* const certificate = arg;

    // Free
    if (certificate->certificate) {
        X509_free(certificate->certificate);
    }
    if (certificate->key) {
        EVP_PKEY_free(certificate->key);
    }
}

/*
 * Create and generate a self-signed certificate.
 *
 * Sane and safe default options will be applied if `options` is
 * `NULL`.
 */
enum anyrtc_code anyrtc_certificate_generate(
        struct anyrtc_certificate** const certificatep,
        struct anyrtc_certificate_options* options // nullable
) {
    struct anyrtc_certificate* certificate;
    enum anyrtc_code error;

    // Check arguments
    if (!certificatep) {
        return ANYRTC_CODE_INVALID_ARGUMENT;
    }

    // Default options
    if (!options) {
        options = &anyrtc_default_certificate_options;
    }

    // Allocate
    certificate = mem_zalloc(sizeof(struct anyrtc_certificate), anyrtc_certificate_destroy);
    if (!certificate) {
        return ANYRTC_CODE_NO_MEMORY;
    }

    // Generate key pair
    switch (options->key_type) {
        case ANYRTC_CERTIFICATE_KEY_TYPE_RSA:
            error = generate_key_rsa(&certificate->key, options->modulus_length);
            break;
        case ANYRTC_CERTIFICATE_KEY_TYPE_EC:
            error = generate_key_ecc(&certificate->key, options->named_curve);
            break;
        default:
            return ANYRTC_CODE_INVALID_STATE;
    }
    if (error) {
        goto out;
    }

    // Generate certificate
    error = generate_self_signed_certificate(
            &certificate->certificate, certificate->key,
            options->common_name, options->valid_until, options->sign_algorithm);
    if (error) {
        goto out;
    }

    // Set key type
    certificate->key_type = options->key_type;

out:
    if (error) {
        mem_deref(certificate);
    } else {
        // Set pointer
        *certificatep = certificate;
    }
    return error;
}

/*
 * Copy a certificate.
 * References the x509 certificate and private key.
 */
enum anyrtc_code anyrtc_certificate_copy(
        struct anyrtc_certificate** const certificatep, // de-referenced
        struct anyrtc_certificate* const source_certificate
) {
    enum anyrtc_code error = ANYRTC_CODE_UNKNOWN_ERROR;
    struct anyrtc_certificate *certificate;

    // Check arguments
    if (!certificatep || !source_certificate) {
        return ANYRTC_CODE_INVALID_ARGUMENT;
    }

    // Allocate
    certificate = mem_zalloc(sizeof(struct anyrtc_certificate), anyrtc_certificate_destroy);
    if (!certificate) {
        return ANYRTC_CODE_NO_MEMORY;
    }

    // Increment reference count of certificate and private key, copy the pointers
    // TODO: Use X509_up_ref when OpenSSL version is >= 1.1.0
    if (!CRYPTO_add(&source_certificate->certificate->references, 1, CRYPTO_LOCK_X509)) {
        goto out;
    }
    certificate->certificate = source_certificate->certificate;
    // TODO: Use EVP_PKEY_up_ref when OpenSSL version is >= 1.1.0
    if (!CRYPTO_add(&source_certificate->key->references, 1, CRYPTO_LOCK_EVP_PKEY)) {
        goto out;
    }
    certificate->key = source_certificate->key;
    certificate->key_type = source_certificate->key_type;

    // Done
    error = ANYRTC_CODE_SUCCESS;

out:
    if (error) {
        mem_deref(certificate);
    } else {
        // Set pointer
        *certificatep = certificate;
    }
    return error;
}

static enum anyrtc_code what_to_encode(
        enum anyrtc_certificate_encode const to_encode,
        bool* encode_certificatep,  // de-referenced
        bool* encode_keyp  // de-referenced
) {
    *encode_certificatep = false;
    *encode_keyp = false;

    // What to encode?
    switch (to_encode) {
        case ANYRTC_CERTIFICATE_ENCODE_CERTIFICATE:
            *encode_certificatep = true;
            break;
        case ANYRTC_CERTIFICATE_ENCODE_PRIVATE_KEY:
            *encode_keyp = true;
            break;
        case ANYRTC_CERTIFICATE_ENCODE_BOTH:
            *encode_certificatep = true;
            *encode_keyp = true;
            break;
        default:
            return ANYRTC_CODE_INVALID_ARGUMENT;
    }

    // Done
    return ANYRTC_CODE_SUCCESS;
}

/*
 * Get PEM of the certificate and/or the private key if requested.
 * *pemp will NOT be null-terminated!
 */
enum anyrtc_code anyrtc_certificate_get_pem(
        char** const pemp,  // de-referenced
        size_t* const pem_lengthp,  // de-referenced
        struct anyrtc_certificate* const certificate,
        enum anyrtc_certificate_encode const to_encode
) {
    bool encode_certificate;
    bool encode_key;
    enum anyrtc_code error;
    BIO* bio = NULL;
    char* pem = NULL;
    size_t length;

    // Check arguments
    if (!pemp || !certificate) {
        return ANYRTC_CODE_INVALID_ARGUMENT;
    }

    // What to encode?
    error = what_to_encode(to_encode, &encode_certificate, &encode_key);
    if (error) {
        return error;
    }
    error = ANYRTC_CODE_UNKNOWN_ERROR;

    // Create bio structure
    // TODO: Use BIO_s_secmem when OpenSSL version is >= 1.1.0
    bio = BIO_new(BIO_s_mem());

    // Write certificate
    if (encode_certificate && !PEM_write_bio_X509(bio, certificate->certificate)) {
        goto out;
    }

    // Write private key (if requested)
    if (encode_key && !PEM_write_bio_PrivateKey(bio, certificate->key, NULL, NULL, 0, 0, NULL)) {
        goto out;
    }

    // Allocate buffer
    length = bio->num_write;
    pem = mem_alloc(length, NULL);

    // Copy to buffer
    if (length > INT_MAX) {
        return ANYRTC_CODE_UNKNOWN_ERROR;
    }
    if (BIO_read(bio, pem, (int) length) < length) {
        goto out;
    }

    // Done
    error = ANYRTC_CODE_SUCCESS;

out:
    if (bio) {
        BIO_free(bio);
    }
    if (error) {
        mem_deref(pem);
    } else {
        // Set pointers
        *pemp = pem;
        *pem_lengthp = length;
    }
    return error;
}

/*
 * Get DER of the certificate and/or the private key if requested.
 * *derp will NOT be null-terminated!
 */
enum anyrtc_code anyrtc_certificate_get_der(
        uint8_t** const derp,  // de-referenced
        size_t* const der_lengthp,  // de-referenced
        struct anyrtc_certificate* const certificate,
        enum anyrtc_certificate_encode const to_encode
) {
    bool encode_certificate;
    bool encode_key;
    enum anyrtc_code error;
    int length_certificate = 0;
    int length_key = 0;
    size_t length;
    uint8_t* der = NULL;
    uint8_t* der_i2d;

    // Check arguments
    if (!derp || !certificate) {
        return ANYRTC_CODE_INVALID_ARGUMENT;
    }

    // What to encode?
    error = what_to_encode(to_encode, &encode_certificate, &encode_key);
    if (error) {
        return error;
    }
    error = ANYRTC_CODE_UNKNOWN_ERROR;

    // Allocate buffer
    if (encode_certificate) {
        length_certificate = i2d_X509(certificate->certificate, NULL);
        if (length_certificate < 1) {
            return ANYRTC_CODE_UNKNOWN_ERROR;
        }
    }
    if (encode_key) {
        length_key = i2d_PrivateKey(certificate->key, NULL);
        if (length_key < 1) {
            return ANYRTC_CODE_UNKNOWN_ERROR;
        }
    }
    length = (size_t) (length_certificate + length_key);
    der = mem_alloc(length, NULL);
    der_i2d = der;

    // Write certificate
    if (encode_certificate && i2d_X509(certificate->certificate, &der_i2d) < length_certificate) {
        goto out;
    }

    // Write private key (if requested)
    if (encode_key && i2d_PrivateKey(certificate->key, &der_i2d) < length_key) {
        goto out;
    }

    // Done
    error = ANYRTC_CODE_SUCCESS;

out:
    if (error) {
        mem_deref(der);
    } else {
        // Set pointers
        *derp = der;
        *der_lengthp = length;
    }
    return error;
}
