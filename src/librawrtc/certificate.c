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
#include <rawrtc.h>
#include "certificate.h"
#include "utils.h"

#define DEBUG_MODULE "certificate"
//#define RAWRTC_DEBUG_MODULE_LEVEL 7 // Note: Uncomment this to debug this module only
#include "debug.h"

/*
 * Print and flush the OpenSSL error queue.
 */
static int print_openssl_error(
        char const * message,
        size_t length,
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
static enum rawrtc_code generate_key_rsa(
        EVP_PKEY** const keyp, // de-referenced
        uint_fast32_t const modulus_length
) {
    enum rawrtc_code error = RAWRTC_CODE_UNKNOWN_ERROR;
    EVP_PKEY* key = NULL;
    RSA* rsa = NULL;
    BIGNUM* bn = NULL;

    // Check arguments
    if (!keyp) {
        return RAWRTC_CODE_INVALID_ARGUMENT;
    }
#if (UINT_FAST32_MAX > INT_MAX)
    if (modulus_length > INT_MAX) {
        return RAWRTC_CODE_INVALID_ARGUMENT;
    }
#endif

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
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
    bn = BN_secure_new();
#else
    bn = BN_new();
#endif
    if (!bn) {
        DEBUG_WARNING("Could not allocate BIGNUM\n");
        goto out;
    }

    // Generate RSA key pair and store it in the RSA structure
    BN_set_word(bn, RSA_F4);
    if (!RSA_generate_key_ex(rsa, (int) modulus_length, bn, NULL)) {
        DEBUG_WARNING("Could not generate RSA key pair\n");
        goto out;
    }

    // Store the generated RSA key pair in the EVP_PKEY structure
    if (!EVP_PKEY_set1_RSA(key, rsa)) {
        DEBUG_WARNING("Could not assign RSA key pair to EVP_PKEY structure\n");
        goto out;
    }

    // Done
    error = RAWRTC_CODE_SUCCESS;

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
static enum rawrtc_code generate_key_ecc(
        EVP_PKEY** const keyp, // de-referenced
        char* const named_curve
) {
    enum rawrtc_code error = RAWRTC_CODE_UNKNOWN_ERROR;
    EVP_PKEY* key = NULL;
    int curve_group_nid;
    EC_KEY* ecc = NULL;

    // Check arguments
    if (!keyp || !named_curve) {
        return RAWRTC_CODE_INVALID_ARGUMENT;
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
    error = RAWRTC_CODE_SUCCESS;

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
 * Generates a self-signed certificate.
 * Caller must call `X509_free(*certificatep)` when done.
 */
static enum rawrtc_code generate_self_signed_certificate(
        X509** const certificatep, // de-referenced
        EVP_PKEY* const key,
        char* const common_name,
        uint_fast32_t const valid_until,
        enum rawrtc_certificate_sign_algorithm const sign_algorithm
) {
    enum rawrtc_code error = RAWRTC_CODE_UNKNOWN_ERROR;
    X509* certificate = NULL;
    X509_NAME* name = NULL;
    EVP_MD const* sign_function;

    // Check arguments
    if (!certificatep || !key || !common_name) {
        return RAWRTC_CODE_INVALID_ARGUMENT;
    }
#if (UINT_FAST32_MAX > LONG_MAX)
    if (valid_until > LONG_MAX) {
        return RAWRTC_CODE_INVALID_ARGUMENT;
    }
#endif

    // Get sign function
    sign_function = rawrtc_get_sign_function(sign_algorithm);
    if (!sign_function) {
        return RAWRTC_CODE_INVALID_ARGUMENT;
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
    error = RAWRTC_CODE_SUCCESS;

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
static void rawrtc_certificate_options_destroy(
        void* arg
) {
    struct rawrtc_certificate_options* const options = arg;

    // Un-reference
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
enum rawrtc_code rawrtc_certificate_options_create(
        struct rawrtc_certificate_options** const optionsp, // de-referenced
        enum rawrtc_certificate_key_type const key_type,
        char* common_name, // nullable, copied
        uint_fast32_t valid_until,
        enum rawrtc_certificate_sign_algorithm sign_algorithm,
        char* named_curve, // nullable, copied, ignored for RSA
        uint_fast32_t modulus_length // ignored for ECC
) {
    struct rawrtc_certificate_options* options;
    enum rawrtc_code error = RAWRTC_CODE_SUCCESS;

    // Check arguments
    if (!optionsp) {
        return RAWRTC_CODE_INVALID_ARGUMENT;
    }
#if (UINT_FAST32_MAX > LONG_MAX)
    if (valid_until > LONG_MAX) {
        return RAWRTC_CODE_INVALID_ARGUMENT;
    }
#endif
#if (UINT_FAST32_MAX > INT_MAX)
    if (modulus_length > INT_MAX) {
        return RAWRTC_CODE_INVALID_ARGUMENT;
    }
#endif

    // Set defaults
    if (!common_name) {
        common_name = rawrtc_default_certificate_options.common_name;
    }
    if (!valid_until) {
        valid_until = rawrtc_default_certificate_options.valid_until;
    }

    // Check sign algorithm/set default
    // Note: We say 'no' to SHA1 intentionally
    // Note: SHA-384 and SHA-512 are currently not supported (needs to be added to libre)
    switch (sign_algorithm) {
        case RAWRTC_CERTIFICATE_SIGN_ALGORITHM_NONE:
            sign_algorithm = rawrtc_default_certificate_options.sign_algorithm;
            break;
        case RAWRTC_CERTIFICATE_SIGN_ALGORITHM_SHA256:
            break;
        default:
            return RAWRTC_CODE_INVALID_ARGUMENT;
    }

    // Set defaults depending on key type
    switch (key_type) {
        case RAWRTC_CERTIFICATE_KEY_TYPE_RSA:
            // Unset ECC vars
            named_curve = NULL;

            // Prevent user from being stupid
            if (modulus_length < RAWRTC_MODULUS_LENGTH_MIN) {
                modulus_length = rawrtc_default_certificate_options.modulus_length;
            }

            break;

        case RAWRTC_CERTIFICATE_KEY_TYPE_EC:
            // Unset RSA vars
            modulus_length = 0;

            // Set default named curve (if required)
            if (!named_curve) {
                named_curve = rawrtc_default_certificate_options.named_curve;
            }

            break;

        default:
            return RAWRTC_CODE_INVALID_STATE;
    }

    // Allocate
    options = mem_zalloc(sizeof(*options), rawrtc_certificate_options_destroy);
    if (!options) {
        return RAWRTC_CODE_NO_MEMORY;
    }

    // Set fields/copy
    options->key_type = key_type;
    if (common_name) {
        error = rawrtc_strdup(&options->common_name, common_name);
        if (error) {
            goto out;
        }
    }
    options->valid_until = valid_until;
    options->sign_algorithm = sign_algorithm;
    if (named_curve) {
        error = rawrtc_strdup(&options->named_curve, named_curve);
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
static void rawrtc_certificate_destroy(
        void* arg
) {
    struct rawrtc_certificate* const certificate = arg;

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
enum rawrtc_code rawrtc_certificate_generate(
        struct rawrtc_certificate** const certificatep,
        struct rawrtc_certificate_options* options // nullable
) {
    struct rawrtc_certificate* certificate;
    enum rawrtc_code error;

    // Check arguments
    if (!certificatep) {
        return RAWRTC_CODE_INVALID_ARGUMENT;
    }

    // Default options
    if (!options) {
        options = &rawrtc_default_certificate_options;
    }

    // Allocate
    certificate = mem_zalloc(sizeof(*certificate), rawrtc_certificate_destroy);
    if (!certificate) {
        return RAWRTC_CODE_NO_MEMORY;
    }

    // Generate key pair
    switch (options->key_type) {
        case RAWRTC_CERTIFICATE_KEY_TYPE_RSA:
            error = generate_key_rsa(&certificate->key, options->modulus_length);
            break;
        case RAWRTC_CERTIFICATE_KEY_TYPE_EC:
            error = generate_key_ecc(&certificate->key, options->named_curve);
            break;
        default:
            return RAWRTC_CODE_INVALID_STATE;
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
enum rawrtc_code rawrtc_certificate_copy(
        struct rawrtc_certificate** const certificatep, // de-referenced
        struct rawrtc_certificate* const source_certificate
) {
    enum rawrtc_code error = RAWRTC_CODE_UNKNOWN_ERROR;
    struct rawrtc_certificate *certificate;

    // Check arguments
    if (!certificatep || !source_certificate) {
        return RAWRTC_CODE_INVALID_ARGUMENT;
    }

    // Allocate
    certificate = mem_zalloc(sizeof(*certificate), rawrtc_certificate_destroy);
    if (!certificate) {
        return RAWRTC_CODE_NO_MEMORY;
    }

    // Increment reference count of certificate and private key, copy the pointers
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
    if (!X509_up_ref(source_certificate->certificate)) {
        goto out;
    }
#else
    if (!CRYPTO_add(&source_certificate->certificate->references, 1, CRYPTO_LOCK_X509)) {
        goto out;
    }
#endif
    certificate->certificate = source_certificate->certificate;
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
    if (!EVP_PKEY_up_ref(source_certificate->key)) {
        goto out;
    }
#else
    if (!CRYPTO_add(&source_certificate->key->references, 1, CRYPTO_LOCK_EVP_PKEY)) {
        goto out;
    }
#endif
    certificate->key = source_certificate->key;
    certificate->key_type = source_certificate->key_type;

    // Done
    error = RAWRTC_CODE_SUCCESS;

out:
    if (error) {
        mem_deref(certificate);
        ERR_print_errors_cb(print_openssl_error, NULL);
    } else {
        // Set pointer
        *certificatep = certificate;
    }
    return error;
}

static enum rawrtc_code what_to_encode(
        enum rawrtc_certificate_encode const to_encode,
        bool* encode_certificatep,  // de-referenced
        bool* encode_keyp  // de-referenced
) {
    *encode_certificatep = false;
    *encode_keyp = false;

    // What to encode?
    switch (to_encode) {
        case RAWRTC_CERTIFICATE_ENCODE_CERTIFICATE:
            *encode_certificatep = true;
            break;
        case RAWRTC_CERTIFICATE_ENCODE_PRIVATE_KEY:
            *encode_keyp = true;
            break;
        case RAWRTC_CERTIFICATE_ENCODE_BOTH:
            *encode_certificatep = true;
            *encode_keyp = true;
            break;
        default:
            return RAWRTC_CODE_INVALID_ARGUMENT;
    }

    // Done
    return RAWRTC_CODE_SUCCESS;
}

/*
 * Get PEM of the certificate and/or the private key if requested.
 * *pemp will NOT be null-terminated!
 */
enum rawrtc_code rawrtc_certificate_get_pem(
        char** const pemp,  // de-referenced
        size_t* const pem_lengthp,  // de-referenced
        struct rawrtc_certificate* const certificate,
        enum rawrtc_certificate_encode const to_encode
) {
    bool encode_certificate;
    bool encode_key;
    enum rawrtc_code error;
    BIO* bio = NULL;
    char* pem = NULL;
    uint64_t length;

    // Check arguments
    if (!pemp || !certificate) {
        return RAWRTC_CODE_INVALID_ARGUMENT;
    }

    // What to encode?
    error = what_to_encode(to_encode, &encode_certificate, &encode_key);
    if (error) {
        return error;
    }
    error = RAWRTC_CODE_UNKNOWN_ERROR;

    // Create bio structure
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
    bio = BIO_new(BIO_s_secmem());
#else
    bio = BIO_new(BIO_s_mem());
#endif

    // Write certificate
    if (encode_certificate && !PEM_write_bio_X509(bio, certificate->certificate)) {
        goto out;
    }

    // Write private key (if requested)
    if (encode_key && !PEM_write_bio_PrivateKey(bio, certificate->key, NULL, NULL, 0, 0, NULL)) {
        goto out;
    }

    // Allocate buffer
    length = BIO_number_written(bio);
#if (UINT64_MAX > INT_MAX)
    if (length > INT_MAX) {
        error = RAWRTC_CODE_UNKNOWN_ERROR;
        goto out;
    }
#endif
    pem = mem_alloc(length, NULL);
    if (!pem) {
        error = RAWRTC_CODE_NO_MEMORY;
        goto out;
    }

    // Copy to buffer
    if (BIO_read(bio, pem, (int) length) < length) {
        goto out;
    }

    // Done
    error = RAWRTC_CODE_SUCCESS;

out:
    if (bio) {
        BIO_free(bio);
    }
    if (error) {
        mem_deref(pem);
        ERR_print_errors_cb(print_openssl_error, NULL);
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
enum rawrtc_code rawrtc_certificate_get_der(
        uint8_t** const derp,  // de-referenced
        size_t* const der_lengthp,  // de-referenced
        struct rawrtc_certificate* const certificate,
        enum rawrtc_certificate_encode const to_encode
) {
    bool encode_certificate;
    bool encode_key;
    enum rawrtc_code error;
    int length_certificate = 0;
    int length_key = 0;
    size_t length;
    uint8_t* der = NULL;
    uint8_t* der_i2d;

    // Check arguments
    if (!derp || !certificate) {
        return RAWRTC_CODE_INVALID_ARGUMENT;
    }

    // What to encode?
    error = what_to_encode(to_encode, &encode_certificate, &encode_key);
    if (error) {
        return error;
    }
    error = RAWRTC_CODE_UNKNOWN_ERROR;

    // Allocate buffer
    if (encode_certificate) {
        length_certificate = i2d_X509(certificate->certificate, NULL);
        if (length_certificate < 1) {
            return RAWRTC_CODE_UNKNOWN_ERROR;
        }
    }
    if (encode_key) {
        length_key = i2d_PrivateKey(certificate->key, NULL);
        if (length_key < 1) {
            return RAWRTC_CODE_UNKNOWN_ERROR;
        }
    }
    length = (size_t) (length_certificate + length_key);
    der = mem_alloc(length, NULL);
    if (!der) {
        error = RAWRTC_CODE_NO_MEMORY;
        goto out;
    }
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
    error = RAWRTC_CODE_SUCCESS;

out:
    if (error) {
        mem_deref(der);
        ERR_print_errors_cb(print_openssl_error, NULL);
    } else {
        // Set pointers
        *derp = der;
        *der_lengthp = length;
    }
    return error;
}

/*
 * Get certificate's fingerprint.
 * Caller must ensure that `buffer` has space for
 * `RAWRTC_FINGERPRINT_MAX_SIZE_HEX` bytes
 */
enum rawrtc_code rawrtc_certificate_get_fingerprint(
        char** const fingerprint, // de-referenced
        struct rawrtc_certificate* const certificate,
        enum rawrtc_certificate_sign_algorithm const algorithm
) {
    EVP_MD const * sign_function;
    uint8_t bytes_buffer[RAWRTC_FINGERPRINT_MAX_SIZE_HEX];
    uint_least32_t length;

    // Check arguments
    if (!fingerprint || !certificate) {
        return RAWRTC_CODE_INVALID_ARGUMENT;
    }

    // Get sign function for algorithm
    sign_function = rawrtc_get_sign_function(algorithm);
    if (!sign_function) {
        return RAWRTC_CODE_INVALID_ARGUMENT;
    }

    // Generate certificate fingerprint
    if (!X509_digest(certificate->certificate, sign_function, bytes_buffer, &length)) {
        return RAWRTC_CODE_NO_VALUE;
    }
    if (length < 1) {
        return RAWRTC_CODE_UNKNOWN_ERROR;
    }

    // Convert bytes to hex
    return rawrtc_bin_to_colon_hex(fingerprint, bytes_buffer, (size_t) length);
}

/*
 * Copy and append a certificate to a list.
 */
enum rawrtc_code copy_and_append_certificate(
        struct list* const certificate_list, // de-referenced, not checked
        struct rawrtc_certificate* const certificate // copied, not checked
) {
    enum rawrtc_code error;
    struct rawrtc_certificate* copied_certificate;

    // Null?
    if (certificate == NULL) {
        return RAWRTC_CODE_INVALID_ARGUMENT;
    }

    // Copy certificate
    // Note: Copying is needed as the 'le' element cannot be associated to multiple lists
    error = rawrtc_certificate_copy(&copied_certificate, certificate);
    if (error) {
        return error;
    }

    // Append to list
    list_append(certificate_list, &copied_certificate->le, copied_certificate);
    return RAWRTC_CODE_SUCCESS;
}

/*
 * Copy an array of certificates to a list.
 * Warning: The list will be flushed on error.
 */
enum rawrtc_code rawrtc_certificate_array_to_list(
        struct list* const certificate_list, // de-referenced, copied into
        struct rawrtc_certificate* const certificates[], // copied (each item)
        size_t const n_certificates
) {
    size_t i;
    enum rawrtc_code error = RAWRTC_CODE_SUCCESS;

    // Check arguments
    if (!certificate_list || !certificates) {
        return RAWRTC_CODE_INVALID_ARGUMENT;
    }

    // Append and reference certificates
    for (i = 0; i < n_certificates; ++i) {
        error = copy_and_append_certificate(certificate_list, certificates[i]);
        if (error) {
            goto out;
        }
    }

out:
    if (error) {
        list_flush(certificate_list);
    }
    return error;
}

/*
 * Copy a certificate list.
 * Warning: The destination list will be flushed on error.
 */
enum rawrtc_code rawrtc_certificate_list_copy(
        struct list* const destination_list, // de-referenced, copied into
        struct list* const source_list // de-referenced, copied (each item)
) {
    struct le* le;
    enum rawrtc_code error = RAWRTC_CODE_SUCCESS;

    // Check arguments
    if (!destination_list || !source_list) {
        return RAWRTC_CODE_INVALID_ARGUMENT;
    }

    // Append and reference certificates
    for (le = list_head(source_list); le != NULL; le = le->next) {
        struct rawrtc_certificate* const certificate = le->data;
        error = copy_and_append_certificate(destination_list, certificate);
        if (error) {
            goto out;
        }
    }

out:
    if (error) {
        list_flush(destination_list);
    }
    return error;
}
