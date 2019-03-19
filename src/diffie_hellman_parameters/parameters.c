#include "parameters.h"
#include <rawrtc/config.h>
#include <rawrtcc/code.h>
#include <re.h>
#include <openssl/bio.h>  // BIO_new_mem_buf
#include <openssl/dh.h>  // DH, DH_check_params
#include <openssl/err.h>  // ERR_clear_error
#include <openssl/pem.h>  // PEM_read_bio_DHparams
#include <openssl/ssl.h>  // SSL_CTX_set_tmp_dh, SSL_CTX_set_ecdh_auto
#include <limits.h>  // INT_MAX, LONG_MAX

#define DEBUG_MODULE "diffie-hellman-parameters"
//#define RAWRTC_DEBUG_MODULE_LEVEL 7 // Note: Uncomment this to debug this module only
#include <rawrtcc/debug.h>

/*
 * Apply Diffie-Hellman parameters on an OpenSSL context.
 */
static enum rawrtc_code set_dh_parameters(
    struct ssl_ctx_st* const ssl_context,  // not checked
    DH const* const dh  // not checked
) {
    int codes;

    // Check that the parameters are "likely enough to be valid"
#if OPENSSL_VERSION_NUMBER < 0x1010000fL || defined(OPENSSL_IS_BORINGSSL)
    if (!DH_check(dh, &codes)) {
        return RAWRTC_CODE_INVALID_ARGUMENT;
    }
#else
    if (!DH_check_params(dh, &codes)) {
        return RAWRTC_CODE_INVALID_ARGUMENT;
    }
#endif
    if (codes) {
#if defined(DH_CHECK_P_NOT_PRIME)
        if (codes & DH_CHECK_P_NOT_PRIME) {
            DEBUG_WARNING("set_dh_parameters: p is not prime\n");
        }
#endif
#if defined(DH_CHECK_P_NOT_SAFE_PRIME)
        if (codes & DH_CHECK_P_NOT_SAFE_PRIME) {
            DEBUG_WARNING("set_dh_parameters: p is not safe prime\n");
        }
#endif
#if defined(DH_UNABLE_TO_CHECK_GENERATOR)
        if (codes & DH_UNABLE_TO_CHECK_GENERATOR) {
            DEBUG_WARNING("set_dh_parameters: generator g cannot be checked\n");
        }
#endif
#if defined(DH_NOT_SUITABLE_GENERATOR)
        if (codes & DH_NOT_SUITABLE_GENERATOR) {
            DEBUG_WARNING("set_dh_parameters: generator g is not suitable\n");
        }
#endif
#if defined(DH_CHECK_Q_NOT_PRIME)
        if (codes & DH_CHECK_Q_NOT_PRIME) {
            DEBUG_WARNING("set_dh_parameters: q is not prime\n");
        }
#endif
#if defined(DH_CHECK_INVALID_Q_VALUE)
        if (codes & DH_CHECK_INVALID_Q_VALUE) {
            DEBUG_WARNING("set_dh_parameters: q is invalid\n");
        }
#endif
#if defined(DH_CHECK_INVALID_J_VALUE)
        if (codes & DH_CHECK_INVALID_J_VALUE) {
            DEBUG_WARNING("set_dh_parameters: j is invalid\n");
        }
#endif
        return RAWRTC_CODE_INVALID_ARGUMENT;
    }

    // Apply Diffie-Hellman parameters
    if (!SSL_CTX_set_tmp_dh(ssl_context, dh)) {
        DEBUG_WARNING("set_dh_parameters: set_tmp_dh failed\n");
        return RAWRTC_CODE_UNKNOWN_ERROR;
    }

    // Done
    return RAWRTC_CODE_SUCCESS;
}

/*
 * Set Diffie-Hellman parameters on an OpenSSL context using DER encoding.
 */
enum rawrtc_code rawrtc_set_dh_parameters_der(
    struct tls* const tls, uint8_t const* const der, size_t const der_size) {
    struct ssl_ctx_st* const ssl_context = tls_openssl_context(tls);
    DH* dh = NULL;
    enum rawrtc_code error = RAWRTC_CODE_UNKNOWN_ERROR;

    // Check arguments
    if (!ssl_context || !der || der_size == 0 || der_size > LONG_MAX) {
        return RAWRTC_CODE_INVALID_ARGUMENT;
    }

    // Decode PKCS#3 Diffie-Hellman parameters
    dh = d2i_DHparams(NULL, (unsigned char const**) &der, der_size);
    if (!dh) {
        goto out;
    }

    // Apply Diffie-Hellman parameters
    error = set_dh_parameters(ssl_context, dh);
    if (error) {
        goto out;
    }

    // Done
    error = RAWRTC_CODE_SUCCESS;

out:
    if (dh) {
        DH_free(dh);
    }
    if (error) {
        ERR_clear_error();
    }
    return error;
}

/**
 * Set Diffie-Hellman parameters on an OpenSSL context using PEM encoding.
 */
enum rawrtc_code rawrtc_set_dh_parameters_pem(
    struct tls* const tls, char const* const pem, size_t const pem_size) {
    struct ssl_ctx_st* const ssl_context = tls_openssl_context(tls);
    BIO* bio = NULL;
    DH* dh = NULL;
    enum rawrtc_code error = RAWRTC_CODE_NO_MEMORY;

    // Check arguments
    if (!ssl_context || !pem || pem_size == 0 || pem_size > INT_MAX) {
        return RAWRTC_CODE_INVALID_ARGUMENT;
    }

    // Create memory sink
    bio = BIO_new_mem_buf(pem, (int) pem_size);
    if (!bio) {
        goto out;
    }

    // Read Diffie-Hellman parameters into memory sink
    dh = PEM_read_bio_DHparams(bio, NULL, 0, NULL);
    if (!dh)
        goto out;

    // Apply Diffie-Hellman parameters
    error = set_dh_parameters(ssl_context, dh);
    if (error) {
        goto out;
    }

    // Done
    error = RAWRTC_CODE_SUCCESS;

out:
    if (dh) {
        DH_free(dh);
    }
    if (bio) {
        BIO_free(bio);
    }
    if (error) {
        ERR_clear_error();
    }
    return error;
}

/*
 * Enable elliptic-curve Diffie-Hellman on an OpenSSL context.
 */
enum rawrtc_code rawrtc_enable_ecdh(struct tls* const tls) {
    struct ssl_ctx_st* const ssl_context = tls_openssl_context(tls);

    // Check arguments
    if (!ssl_context) {
        return RAWRTC_CODE_INVALID_ARGUMENT;
    }

    // Enable elliptic-curve Diffie-Hellman
    if (!SSL_CTX_set_ecdh_auto(ssl_context, (long) 1)) {
        DEBUG_WARNING("set_dh_params: set_ecdh_auto failed\n");
        return RAWRTC_CODE_UNKNOWN_ERROR;
    }

    // Done
    return RAWRTC_CODE_SUCCESS;
}
