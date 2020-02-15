/* Code to create an extended X.509 certificate with OpenSSL. */

#include <assert.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <sgx_uae_service.h>

#include <openssl/rsa.h>
#include <openssl/x509.h>

#include "ra.h"
#include "ra-attester.h"
#include "ra-challenger_private.h"
#include "ra_private.h"

#include "str-two-way.h"

// borrowed from https://github.com/bminor/glibc/blob/5cb226d7e4e710939cff7288bf9970cb52ec0dfa/string/memmem.c
#define hash2(p) (((size_t)(p)[0] - ((size_t)(p)[-1] << 3)) % sizeof (shift))

//#define RASSL_DEBUG

void *
memmem (const void *haystack, size_t hs_len,
	  const void *needle, size_t ne_len)
{
  const unsigned char *hs = (const unsigned char *) haystack;
  const unsigned char *ne = (const unsigned char *) needle;

  if (ne_len == 0)
    return (void *) hs;
  if (ne_len == 1)
    return (void *) memchr (hs, ne[0], hs_len);

  /* Ensure haystack length is >= needle length.  */
  if (hs_len < ne_len)
    return NULL;

  const unsigned char *end = hs + hs_len - ne_len;

  if (ne_len == 2)
    {
      uint32_t nw = ne[0] << 16 | ne[1], hw = hs[0] << 16 | hs[1];
      for (hs++; hs <= end && hw != nw; )
	hw = hw << 16 | *++hs;
      return hw == nw ? (void *)hs - 1 : NULL;
    }

  /* Use Two-Way algorithm for very long needles.  */
  if (__builtin_expect (ne_len > 256, 0))
    return two_way_long_needle (hs, hs_len, ne, ne_len);

  uint8_t shift[256];
  size_t tmp, shift1;
  size_t m1 = ne_len - 1;
  size_t offset = 0;

  memset (shift, 0, sizeof (shift));
  for (int i = 1; i < m1; i++)
    shift[hash2 (ne + i)] = i;
  /* Shift1 is the amount we can skip after matching the hash of the
     needle end but not the full needle.  */
  shift1 = m1 - shift[hash2 (ne + m1)];
  shift[hash2 (ne + m1)] = m1;

  for ( ; hs <= end; )
    {
      /* Skip past character pairs not in the needle.  */
      do
	{
	  hs += m1;
	  tmp = shift[hash2 (hs)];
	}
      while (tmp == 0 && hs <= end);

      /* If the match is not at the end of the needle, shift to the end
	 and continue until we match the hash of the needle end.  */
      hs -= tmp;
      if (tmp < m1)
	continue;

      /* Hash of the last 2 characters matches.  If the needle is long,
	 try to quickly filter out mismatches.  */
      if (m1 < 15 || memcmp (hs + offset, ne + offset, 8) == 0)
	{
	  if (memcmp (hs, ne, m1) == 0)
	    return (void *) hs;

	  /* Adjust filter offset when it doesn't find the mismatch.  */
	  offset = (offset >= 8 ? offset : m1) - 8;
	}

      /* Skip based on matching the hash of the needle end.  */
      hs += shift1;
    }
  return NULL;
}



static const uint32_t SHA256_DIGEST_SIZE = 256 / 8;

//#include <sys/time.h> // doesn't exist in trusted SDK
//#define MEASURE_FINE_GRAINED_SETUP_TIME

// uses accessor APIs, bcs. more data types are opaque in OpenSSL > 1.0.2
int add_sgx_extension(X509 *crt, const char *oid, const char *sn, const char *ln,
                      const unsigned char *value, int len) {
    int asn1_obj = OBJ_create(oid, sn, ln);
    if (asn1_obj == NID_undef) return -1;
    
    ASN1_OCTET_STRING *ostr_ptr = ASN1_OCTET_STRING_new();
    ASN1_OCTET_STRING_set(ostr_ptr, value, len);    

    X509_EXTENSION *ex = NULL;
    // if critical, I got: [error] Certificate Verification: Error (34): unhandled critical extension
    X509_EXTENSION_create_by_NID(&ex, asn1_obj, 0, ostr_ptr); // non-crit [ok?]

    int res = X509_add_ext(crt, ex, -1);
    if (res == 0) return -1;

    X509_EXTENSION_free(ex);
    // already done by extension free?
    ASN1_OCTET_STRING_free(ostr_ptr);

    return 0;
}


/**
 * Caller must allocate memory for certificate.
 * 
 * @param der_crt_len On entry contains the size of der_crt buffer. On return holds actual size of certificate in bytes.
 */
static
void generate_x509
(
    EVP_PKEY* key,   /* in */
    uint8_t* der_crt, /* out */
    int* der_crt_len, /* in/out */
    attestation_verification_report_t* attn_report
)
{
    X509* crt;
    crt = X509_new();
    
    X509_set_version(crt, 2);
    X509_gmtime_adj(X509_get_notBefore(crt), 0);
    X509_gmtime_adj(X509_get_notAfter(crt), 31536000L);

    X509_set_pubkey(crt, key);

    X509_NAME* name;
    name = X509_get_subject_name(crt);
    
    X509_NAME_add_entry_by_txt(name, "C",  MBSTRING_ASC,
                               (unsigned char *)"US", -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "ST",  MBSTRING_ASC,
                               (unsigned char *)"OR", -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "L",  MBSTRING_ASC,
                               (unsigned char *)"Hillsboro", -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "O",  MBSTRING_ASC,
                               (unsigned char *)"Intel Inc.", -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "OU",  MBSTRING_ASC,
                               (unsigned char *)"Intel Labs", -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
                               (unsigned char *)"SGX rocks!", -1, -1, 0);

    X509_set_issuer_name(crt, name);

    /* Add custom extensions with IAS report */

#ifdef RASSL_DEBUG
    printf("Trying to create ASN1 object\n");
#endif

    /* not working, bcs. I think the "." which separate the numbers are missing, and there seems to be no API
     * allowing to input the direct byte arrays
    int l = ias_oid_len-2;
    char *obj1_copy = malloc(l+1);
    memcpy(obj1_copy, ias_response_body_oid+2, l);
    obj1_copy[l] = '\0';
    printf("Object OID: %s\n", obj1_copy);
    */

    if (0 != add_sgx_extension(crt, "1.2.840.113741.1337.2", "sgx1", "ias_response_body_oid", 
                                    attn_report->ias_report, attn_report->ias_report_len))
        printf("Failed adding extension\n");

    if (0 != add_sgx_extension(crt, "1.2.840.113741.1337.3", "sgx2", "ias_root_cert_oid",
                                    attn_report->ias_sign_ca_cert, attn_report->ias_sign_ca_cert_len))
        printf("Failed adding extension\n");

    if (0 != add_sgx_extension(crt, "1.2.840.113741.1337.4", "sgx3", "ias_leaf_cert_oid",
                                    attn_report->ias_sign_cert, attn_report->ias_sign_cert_len))
        printf("Failed adding extension\n");

    if (0 != add_sgx_extension(crt, "1.2.840.113741.1337.5", "sgx4", "ias_report_signature_oid",
                                    attn_report->ias_report_signature, attn_report->ias_report_signature_len))
        printf("Failed adding extension\n");

    // --------------------------------------

    X509_sign(crt, key, EVP_sha256());

    /* Encode X509 as DER. */
    int len = i2d_X509(crt, NULL);
    //assert(len <= *der_crt_len);
    i2d_X509(crt, &der_crt);
    *der_crt_len = len;

    X509_free(crt);
    crt = NULL;
}

void sha256_rsa_pubkey
(
    unsigned char hash[SHA256_DIGEST_SIZE],
    RSA* key
)
{
    int len = i2d_RSAPublicKey(key, NULL);
   // assert(len > 0);
    /* magic size of DER-encoded 2048 bit RSA public key. */
   // assert(len == 270);
    
    unsigned char buf[len];
    unsigned char* p = buf;
    len = i2d_RSAPublicKey(key, &p);

    unsigned char md_value[EVP_MAX_MD_SIZE];
    uint32_t md_len;

    EVP_MD_CTX* mdctx = EVP_MD_CTX_create();
    const EVP_MD* md = EVP_sha256();
    EVP_DigestInit_ex(mdctx, md, NULL);
    EVP_DigestUpdate(mdctx, buf, len);
    EVP_DigestFinal_ex(mdctx, md_value, &md_len);
  //  assert(md_len == SHA256_DIGEST_SIZE);
    EVP_MD_CTX_destroy(mdctx);
    memcpy(hash, md_value, SHA256_DIGEST_SIZE);
}

static void
openssl_create_key_and_x509
(
    uint8_t* der_key,
    int* der_key_len,
    uint8_t* der_cert,
    int* der_cert_len,
    const struct ra_tls_options* opts
)
{
#ifdef MEASURE_FINE_GRAINED_SETUP_TIME
        int timeofday_ok_key = 1;
        struct timeval listen_tv_start_key, listen_tv_end_key;
        if( gettimeofday(&listen_tv_start_key, NULL) != 0 ) {
            fprintf(stderr, "gettimeofday failed in setup\n");
            fflush(stderr);
            timeofday_ok_key = 0;
        }
#endif
    /* Generate key. */
    //RSA* key;
    RSA *key = RSA_new();
    if (key == NULL) {
      printf("Failed to create RSA obj\n");
      return;
    }
    //RSA_free();

    static const int nr_bits = 2048;
    static const char *e = "0x10001";
    BIGNUM *e_p = BN_new();
    if (e_p == NULL) {
      printf("Failed to create BN obj\n");
      return;
    }

    //BN_free(e_p);
    int ret = BN_set_word(e_p, RSA_F4);
    if (ret == 0) {
      printf("BN_set_word failed\n");
      BN_free(e_p);
      return;
    }
    
#ifdef RASSL_DEBUG
    printf("Going to call RSA_generate_key_ex()\n");
#endif
    
    //key = RSA_generate_key(nr_bits, RSA_F4, NULL, NULL);
    RSA_generate_key_ex(key, nr_bits, e_p, NULL); // returns int

#ifdef RASSL_DEBUG
    printf("Returned from RSA_gen_key_ex()!\n");
#endif

  //  assert(NULL != key);
    
    uint8_t der[4096];
    int derSz = i2d_RSAPrivateKey(key, NULL);
  //  assert(derSz >= 0);
  //  assert(derSz <= (int) *der_key_len);
    unsigned char* p = der;
    i2d_RSAPrivateKey(key, &p);

    *der_key_len = derSz;
    memcpy(der_key, der, derSz);
#ifdef MEASURE_FINE_GRAINED_SETUP_TIME
        if( timeofday_ok_key == 1 ) {
            if ( gettimeofday(&listen_tv_end_key, NULL) != 0 ) {
                fprintf(stderr, "gettimeofday failed in setup\n");
                fflush(stderr);
            } else {
                unsigned long int diff_sec = listen_tv_end_key.tv_sec - listen_tv_start_key.tv_sec;
                unsigned long int total_diff_in_ms = diff_sec * 1000000 + listen_tv_end_key.tv_usec - listen_tv_start_key.tv_usec;
                printf("%ld;", total_diff_in_ms);
                //fprintf(stderr, "RSA key\n");
                //fflush(stdout);
            }
        }
#endif

    /* Generate certificate */
    sgx_report_data_t report_data = {0, };
    sha256_rsa_pubkey(report_data.d, key);
    attestation_verification_report_t attestation_report;

    do_remote_attestation(&report_data, opts, &attestation_report);

    EVP_PKEY* evp_key = EVP_PKEY_new();
    EVP_PKEY_assign_RSA(evp_key, key);
#ifdef MEASURE_FINE_GRAINED_SETUP_TIME
        int timeofday_ok = 1;
        struct timeval listen_tv_start, listen_tv_end;
        if( gettimeofday(&listen_tv_start, NULL) != 0 ) {
            fprintf(stderr, "gettimeofday failed in setup\n");
            fflush(stderr);
            timeofday_ok = 0;
        }
#endif
    generate_x509(evp_key, der_cert, der_cert_len,
                  &attestation_report);
#ifdef MEASURE_FINE_GRAINED_SETUP_TIME
        if( timeofday_ok == 1 ) {
            if ( gettimeofday(&listen_tv_end, NULL) != 0 ) {
                fprintf(stderr, "gettimeofday failed in setup\n");
                fflush(stderr);
            } else {
                unsigned long int diff_sec = listen_tv_end.tv_sec - listen_tv_start.tv_sec;
                unsigned long int total_diff_in_ms = diff_sec * 1000000 + listen_tv_end.tv_usec - listen_tv_start.tv_usec;
                printf("%ld;", total_diff_in_ms);
                //fprintf(stderr, "x509\n");
                //fflush(stdout);
            }
        }
#endif
    EVP_PKEY_free(evp_key);
    evp_key = NULL;
}

void create_key_and_x509
(
    uint8_t* der_key,  /* out */
    int* der_key_len,  /* in/out */
    uint8_t* der_cert, /* out */
    int* der_cert_len, /* in/out */
    const struct ra_tls_options* opts /* in */
)
{
    openssl_create_key_and_x509(der_key, der_key_len,
                                der_cert, der_cert_len,
                                opts);
}
