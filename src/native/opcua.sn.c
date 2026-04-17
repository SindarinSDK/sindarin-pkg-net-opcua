/* ==============================================================================
 * opcua.sn.c - OPC UA client bindings for Sindarin using open62541 + OpenSSL
 * ==============================================================================
 * Thread safety model:
 *   - UA_Client is NOT thread-safe across operations. Every call into open62541
 *     for a given client is serialized via RtOpcUaClient::mutex.
 *   - A background "pump" thread periodically calls UA_Client_run_iterate() to
 *     drive subscription publishing and secure-channel keep-alives. It holds
 *     the client mutex only briefly per iteration so foreground calls can
 *     interleave.
 *   - Incoming data-change notifications are enqueued onto a per-subscription
 *     event ring. User code drains events via sn_opcua_subscription_next_event.
 * ============================================================================== */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <time.h>
#include <errno.h>

/* open62541 */
#include <open62541/client.h>
#include <open62541/client_config_default.h>
#include <open62541/client_highlevel.h>
#include <open62541/client_subscriptions.h>
#include <open62541/plugin/log_stdout.h>
#include <open62541/plugin/securitypolicy.h>
#include <open62541/types.h>
#include <open62541/types_generated.h>
#include <open62541/types_generated_handling.h>

/* OpenSSL (cert loading, thumbprint, DN parsing) */
#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/sha.h>
#include <openssl/x509.h>

/* Platform threading */
#ifdef _WIN32
    #ifndef WIN32_LEAN_AND_MEAN
        #define WIN32_LEAN_AND_MEAN
    #endif
    #include <windows.h>
    #include <process.h>

    /* open62541 calls into Winsock, IP Helper, Windows crypto, and the
     * Windows User32 API for its default logger. Autolink the system libs
     * so the static open62541 build resolves all references. */
    #pragma comment(lib, "ws2_32.lib")
    #pragma comment(lib, "iphlpapi.lib")
    #pragma comment(lib, "crypt32.lib")
    #pragma comment(lib, "bcrypt.lib")
    #pragma comment(lib, "advapi32.lib")
    #pragma comment(lib, "user32.lib")

    typedef CRITICAL_SECTION opcua_mutex_t;
    typedef HANDLE opcua_thread_t;
    typedef CONDITION_VARIABLE opcua_cond_t;

    #define OPCUA_MUTEX_INIT(m)      InitializeCriticalSection(m)
    #define OPCUA_MUTEX_DESTROY(m)   DeleteCriticalSection(m)
    #define OPCUA_MUTEX_LOCK(m)      EnterCriticalSection(m)
    #define OPCUA_MUTEX_UNLOCK(m)    LeaveCriticalSection(m)
    #define OPCUA_COND_INIT(c)       InitializeConditionVariable(c)
    #define OPCUA_COND_DESTROY(c)    ((void)0)
    #define OPCUA_COND_WAIT(c, m)    SleepConditionVariableCS(c, m, INFINITE)
    #define OPCUA_COND_TIMEDWAIT(c, m, ms) SleepConditionVariableCS(c, m, (DWORD)(ms))
    #define OPCUA_COND_SIGNAL(c)     WakeConditionVariable(c)
    #define OPCUA_COND_BROADCAST(c)  WakeAllConditionVariable(c)
    #define OPCUA_SLEEP_MS(ms)       Sleep((DWORD)(ms))
#else
    #include <pthread.h>
    #include <unistd.h>

    typedef pthread_mutex_t   opcua_mutex_t;
    typedef pthread_t         opcua_thread_t;
    typedef pthread_cond_t    opcua_cond_t;

    #define OPCUA_MUTEX_INIT(m)      pthread_mutex_init(m, NULL)
    #define OPCUA_MUTEX_DESTROY(m)   pthread_mutex_destroy(m)
    #define OPCUA_MUTEX_LOCK(m)      pthread_mutex_lock(m)
    #define OPCUA_MUTEX_UNLOCK(m)    pthread_mutex_unlock(m)
    #define OPCUA_COND_INIT(c)       pthread_cond_init(c, NULL)
    #define OPCUA_COND_DESTROY(c)    pthread_cond_destroy(c)
    #define OPCUA_COND_WAIT(c, m)    pthread_cond_wait(c, m)
    static int opcua_cond_timedwait_ms(pthread_cond_t *c, pthread_mutex_t *m, int ms) {
        struct timespec ts;
        clock_gettime(CLOCK_REALTIME, &ts);
        ts.tv_sec  += ms / 1000;
        ts.tv_nsec += (long)(ms % 1000) * 1000000L;
        if (ts.tv_nsec >= 1000000000L) { ts.tv_sec++; ts.tv_nsec -= 1000000000L; }
        return pthread_cond_timedwait(c, m, &ts);
    }
    #define OPCUA_COND_TIMEDWAIT(c, m, ms) opcua_cond_timedwait_ms(c, m, ms)
    #define OPCUA_COND_SIGNAL(c)     pthread_cond_signal(c)
    #define OPCUA_COND_BROADCAST(c)  pthread_cond_broadcast(c)
    #define OPCUA_SLEEP_MS(ms)       usleep((useconds_t)((ms) * 1000))
#endif

/* ============================================================================
 * Null logger — suppresses open62541's own stdout/stderr noise, which would
 * otherwise interleave with test output and break .expected comparisons.
 * Can be bypassed by setting OPCUA_VERBOSE=1 in the environment.
 * ============================================================================ */

static void opcua_null_log_cb(void *ctx, UA_LogLevel level, UA_LogCategory cat,
                              const char *msg, va_list args) {
    (void)ctx; (void)level; (void)cat; (void)msg; (void)args;
}

static UA_Logger OPCUA_NULL_LOGGER = { opcua_null_log_cb, NULL, NULL };

static bool opcua_verbose(void) {
    const char *v = getenv("OPCUA_VERBOSE");
    return v && v[0] && v[0] != '0';
}

static UA_Logger *opcua_resolve_logger(UA_Logger *current) {
    return opcua_verbose() ? current : &OPCUA_NULL_LOGGER;
}

/* Stdout silencing helpers are unused in the library binding — the test
 * server handles silencing via dup2 around its lifetime. Kept here for the
 * discovery path where no test server is involved, but currently unused. */

/* ============================================================================
 * Forward-declared Rt aliases (the compiler emits __sn__X via the .sn file).
 * ============================================================================ */

typedef __sn__OpcUaSecurityPolicy        RtOpcUaSecurityPolicy;
typedef __sn__OpcUaMessageSecurityMode   RtOpcUaMessageSecurityMode;
typedef __sn__OpcUaUserIdentity          RtOpcUaUserIdentity;
typedef __sn__OpcUaCertificate           RtOpcUaCertificate;
typedef __sn__OpcUaTrustList             RtOpcUaTrustList;
typedef __sn__OpcUaNodeId                RtOpcUaNodeId;
typedef __sn__OpcUaVariant               RtOpcUaVariant;
typedef __sn__OpcUaReferenceDescription  RtOpcUaReferenceDescription;
typedef __sn__OpcUaEndpointDescription   RtOpcUaEndpointDescription;
typedef __sn__OpcUaApplicationDescription RtOpcUaApplicationDescription;
typedef __sn__OpcUaDataChangeEvent       RtOpcUaDataChangeEvent;
typedef __sn__OpcUaMonitoredItem         RtOpcUaMonitoredItem;
typedef __sn__OpcUaSubscription          RtOpcUaSubscription;
typedef __sn__OpcUaClientConfig          RtOpcUaClientConfig;
typedef __sn__OpcUaClient                RtOpcUaClient;

/* ============================================================================
 * String / array helpers
 * ============================================================================ */

static char *opcua_strdup_or_empty(const char *s) {
    return strdup(s ? s : "");
}

static char *opcua_strdup_ua_string(const UA_String *s) {
    if (!s || s->length == 0 || !s->data) return strdup("");
    char *out = (char *)malloc(s->length + 1);
    if (!out) { fprintf(stderr, "OPC UA: allocation failed\n"); exit(1); }
    memcpy(out, s->data, s->length);
    out[s->length] = '\0';
    return out;
}

static UA_String opcua_ua_string_from_cstr(const char *s) {
    if (!s) return UA_STRING_NULL;
    return UA_String_fromChars(s);
}

static SnArray *opcua_empty_byte_array(void) {
    SnArray *a = sn_array_new(sizeof(unsigned char), 0);
    a->elem_tag = SN_TAG_BYTE;
    return a;
}

static SnArray *opcua_byte_array_from_buf(const unsigned char *buf, size_t len) {
    SnArray *a = sn_array_new(sizeof(unsigned char), (long long)len);
    a->elem_tag = SN_TAG_BYTE;
    for (size_t i = 0; i < len; i++) sn_array_push(a, &buf[i]);
    return a;
}

static SnArray *opcua_byte_array_from_bytestring(const UA_ByteString *b) {
    if (!b || b->length == 0 || !b->data) return opcua_empty_byte_array();
    return opcua_byte_array_from_buf((const unsigned char *)b->data, b->length);
}

static UA_ByteString opcua_bytestring_from_array(SnArray *arr) {
    UA_ByteString bs;
    UA_ByteString_init(&bs);
    if (!arr || arr->len == 0) return bs;
    bs.length = (size_t)arr->len;
    bs.data = (UA_Byte *)UA_malloc(bs.length);
    if (!bs.data) { bs.length = 0; return bs; }
    bs.length = (size_t)arr->len;
    for (size_t i = 0; i < bs.length; i++) {
        unsigned char *p = (unsigned char *)sn_array_get(arr, (long long)i);
        bs.data[i] = p ? *p : 0;
    }
    return bs;
}

static SnArray *opcua_empty_string_array(void) {
    SnArray *a = sn_array_new(sizeof(char *), 0);
    a->elem_tag     = SN_TAG_STRING;
    a->elem_release = (void (*)(void *))sn_cleanup_str;
    a->elem_copy    = sn_copy_str;
    return a;
}

static void opcua_string_array_push(SnArray *arr, const char *s) {
    char *dup = strdup(s ? s : "");
    sn_array_push(arr, &dup);
}

/* ============================================================================
 * OpcUaSecurityPolicy
 * ============================================================================ */

static const char *opcua_security_policy_uri_for_code(int code) {
    switch (code) {
        case 0: return "http://opcfoundation.org/UA/SecurityPolicy#None";
        case 1: return "http://opcfoundation.org/UA/SecurityPolicy#Basic128Rsa15";
        case 2: return "http://opcfoundation.org/UA/SecurityPolicy#Basic256";
        case 3: return "http://opcfoundation.org/UA/SecurityPolicy#Basic256Sha256";
        case 4: return "http://opcfoundation.org/UA/SecurityPolicy#Aes128_Sha256_RsaOaep";
        case 5: return "http://opcfoundation.org/UA/SecurityPolicy#Aes256_Sha256_RsaPss";
        default: return "http://opcfoundation.org/UA/SecurityPolicy#None";
    }
}

RtOpcUaSecurityPolicy *sn_opcua_security_policy_new(long long code) {
    RtOpcUaSecurityPolicy *p = __sn__OpcUaSecurityPolicy__new();
    p->code = code;
    return p;
}

long long sn_opcua_security_policy_code(RtOpcUaSecurityPolicy *policy) {
    return policy ? policy->code : 0;
}

char *sn_opcua_security_policy_uri(RtOpcUaSecurityPolicy *policy) {
    if (!policy) return strdup("");
    return strdup(opcua_security_policy_uri_for_code((int)policy->code));
}

void sn_opcua_security_policy_dispose(RtOpcUaSecurityPolicy *policy) {
    (void)policy; /* nothing to release — plain value holder */
}

/* ============================================================================
 * OpcUaMessageSecurityMode
 * ============================================================================ */

RtOpcUaMessageSecurityMode *sn_opcua_message_mode_new(long long code) {
    RtOpcUaMessageSecurityMode *m = __sn__OpcUaMessageSecurityMode__new();
    m->code = code;
    return m;
}

long long sn_opcua_message_mode_code(RtOpcUaMessageSecurityMode *m) {
    return m ? m->code : 1;
}

void sn_opcua_message_mode_dispose(RtOpcUaMessageSecurityMode *m) {
    (void)m;
}

/* ============================================================================
 * OpcUaUserIdentity
 * ============================================================================ */

RtOpcUaUserIdentity *sn_opcua_user_identity_anonymous(void) {
    RtOpcUaUserIdentity *u = __sn__OpcUaUserIdentity__new();
    u->kind = 0;
    u->username = strdup("");
    u->password = strdup("");
    u->cert_path = strdup("");
    u->key_path  = strdup("");
    u->issued_token = opcua_empty_byte_array();
    u->token_type = strdup("");
    return u;
}

RtOpcUaUserIdentity *sn_opcua_user_identity_userpass(char *username, char *password) {
    RtOpcUaUserIdentity *u = __sn__OpcUaUserIdentity__new();
    u->kind = 1;
    u->username = strdup(username ? username : "");
    u->password = strdup(password ? password : "");
    u->cert_path = strdup("");
    u->key_path  = strdup("");
    u->issued_token = opcua_empty_byte_array();
    u->token_type = strdup("");
    return u;
}

RtOpcUaUserIdentity *sn_opcua_user_identity_certificate(char *certPath, char *keyPath) {
    RtOpcUaUserIdentity *u = __sn__OpcUaUserIdentity__new();
    u->kind = 2;
    u->username = strdup("");
    u->password = strdup("");
    u->cert_path = strdup(certPath ? certPath : "");
    u->key_path  = strdup(keyPath ? keyPath : "");
    u->issued_token = opcua_empty_byte_array();
    u->token_type = strdup("");
    return u;
}

RtOpcUaUserIdentity *sn_opcua_user_identity_issued(SnArray *token, char *tokenType) {
    RtOpcUaUserIdentity *u = __sn__OpcUaUserIdentity__new();
    u->kind = 3;
    u->username = strdup("");
    u->password = strdup("");
    u->cert_path = strdup("");
    u->key_path  = strdup("");
    if (token && token->len > 0) {
        u->issued_token = opcua_byte_array_from_buf(
            (const unsigned char *)sn_array_get(token, 0), (size_t)token->len);
    } else {
        u->issued_token = opcua_empty_byte_array();
    }
    u->token_type = strdup(tokenType ? tokenType : "");
    return u;
}

long long sn_opcua_user_identity_kind(RtOpcUaUserIdentity *u) {
    return u ? u->kind : 0;
}

void sn_opcua_user_identity_dispose(RtOpcUaUserIdentity *u) {
    (void)u; /* fields freed by runtime */
}

/* ============================================================================
 * OpcUaCertificate - OpenSSL-backed
 * ============================================================================ */

/* Internal: load X509 from file (PEM or DER) into DER bytes. */
static int opcua_load_cert_bytes_pem(const char *path, unsigned char **out, size_t *out_len) {
    FILE *fp = fopen(path, "rb");
    if (!fp) return -1;
    X509 *x = PEM_read_X509(fp, NULL, NULL, NULL);
    fclose(fp);
    if (!x) return -1;
    int len = i2d_X509(x, NULL);
    if (len <= 0) { X509_free(x); return -1; }
    unsigned char *buf = (unsigned char *)malloc((size_t)len);
    if (!buf) { X509_free(x); return -1; }
    unsigned char *p = buf;
    i2d_X509(x, &p);
    X509_free(x);
    *out = buf;
    *out_len = (size_t)len;
    return 0;
}

static int opcua_load_cert_bytes_der(const char *path, unsigned char **out, size_t *out_len) {
    FILE *fp = fopen(path, "rb");
    if (!fp) return -1;
    fseek(fp, 0, SEEK_END);
    long len = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    if (len <= 0) { fclose(fp); return -1; }
    unsigned char *buf = (unsigned char *)malloc((size_t)len);
    if (!buf) { fclose(fp); return -1; }
    if (fread(buf, 1, (size_t)len, fp) != (size_t)len) {
        free(buf); fclose(fp); return -1;
    }
    fclose(fp);
    *out = buf;
    *out_len = (size_t)len;
    return 0;
}

/* Build an X509 from DER bytes (caller must X509_free). */
static X509 *opcua_x509_from_der(const unsigned char *der, size_t len) {
    const unsigned char *p = der;
    return d2i_X509(NULL, &p, (long)len);
}

RtOpcUaCertificate *sn_opcua_certificate_load_pem(char *path) {
    if (!path) return NULL;
    unsigned char *buf = NULL; size_t len = 0;
    if (opcua_load_cert_bytes_pem(path, &buf, &len) != 0) {
        fprintf(stderr, "OpcUaCertificate.loadPem: failed to read %s\n", path);
        return NULL;
    }
    RtOpcUaCertificate *c = __sn__OpcUaCertificate__new();
    c->der_ptr = (long long)(uintptr_t)buf;
    c->der_len = (long long)len;
    return c;
}

RtOpcUaCertificate *sn_opcua_certificate_load_der(char *path) {
    if (!path) return NULL;
    unsigned char *buf = NULL; size_t len = 0;
    if (opcua_load_cert_bytes_der(path, &buf, &len) != 0) {
        fprintf(stderr, "OpcUaCertificate.loadDer: failed to read %s\n", path);
        return NULL;
    }
    /* Validate it parses. */
    X509 *x = opcua_x509_from_der(buf, len);
    if (!x) { free(buf); fprintf(stderr, "OpcUaCertificate.loadDer: bad DER\n"); return NULL; }
    X509_free(x);
    RtOpcUaCertificate *c = __sn__OpcUaCertificate__new();
    c->der_ptr = (long long)(uintptr_t)buf;
    c->der_len = (long long)len;
    return c;
}

RtOpcUaCertificate *sn_opcua_certificate_from_der(SnArray *bytes) {
    if (!bytes || bytes->len == 0) return NULL;
    size_t len = (size_t)bytes->len;
    unsigned char *buf = (unsigned char *)malloc(len);
    if (!buf) return NULL;
    for (size_t i = 0; i < len; i++) {
        unsigned char *p = (unsigned char *)sn_array_get(bytes, (long long)i);
        buf[i] = p ? *p : 0;
    }
    X509 *x = opcua_x509_from_der(buf, len);
    if (!x) { free(buf); return NULL; }
    X509_free(x);
    RtOpcUaCertificate *c = __sn__OpcUaCertificate__new();
    c->der_ptr = (long long)(uintptr_t)buf;
    c->der_len = (long long)len;
    return c;
}

char *sn_opcua_certificate_thumbprint(RtOpcUaCertificate *cert) {
    if (!cert || cert->der_ptr == 0) return strdup("");
    unsigned char *buf = (unsigned char *)(uintptr_t)cert->der_ptr;
    size_t len = (size_t)cert->der_len;
    unsigned char digest[SHA_DIGEST_LENGTH];
    SHA1(buf, len, digest);
    char *out = (char *)malloc(SHA_DIGEST_LENGTH * 2 + 1);
    for (int i = 0; i < SHA_DIGEST_LENGTH; i++) {
        sprintf(out + i * 2, "%02x", digest[i]);
    }
    out[SHA_DIGEST_LENGTH * 2] = '\0';
    return out;
}

static char *opcua_x509_name_to_string(X509_NAME *name) {
    if (!name) return strdup("");
    BIO *bio = BIO_new(BIO_s_mem());
    if (!bio) return strdup("");
    X509_NAME_print_ex(bio, name, 0, XN_FLAG_RFC2253);
    char *buf = NULL;
    long sz = BIO_get_mem_data(bio, &buf);
    char *out;
    if (sz > 0 && buf) {
        out = (char *)malloc((size_t)sz + 1);
        if (out) { memcpy(out, buf, (size_t)sz); out[sz] = '\0'; }
        else out = strdup("");
    } else {
        out = strdup("");
    }
    BIO_free(bio);
    return out;
}

char *sn_opcua_certificate_subject(RtOpcUaCertificate *cert) {
    if (!cert || cert->der_ptr == 0) return strdup("");
    X509 *x = opcua_x509_from_der((unsigned char *)(uintptr_t)cert->der_ptr, (size_t)cert->der_len);
    if (!x) return strdup("");
    char *out = opcua_x509_name_to_string(X509_get_subject_name(x));
    X509_free(x);
    return out;
}

char *sn_opcua_certificate_issuer(RtOpcUaCertificate *cert) {
    if (!cert || cert->der_ptr == 0) return strdup("");
    X509 *x = opcua_x509_from_der((unsigned char *)(uintptr_t)cert->der_ptr, (size_t)cert->der_len);
    if (!x) return strdup("");
    char *out = opcua_x509_name_to_string(X509_get_issuer_name(x));
    X509_free(x);
    return out;
}

static long long opcua_asn1_time_to_unix_ms(const ASN1_TIME *t) {
    if (!t) return 0;
    struct tm tm;
    memset(&tm, 0, sizeof(tm));
    if (ASN1_TIME_to_tm(t, &tm) != 1) return 0;
#ifdef _WIN32
    time_t secs = _mkgmtime(&tm);
#else
    time_t secs = timegm(&tm);
#endif
    if (secs == (time_t)-1) return 0;
    return (long long)secs * 1000LL;
}

long long sn_opcua_certificate_not_before_ms(RtOpcUaCertificate *cert) {
    if (!cert || cert->der_ptr == 0) return 0;
    X509 *x = opcua_x509_from_der((unsigned char *)(uintptr_t)cert->der_ptr, (size_t)cert->der_len);
    if (!x) return 0;
    long long ms = opcua_asn1_time_to_unix_ms(X509_get0_notBefore(x));
    X509_free(x);
    return ms;
}

long long sn_opcua_certificate_not_after_ms(RtOpcUaCertificate *cert) {
    if (!cert || cert->der_ptr == 0) return 0;
    X509 *x = opcua_x509_from_der((unsigned char *)(uintptr_t)cert->der_ptr, (size_t)cert->der_len);
    if (!x) return 0;
    long long ms = opcua_asn1_time_to_unix_ms(X509_get0_notAfter(x));
    X509_free(x);
    return ms;
}

SnArray *sn_opcua_certificate_der_bytes(RtOpcUaCertificate *cert) {
    if (!cert || cert->der_ptr == 0) return opcua_empty_byte_array();
    return opcua_byte_array_from_buf(
        (unsigned char *)(uintptr_t)cert->der_ptr, (size_t)cert->der_len);
}

void sn_opcua_certificate_dispose(RtOpcUaCertificate *cert) {
    if (!cert) return;
    if (cert->der_ptr != 0) {
        free((void *)(uintptr_t)cert->der_ptr);
        cert->der_ptr = 0;
        cert->der_len = 0;
    }
}

/* ============================================================================
 * OpcUaTrustList
 * ============================================================================ */

typedef struct {
    /* Trusted certs (DER). */
    unsigned char **trusted;
    size_t          *trusted_len;
    size_t           trusted_count;
    /* Issuer certs (DER). */
    unsigned char **issuers;
    size_t          *issuers_len;
    size_t           issuers_count;
    /* CRLs (DER). */
    unsigned char **crls;
    size_t          *crls_len;
    size_t           crls_count;
    /* If true, server cert validation is disabled — test/dev only. */
    bool             no_verification;
} OpcUaTrustListInternal;

static OpcUaTrustListInternal *opcua_trust_list_internal(RtOpcUaTrustList *tl) {
    return (OpcUaTrustListInternal *)(uintptr_t)tl->internal_ptr;
}

static void opcua_trust_list_push(unsigned char ***arr, size_t **lens, size_t *count,
                                  const unsigned char *der, size_t der_len) {
    *arr  = (unsigned char **)realloc(*arr,  sizeof(unsigned char *) * (*count + 1));
    *lens = (size_t *)        realloc(*lens, sizeof(size_t)          * (*count + 1));
    unsigned char *copy = (unsigned char *)malloc(der_len);
    memcpy(copy, der, der_len);
    (*arr)[*count]  = copy;
    (*lens)[*count] = der_len;
    (*count)++;
}

RtOpcUaTrustList *sn_opcua_trust_list_new(void) {
    RtOpcUaTrustList *tl = __sn__OpcUaTrustList__new();
    OpcUaTrustListInternal *i = (OpcUaTrustListInternal *)calloc(1, sizeof(*i));
    tl->internal_ptr = (long long)(uintptr_t)i;
    return tl;
}

RtOpcUaTrustList *sn_opcua_trust_list_no_verification(void) {
    RtOpcUaTrustList *tl = sn_opcua_trust_list_new();
    OpcUaTrustListInternal *i = opcua_trust_list_internal(tl);
    i->no_verification = true;
    return tl;
}

static int opcua_has_ext(const char *name, const char *suffix) {
    size_t ln = strlen(name), ls = strlen(suffix);
    if (ln < ls) return 0;
    return strcmp(name + ln - ls, suffix) == 0;
}

#include <sys/stat.h>
#ifdef _WIN32
#include <io.h>
#define OPCUA_STAT _stat
#define opcua_stat_t struct _stat
#else
#include <dirent.h>
#define OPCUA_STAT stat
#define opcua_stat_t struct stat
#endif

static void opcua_trust_list_load_dir_into(
    OpcUaTrustListInternal *i, const char *dir_path,
    unsigned char ***arr, size_t **lens, size_t *count, int is_crl)
{
    (void)is_crl;
#ifdef _WIN32
    char pattern[1024];
    snprintf(pattern, sizeof(pattern), "%s\\*", dir_path);
    WIN32_FIND_DATAA ffd;
    HANDLE h = FindFirstFileA(pattern, &ffd);
    if (h == INVALID_HANDLE_VALUE) return;
    do {
        if (ffd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) continue;
        char full[1024];
        snprintf(full, sizeof(full), "%s\\%s", dir_path, ffd.cFileName);
        unsigned char *buf = NULL; size_t len = 0;
        int rc = -1;
        if (opcua_has_ext(ffd.cFileName, ".der") || opcua_has_ext(ffd.cFileName, ".crl")) {
            rc = opcua_load_cert_bytes_der(full, &buf, &len);
        } else if (opcua_has_ext(ffd.cFileName, ".pem") || opcua_has_ext(ffd.cFileName, ".crt")) {
            rc = opcua_load_cert_bytes_pem(full, &buf, &len);
        }
        if (rc == 0) {
            opcua_trust_list_push(arr, lens, count, buf, len);
            free(buf);
        }
    } while (FindNextFileA(h, &ffd));
    FindClose(h);
#else
    DIR *d = opendir(dir_path);
    if (!d) return;
    struct dirent *e;
    while ((e = readdir(d)) != NULL) {
        if (e->d_name[0] == '.') continue;
        char full[1024];
        snprintf(full, sizeof(full), "%s/%s", dir_path, e->d_name);
        opcua_stat_t st;
        if (OPCUA_STAT(full, &st) != 0) continue;
        if (!S_ISREG(st.st_mode)) continue;
        unsigned char *buf = NULL; size_t len = 0;
        int rc = -1;
        if (opcua_has_ext(e->d_name, ".der") || opcua_has_ext(e->d_name, ".crl")) {
            rc = opcua_load_cert_bytes_der(full, &buf, &len);
        } else if (opcua_has_ext(e->d_name, ".pem") || opcua_has_ext(e->d_name, ".crt")) {
            rc = opcua_load_cert_bytes_pem(full, &buf, &len);
        }
        if (rc == 0) {
            opcua_trust_list_push(arr, lens, count, buf, len);
            free(buf);
        }
    }
    closedir(d);
#endif
}

RtOpcUaTrustList *sn_opcua_trust_list_load_from_dir(char *path) {
    if (!path) return sn_opcua_trust_list_new();
    RtOpcUaTrustList *tl = sn_opcua_trust_list_new();
    OpcUaTrustListInternal *i = opcua_trust_list_internal(tl);

    char sub[1024];
    /* Standard layout: trusted/certs, issuers/certs, trusted/crl, issuers/crl */
#ifdef _WIN32
    const char *sep = "\\";
#else
    const char *sep = "/";
#endif
    snprintf(sub, sizeof(sub), "%s%strusted%scerts", path, sep, sep);
    opcua_trust_list_load_dir_into(i, sub, &i->trusted, &i->trusted_len, &i->trusted_count, 0);
    snprintf(sub, sizeof(sub), "%s%sissuers%scerts", path, sep, sep);
    opcua_trust_list_load_dir_into(i, sub, &i->issuers, &i->issuers_len, &i->issuers_count, 0);
    snprintf(sub, sizeof(sub), "%s%strusted%scrl", path, sep, sep);
    opcua_trust_list_load_dir_into(i, sub, &i->crls, &i->crls_len, &i->crls_count, 1);
    snprintf(sub, sizeof(sub), "%s%sissuers%scrl", path, sep, sep);
    opcua_trust_list_load_dir_into(i, sub, &i->crls, &i->crls_len, &i->crls_count, 1);
    return tl;
}

RtOpcUaTrustList *sn_opcua_trust_list_add_trusted(RtOpcUaTrustList *tl, RtOpcUaCertificate *cert) {
    if (!tl || !cert || cert->der_ptr == 0) return tl;
    OpcUaTrustListInternal *i = opcua_trust_list_internal(tl);
    opcua_trust_list_push(&i->trusted, &i->trusted_len, &i->trusted_count,
                          (unsigned char *)(uintptr_t)cert->der_ptr,
                          (size_t)cert->der_len);
    return tl;
}

RtOpcUaTrustList *sn_opcua_trust_list_add_issuer(RtOpcUaTrustList *tl, RtOpcUaCertificate *cert) {
    if (!tl || !cert || cert->der_ptr == 0) return tl;
    OpcUaTrustListInternal *i = opcua_trust_list_internal(tl);
    opcua_trust_list_push(&i->issuers, &i->issuers_len, &i->issuers_count,
                          (unsigned char *)(uintptr_t)cert->der_ptr,
                          (size_t)cert->der_len);
    return tl;
}

RtOpcUaTrustList *sn_opcua_trust_list_add_revocation(RtOpcUaTrustList *tl, SnArray *crlDer) {
    if (!tl || !crlDer || crlDer->len == 0) return tl;
    OpcUaTrustListInternal *i = opcua_trust_list_internal(tl);
    size_t len = (size_t)crlDer->len;
    unsigned char *buf = (unsigned char *)malloc(len);
    for (size_t k = 0; k < len; k++) {
        unsigned char *p = (unsigned char *)sn_array_get(crlDer, (long long)k);
        buf[k] = p ? *p : 0;
    }
    opcua_trust_list_push(&i->crls, &i->crls_len, &i->crls_count, buf, len);
    free(buf);
    return tl;
}

long long sn_opcua_trust_list_trusted_count(RtOpcUaTrustList *tl) {
    if (!tl) return 0;
    return (long long)opcua_trust_list_internal(tl)->trusted_count;
}

long long sn_opcua_trust_list_issuer_count(RtOpcUaTrustList *tl) {
    if (!tl) return 0;
    return (long long)opcua_trust_list_internal(tl)->issuers_count;
}

long long sn_opcua_trust_list_revocation_count(RtOpcUaTrustList *tl) {
    if (!tl) return 0;
    return (long long)opcua_trust_list_internal(tl)->crls_count;
}

void sn_opcua_trust_list_save_to_dir(RtOpcUaTrustList *tl, char *path) {
    if (!tl || !path) return;
    /* Not implemented for first cut — raise a notice. */
    fprintf(stderr, "OpcUaTrustList.saveToDir: not implemented yet (path=%s)\n", path);
}

void sn_opcua_trust_list_dispose(RtOpcUaTrustList *tl) {
    if (!tl) return;
    OpcUaTrustListInternal *i = opcua_trust_list_internal(tl);
    if (!i) return;
    for (size_t k = 0; k < i->trusted_count; k++) free(i->trusted[k]);
    for (size_t k = 0; k < i->issuers_count; k++) free(i->issuers[k]);
    for (size_t k = 0; k < i->crls_count;    k++) free(i->crls[k]);
    free(i->trusted);     free(i->trusted_len);
    free(i->issuers);     free(i->issuers_len);
    free(i->crls);        free(i->crls_len);
    free(i);
    tl->internal_ptr = 0;
}

/* ============================================================================
 * OpcUaNodeId
 * ============================================================================ */

RtOpcUaNodeId *sn_opcua_node_id_numeric(long long namespace_idx, long long id) {
    RtOpcUaNodeId *n = __sn__OpcUaNodeId__new();
    n->namespace_index = namespace_idx;
    n->identifier_type = 0;
    n->numeric_id      = id;
    n->string_id       = strdup("");
    n->bytes_id        = opcua_empty_byte_array();
    return n;
}

RtOpcUaNodeId *sn_opcua_node_id_string(long long namespace_idx, char *id) {
    RtOpcUaNodeId *n = __sn__OpcUaNodeId__new();
    n->namespace_index = namespace_idx;
    n->identifier_type = 1;
    n->numeric_id      = 0;
    n->string_id       = strdup(id ? id : "");
    n->bytes_id        = opcua_empty_byte_array();
    return n;
}

RtOpcUaNodeId *sn_opcua_node_id_guid(long long namespace_idx, char *guidStr) {
    RtOpcUaNodeId *n = __sn__OpcUaNodeId__new();
    n->namespace_index = namespace_idx;
    n->identifier_type = 2;
    n->numeric_id      = 0;
    n->string_id       = strdup(guidStr ? guidStr : "");
    n->bytes_id        = opcua_empty_byte_array();
    return n;
}

RtOpcUaNodeId *sn_opcua_node_id_bytestring(long long namespace_idx, SnArray *id) {
    RtOpcUaNodeId *n = __sn__OpcUaNodeId__new();
    n->namespace_index = namespace_idx;
    n->identifier_type = 3;
    n->numeric_id      = 0;
    n->string_id       = strdup("");
    if (id && id->len > 0) {
        n->bytes_id = opcua_byte_array_from_buf(
            (const unsigned char *)sn_array_get(id, 0), (size_t)id->len);
    } else {
        n->bytes_id = opcua_empty_byte_array();
    }
    return n;
}

RtOpcUaNodeId *sn_opcua_node_id_parse(char *text) {
    if (!text) return sn_opcua_node_id_numeric(0, 0);
    /* Parse "ns=<n>;i=<num>|s=<str>|g=<guid>|b=<base64>" */
    int ns = 0;
    const char *p = text;
    if (strncmp(p, "ns=", 3) == 0) {
        p += 3;
        ns = atoi(p);
        while (*p && *p != ';') p++;
        if (*p == ';') p++;
    }
    if (p[0] == 'i' && p[1] == '=') {
        long long id = strtoll(p + 2, NULL, 10);
        return sn_opcua_node_id_numeric(ns, id);
    } else if (p[0] == 's' && p[1] == '=') {
        return sn_opcua_node_id_string(ns, (char *)(p + 2));
    } else if (p[0] == 'g' && p[1] == '=') {
        return sn_opcua_node_id_guid(ns, (char *)(p + 2));
    }
    return sn_opcua_node_id_numeric(ns, 0);
}

long long sn_opcua_node_id_namespace(RtOpcUaNodeId *n) {
    return n ? n->namespace_index : 0;
}

long long sn_opcua_node_id_identifier_type(RtOpcUaNodeId *n) {
    return n ? n->identifier_type : 0;
}

char *sn_opcua_node_id_to_string(RtOpcUaNodeId *n) {
    if (!n) return strdup("");
    char buf[512];
    switch ((int)n->identifier_type) {
        case 0:
            snprintf(buf, sizeof(buf), "ns=%lld;i=%lld", n->namespace_index, n->numeric_id);
            break;
        case 1:
            snprintf(buf, sizeof(buf), "ns=%lld;s=%s", n->namespace_index,
                     n->string_id ? n->string_id : "");
            break;
        case 2:
            snprintf(buf, sizeof(buf), "ns=%lld;g=%s", n->namespace_index,
                     n->string_id ? n->string_id : "");
            break;
        case 3:
            snprintf(buf, sizeof(buf), "ns=%lld;b=<%lld bytes>", n->namespace_index,
                     n->bytes_id ? (long long)n->bytes_id->len : 0);
            break;
        default:
            snprintf(buf, sizeof(buf), "ns=%lld;?", n->namespace_index);
            break;
    }
    return strdup(buf);
}

void sn_opcua_node_id_dispose(RtOpcUaNodeId *n) {
    (void)n;
}

/* Build a UA_NodeId from our Sindarin struct. Caller must UA_NodeId_clear. */
static UA_NodeId opcua_to_ua_node_id(RtOpcUaNodeId *n) {
    UA_NodeId out;
    UA_NodeId_init(&out);
    if (!n) return out;
    out.namespaceIndex = (UA_UInt16)n->namespace_index;
    switch ((int)n->identifier_type) {
        case 0:
            out.identifierType = UA_NODEIDTYPE_NUMERIC;
            out.identifier.numeric = (UA_UInt32)n->numeric_id;
            break;
        case 1:
            out.identifierType = UA_NODEIDTYPE_STRING;
            out.identifier.string = UA_String_fromChars(n->string_id ? n->string_id : "");
            break;
        case 2:
            out.identifierType = UA_NODEIDTYPE_GUID;
            if (UA_Guid_parse(&out.identifier.guid, UA_STRING(n->string_id ? n->string_id : "")) != UA_STATUSCODE_GOOD) {
                UA_Guid_init(&out.identifier.guid);
            }
            break;
        case 3: {
            out.identifierType = UA_NODEIDTYPE_BYTESTRING;
            UA_ByteString_init(&out.identifier.byteString);
            if (n->bytes_id && n->bytes_id->len > 0) {
                out.identifier.byteString.length = (size_t)n->bytes_id->len;
                out.identifier.byteString.data = (UA_Byte *)UA_malloc(out.identifier.byteString.length);
                for (size_t i = 0; i < out.identifier.byteString.length; i++) {
                    unsigned char *p = (unsigned char *)sn_array_get(n->bytes_id, (long long)i);
                    out.identifier.byteString.data[i] = p ? *p : 0;
                }
            }
            break;
        }
    }
    return out;
}

/* Build a Sindarin node id from a UA_NodeId. */
static RtOpcUaNodeId *opcua_from_ua_node_id(const UA_NodeId *n) {
    if (!n) return sn_opcua_node_id_numeric(0, 0);
    switch (n->identifierType) {
        case UA_NODEIDTYPE_NUMERIC:
            return sn_opcua_node_id_numeric(n->namespaceIndex, n->identifier.numeric);
        case UA_NODEIDTYPE_STRING: {
            char *s = opcua_strdup_ua_string(&n->identifier.string);
            RtOpcUaNodeId *out = sn_opcua_node_id_string(n->namespaceIndex, s);
            free(s);
            return out;
        }
        case UA_NODEIDTYPE_GUID: {
            char buf[64];
            snprintf(buf, sizeof(buf),
                     "%08X-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X",
                     n->identifier.guid.data1, n->identifier.guid.data2, n->identifier.guid.data3,
                     n->identifier.guid.data4[0], n->identifier.guid.data4[1],
                     n->identifier.guid.data4[2], n->identifier.guid.data4[3],
                     n->identifier.guid.data4[4], n->identifier.guid.data4[5],
                     n->identifier.guid.data4[6], n->identifier.guid.data4[7]);
            return sn_opcua_node_id_guid(n->namespaceIndex, buf);
        }
        case UA_NODEIDTYPE_BYTESTRING: {
            size_t len = n->identifier.byteString.length;
            SnArray *a = opcua_byte_array_from_buf(
                (const unsigned char *)n->identifier.byteString.data, len);
            RtOpcUaNodeId *out = sn_opcua_node_id_bytestring(n->namespaceIndex, a);
            return out;
        }
    }
    return sn_opcua_node_id_numeric(0, 0);
}

/* ============================================================================
 * OpcUaVariant - stores a heap-allocated UA_Variant
 * ============================================================================ */

static UA_Variant *opcua_variant_ptr(RtOpcUaVariant *v) {
    return (UA_Variant *)(uintptr_t)v->internal_ptr;
}

/* Translate open62541's internal UA_DataTypeKind enum (0-based, Boolean=0)
 * into the OPC UA spec BuiltInType id (1-based, Boolean=1, Part 6 §5.1.2).
 * The Sindarin-facing contract in opcua.sn:325 promises spec numbering, so
 * this mapping is the canonical boundary between the two. Kinds that have
 * no direct BuiltInType (Decimal, Enum, Structure, Union, ...) fall through
 * to 0 (unknown). */
static int opcua_variant_type_code_for(const UA_Variant *v) {
    if (!v || !v->type) return 0;
    switch (v->type->typeKind) {
    case UA_DATATYPEKIND_BOOLEAN:         return 1;
    case UA_DATATYPEKIND_SBYTE:           return 2;
    case UA_DATATYPEKIND_BYTE:            return 3;
    case UA_DATATYPEKIND_INT16:           return 4;
    case UA_DATATYPEKIND_UINT16:          return 5;
    case UA_DATATYPEKIND_INT32:           return 6;
    case UA_DATATYPEKIND_UINT32:          return 7;
    case UA_DATATYPEKIND_INT64:           return 8;
    case UA_DATATYPEKIND_UINT64:          return 9;
    case UA_DATATYPEKIND_FLOAT:           return 10;
    case UA_DATATYPEKIND_DOUBLE:          return 11;
    case UA_DATATYPEKIND_STRING:          return 12;
    case UA_DATATYPEKIND_DATETIME:        return 13;
    case UA_DATATYPEKIND_GUID:            return 14;
    case UA_DATATYPEKIND_BYTESTRING:      return 15;
    case UA_DATATYPEKIND_XMLELEMENT:      return 16;
    case UA_DATATYPEKIND_NODEID:          return 17;
    case UA_DATATYPEKIND_EXPANDEDNODEID:  return 18;
    case UA_DATATYPEKIND_STATUSCODE:      return 19;
    case UA_DATATYPEKIND_QUALIFIEDNAME:   return 20;
    case UA_DATATYPEKIND_LOCALIZEDTEXT:   return 21;
    case UA_DATATYPEKIND_EXTENSIONOBJECT: return 22;
    case UA_DATATYPEKIND_DATAVALUE:       return 23;
    case UA_DATATYPEKIND_VARIANT:         return 24;
    case UA_DATATYPEKIND_DIAGNOSTICINFO:  return 25;
    default:                              return 0;
    }
}

static RtOpcUaVariant *opcua_wrap_variant_take(UA_Variant *src) {
    /* Consumes src (must be heap-allocated). */
    RtOpcUaVariant *v = __sn__OpcUaVariant__new();
    v->type_code    = opcua_variant_type_code_for(src);
    v->is_array     = UA_Variant_isScalar(src) ? 0 : 1;
    v->internal_ptr = (long long)(uintptr_t)src;
    return v;
}

static RtOpcUaVariant *opcua_new_scalar_variant(const void *value, const UA_DataType *type) {
    UA_Variant *ua = (UA_Variant *)UA_Variant_new();
    UA_Variant_setScalarCopy(ua, value, type);
    return opcua_wrap_variant_take(ua);
}

RtOpcUaVariant *sn_opcua_variant_null(void) {
    UA_Variant *ua = (UA_Variant *)UA_Variant_new();
    RtOpcUaVariant *v = __sn__OpcUaVariant__new();
    v->type_code = 0;
    v->is_array  = 0;
    v->internal_ptr = (long long)(uintptr_t)ua;
    return v;
}

RtOpcUaVariant *sn_opcua_variant_from_bool(bool b) {
    UA_Boolean val = b ? UA_TRUE : UA_FALSE;
    return opcua_new_scalar_variant(&val, &UA_TYPES[UA_TYPES_BOOLEAN]);
}

RtOpcUaVariant *sn_opcua_variant_from_int(long long i) {
    UA_Int32 val = (UA_Int32)i;
    return opcua_new_scalar_variant(&val, &UA_TYPES[UA_TYPES_INT32]);
}

RtOpcUaVariant *sn_opcua_variant_from_long(long long i) {
    UA_Int64 val = (UA_Int64)i;
    return opcua_new_scalar_variant(&val, &UA_TYPES[UA_TYPES_INT64]);
}

RtOpcUaVariant *sn_opcua_variant_from_double(double d) {
    return opcua_new_scalar_variant(&d, &UA_TYPES[UA_TYPES_DOUBLE]);
}

RtOpcUaVariant *sn_opcua_variant_from_str(char *s) {
    UA_String ua = UA_String_fromChars(s ? s : "");
    RtOpcUaVariant *v = opcua_new_scalar_variant(&ua, &UA_TYPES[UA_TYPES_STRING]);
    UA_String_clear(&ua);
    return v;
}

RtOpcUaVariant *sn_opcua_variant_from_bytes(SnArray *bytes) {
    UA_ByteString bs = opcua_bytestring_from_array(bytes);
    RtOpcUaVariant *v = opcua_new_scalar_variant(&bs, &UA_TYPES[UA_TYPES_BYTESTRING]);
    UA_ByteString_clear(&bs);
    return v;
}

RtOpcUaVariant *sn_opcua_variant_from_node_id(RtOpcUaNodeId *nodeId) {
    UA_NodeId ua = opcua_to_ua_node_id(nodeId);
    RtOpcUaVariant *v = opcua_new_scalar_variant(&ua, &UA_TYPES[UA_TYPES_NODEID]);
    UA_NodeId_clear(&ua);
    return v;
}

long long sn_opcua_variant_type_code(RtOpcUaVariant *v) {
    if (!v) return 0;
    return v->type_code;
}

bool sn_opcua_variant_is_array(RtOpcUaVariant *v) {
    if (!v) return false;
    return v->is_array != 0;
}

bool sn_opcua_variant_is_null(RtOpcUaVariant *v) {
    if (!v) return true;
    UA_Variant *u = opcua_variant_ptr(v);
    return !u || u->type == NULL;
}

bool sn_opcua_variant_as_bool(RtOpcUaVariant *v) {
    UA_Variant *u = v ? opcua_variant_ptr(v) : NULL;
    if (!u || u->type != &UA_TYPES[UA_TYPES_BOOLEAN]) return false;
    return *(UA_Boolean *)u->data ? true : false;
}

long long sn_opcua_variant_as_int(RtOpcUaVariant *v) {
    UA_Variant *u = v ? opcua_variant_ptr(v) : NULL;
    if (!u || !u->type) return 0;
    if (u->type == &UA_TYPES[UA_TYPES_INT32])  return (long long)*(UA_Int32  *)u->data;
    if (u->type == &UA_TYPES[UA_TYPES_UINT32]) return (long long)*(UA_UInt32 *)u->data;
    if (u->type == &UA_TYPES[UA_TYPES_INT16])  return (long long)*(UA_Int16  *)u->data;
    if (u->type == &UA_TYPES[UA_TYPES_UINT16]) return (long long)*(UA_UInt16 *)u->data;
    if (u->type == &UA_TYPES[UA_TYPES_SBYTE])  return (long long)*(UA_SByte  *)u->data;
    if (u->type == &UA_TYPES[UA_TYPES_BYTE])   return (long long)*(UA_Byte   *)u->data;
    if (u->type == &UA_TYPES[UA_TYPES_INT64])  return (long long)*(UA_Int64  *)u->data;
    if (u->type == &UA_TYPES[UA_TYPES_UINT64]) return (long long)*(UA_UInt64 *)u->data;
    return 0;
}

long long sn_opcua_variant_as_long(RtOpcUaVariant *v) {
    return sn_opcua_variant_as_int(v);
}

double sn_opcua_variant_as_double(RtOpcUaVariant *v) {
    UA_Variant *u = v ? opcua_variant_ptr(v) : NULL;
    if (!u || !u->type) return 0.0;
    if (u->type == &UA_TYPES[UA_TYPES_DOUBLE]) return *(UA_Double *)u->data;
    if (u->type == &UA_TYPES[UA_TYPES_FLOAT])  return (double)*(UA_Float *)u->data;
    return (double)sn_opcua_variant_as_int(v);
}

char *sn_opcua_variant_as_str(RtOpcUaVariant *v) {
    UA_Variant *u = v ? opcua_variant_ptr(v) : NULL;
    if (!u || !u->type) return strdup("");
    if (u->type == &UA_TYPES[UA_TYPES_STRING])
        return opcua_strdup_ua_string((UA_String *)u->data);
    if (u->type == &UA_TYPES[UA_TYPES_LOCALIZEDTEXT])
        return opcua_strdup_ua_string(&((UA_LocalizedText *)u->data)->text);
    if (u->type == &UA_TYPES[UA_TYPES_QUALIFIEDNAME])
        return opcua_strdup_ua_string(&((UA_QualifiedName *)u->data)->name);
    return strdup("");
}

SnArray *sn_opcua_variant_as_bytes(RtOpcUaVariant *v) {
    UA_Variant *u = v ? opcua_variant_ptr(v) : NULL;
    if (!u || !u->type) return opcua_empty_byte_array();
    if (u->type == &UA_TYPES[UA_TYPES_BYTESTRING])
        return opcua_byte_array_from_bytestring((UA_ByteString *)u->data);
    return opcua_empty_byte_array();
}

RtOpcUaNodeId *sn_opcua_variant_as_node_id(RtOpcUaVariant *v) {
    UA_Variant *u = v ? opcua_variant_ptr(v) : NULL;
    if (!u || !u->type || u->type != &UA_TYPES[UA_TYPES_NODEID])
        return sn_opcua_node_id_numeric(0, 0);
    return opcua_from_ua_node_id((UA_NodeId *)u->data);
}

/* Array accessors. */
static SnArray *opcua_bool_array(const UA_Variant *u) {
    SnArray *a = sn_array_new(sizeof(bool), (long long)u->arrayLength);
    a->elem_tag = SN_TAG_BOOL;
    UA_Boolean *src = (UA_Boolean *)u->data;
    for (size_t i = 0; i < u->arrayLength; i++) {
        bool b = src[i] ? true : false;
        sn_array_push(a, &b);
    }
    return a;
}
static SnArray *opcua_int_array(const UA_Variant *u) {
    SnArray *a = sn_array_new(sizeof(long long), (long long)u->arrayLength);
    a->elem_tag = SN_TAG_INT;
    for (size_t i = 0; i < u->arrayLength; i++) {
        long long val = 0;
        if (u->type == &UA_TYPES[UA_TYPES_INT32])       val = (long long)((UA_Int32  *)u->data)[i];
        else if (u->type == &UA_TYPES[UA_TYPES_UINT32]) val = (long long)((UA_UInt32 *)u->data)[i];
        else if (u->type == &UA_TYPES[UA_TYPES_INT16])  val = (long long)((UA_Int16  *)u->data)[i];
        else if (u->type == &UA_TYPES[UA_TYPES_UINT16]) val = (long long)((UA_UInt16 *)u->data)[i];
        else if (u->type == &UA_TYPES[UA_TYPES_SBYTE])  val = (long long)((UA_SByte  *)u->data)[i];
        else if (u->type == &UA_TYPES[UA_TYPES_BYTE])   val = (long long)((UA_Byte   *)u->data)[i];
        else if (u->type == &UA_TYPES[UA_TYPES_INT64])  val = (long long)((UA_Int64  *)u->data)[i];
        else if (u->type == &UA_TYPES[UA_TYPES_UINT64]) val = (long long)((UA_UInt64 *)u->data)[i];
        sn_array_push(a, &val);
    }
    return a;
}
static SnArray *opcua_double_array(const UA_Variant *u) {
    SnArray *a = sn_array_new(sizeof(double), (long long)u->arrayLength);
    a->elem_tag = SN_TAG_DOUBLE;
    for (size_t i = 0; i < u->arrayLength; i++) {
        double val = 0.0;
        if (u->type == &UA_TYPES[UA_TYPES_DOUBLE]) val = ((UA_Double *)u->data)[i];
        else if (u->type == &UA_TYPES[UA_TYPES_FLOAT])  val = (double)((UA_Float  *)u->data)[i];
        sn_array_push(a, &val);
    }
    return a;
}
static SnArray *opcua_str_array(const UA_Variant *u) {
    SnArray *a = opcua_empty_string_array();
    for (size_t i = 0; i < u->arrayLength; i++) {
        char *s;
        if (u->type == &UA_TYPES[UA_TYPES_STRING])
            s = opcua_strdup_ua_string(&((UA_String *)u->data)[i]);
        else if (u->type == &UA_TYPES[UA_TYPES_LOCALIZEDTEXT])
            s = opcua_strdup_ua_string(&((UA_LocalizedText *)u->data)[i].text);
        else
            s = strdup("");
        sn_array_push(a, &s);
    }
    return a;
}

SnArray *sn_opcua_variant_as_bool_array(RtOpcUaVariant *v) {
    UA_Variant *u = v ? opcua_variant_ptr(v) : NULL;
    if (!u || !u->type || UA_Variant_isScalar(u)) {
        SnArray *a = sn_array_new(sizeof(bool), 0);
        a->elem_tag = SN_TAG_BOOL;
        return a;
    }
    return opcua_bool_array(u);
}

SnArray *sn_opcua_variant_as_int_array(RtOpcUaVariant *v) {
    UA_Variant *u = v ? opcua_variant_ptr(v) : NULL;
    if (!u || !u->type || UA_Variant_isScalar(u)) {
        SnArray *a = sn_array_new(sizeof(long long), 0);
        a->elem_tag = SN_TAG_INT;
        return a;
    }
    return opcua_int_array(u);
}

SnArray *sn_opcua_variant_as_long_array(RtOpcUaVariant *v) {
    return sn_opcua_variant_as_int_array(v);
}

SnArray *sn_opcua_variant_as_double_array(RtOpcUaVariant *v) {
    UA_Variant *u = v ? opcua_variant_ptr(v) : NULL;
    if (!u || !u->type || UA_Variant_isScalar(u)) {
        SnArray *a = sn_array_new(sizeof(double), 0);
        a->elem_tag = SN_TAG_DOUBLE;
        return a;
    }
    return opcua_double_array(u);
}

SnArray *sn_opcua_variant_as_str_array(RtOpcUaVariant *v) {
    UA_Variant *u = v ? opcua_variant_ptr(v) : NULL;
    if (!u || !u->type || UA_Variant_isScalar(u)) {
        return opcua_empty_string_array();
    }
    return opcua_str_array(u);
}

char *sn_opcua_variant_to_string(RtOpcUaVariant *v) {
    if (!v) return strdup("<null>");
    UA_Variant *u = opcua_variant_ptr(v);
    if (!u || !u->type) return strdup("<null>");
    if (UA_Variant_isScalar(u)) {
        if (u->type == &UA_TYPES[UA_TYPES_BOOLEAN]) {
            return strdup(*(UA_Boolean *)u->data ? "true" : "false");
        }
        char buf[96];
        /* Every OPC UA built-in numeric scalar gets a dedicated format so
         * downstream logs show real values instead of the fallback token. */
        if (u->type == &UA_TYPES[UA_TYPES_SBYTE])  { snprintf(buf,sizeof(buf),"%d",   (int)*(UA_SByte  *)u->data); return strdup(buf); }
        if (u->type == &UA_TYPES[UA_TYPES_BYTE])   { snprintf(buf,sizeof(buf),"%u",   (unsigned)*(UA_Byte *)u->data); return strdup(buf); }
        if (u->type == &UA_TYPES[UA_TYPES_INT16])  { snprintf(buf,sizeof(buf),"%d",   (int)*(UA_Int16  *)u->data); return strdup(buf); }
        if (u->type == &UA_TYPES[UA_TYPES_UINT16]) { snprintf(buf,sizeof(buf),"%u",   (unsigned)*(UA_UInt16 *)u->data); return strdup(buf); }
        if (u->type == &UA_TYPES[UA_TYPES_INT32])  { snprintf(buf,sizeof(buf),"%d",   *(UA_Int32  *)u->data); return strdup(buf); }
        if (u->type == &UA_TYPES[UA_TYPES_UINT32]) { snprintf(buf,sizeof(buf),"%u",   *(UA_UInt32 *)u->data); return strdup(buf); }
        if (u->type == &UA_TYPES[UA_TYPES_INT64])  { snprintf(buf,sizeof(buf),"%lld", (long long)*(UA_Int64  *)u->data); return strdup(buf); }
        if (u->type == &UA_TYPES[UA_TYPES_UINT64]) { snprintf(buf,sizeof(buf),"%llu", (unsigned long long)*(UA_UInt64 *)u->data); return strdup(buf); }
        if (u->type == &UA_TYPES[UA_TYPES_FLOAT])  { snprintf(buf,sizeof(buf),"%.9g", (double)*(UA_Float *)u->data); return strdup(buf); }
        if (u->type == &UA_TYPES[UA_TYPES_DOUBLE]) { snprintf(buf,sizeof(buf),"%.17g",*(UA_Double *)u->data); return strdup(buf); }
        if (u->type == &UA_TYPES[UA_TYPES_STRING]) { return opcua_strdup_ua_string((UA_String *)u->data); }
        if (u->type == &UA_TYPES[UA_TYPES_DATETIME]) {
            UA_DateTimeStruct ts = UA_DateTime_toStruct(*(UA_DateTime *)u->data);
            snprintf(buf, sizeof(buf),
                     "%04u-%02u-%02uT%02u:%02u:%02u.%03uZ",
                     ts.year, ts.month, ts.day, ts.hour, ts.min, ts.sec, ts.milliSec);
            return strdup(buf);
        }
    }
    char buf[64];
    snprintf(buf, sizeof(buf), "<Variant typeKind=%d arrayLen=%zu>",
             (int)u->type->typeKind, UA_Variant_isScalar(u) ? 0 : u->arrayLength);
    return strdup(buf);
}

void sn_opcua_variant_dispose(RtOpcUaVariant *v) {
    if (!v) return;
    UA_Variant *u = opcua_variant_ptr(v);
    if (u) {
        UA_Variant_clear(u);
        UA_free(u);
    }
    v->internal_ptr = 0;
}

/* ============================================================================
 * OpcUaReferenceDescription
 * ============================================================================ */

static RtOpcUaReferenceDescription *opcua_from_ua_ref_desc(const UA_ReferenceDescription *r) {
    RtOpcUaReferenceDescription *d = __sn__OpcUaReferenceDescription__new();
    d->node_id            = opcua_from_ua_node_id(&r->nodeId.nodeId);
    d->reference_type_id  = opcua_from_ua_node_id(&r->referenceTypeId);
    d->type_definition    = opcua_from_ua_node_id(&r->typeDefinition.nodeId);
    d->browse_name        = opcua_strdup_ua_string(&r->browseName.name);
    d->display_name       = opcua_strdup_ua_string(&r->displayName.text);
    d->node_class         = (long long)r->nodeClass;
    d->is_forward         = r->isForward ? 1 : 0;
    return d;
}

RtOpcUaNodeId *sn_opcua_reference_description_node_id(RtOpcUaReferenceDescription *r) {
    if (!r) return sn_opcua_node_id_numeric(0, 0);
    return (RtOpcUaNodeId *)__sn__OpcUaNodeId_retain(r->node_id);
}

char *sn_opcua_reference_description_browse_name(RtOpcUaReferenceDescription *r) {
    return r && r->browse_name ? strdup(r->browse_name) : strdup("");
}

char *sn_opcua_reference_description_display_name(RtOpcUaReferenceDescription *r) {
    return r && r->display_name ? strdup(r->display_name) : strdup("");
}

long long sn_opcua_reference_description_node_class(RtOpcUaReferenceDescription *r) {
    return r ? r->node_class : 0;
}

bool sn_opcua_reference_description_is_forward(RtOpcUaReferenceDescription *r) {
    return r ? (r->is_forward != 0) : false;
}

void sn_opcua_reference_description_dispose(RtOpcUaReferenceDescription *r) {
    (void)r;
}

/* ============================================================================
 * OpcUaEndpointDescription
 * ============================================================================ */

static RtOpcUaEndpointDescription *opcua_from_ua_endpoint(const UA_EndpointDescription *e) {
    RtOpcUaEndpointDescription *d = __sn__OpcUaEndpointDescription__new();
    d->endpoint_url         = opcua_strdup_ua_string(&e->endpointUrl);
    d->security_policy_uri  = opcua_strdup_ua_string(&e->securityPolicyUri);
    d->security_mode        = (long long)e->securityMode;
    d->server_certificate   = opcua_byte_array_from_bytestring(&e->serverCertificate);
    d->security_level       = (long long)e->securityLevel;
    d->transport_profile_uri = opcua_strdup_ua_string(&e->transportProfileUri);
    return d;
}

char *sn_opcua_endpoint_description_endpoint_url(RtOpcUaEndpointDescription *d) {
    return d && d->endpoint_url ? strdup(d->endpoint_url) : strdup("");
}

char *sn_opcua_endpoint_description_security_policy_uri(RtOpcUaEndpointDescription *d) {
    return d && d->security_policy_uri ? strdup(d->security_policy_uri) : strdup("");
}

long long sn_opcua_endpoint_description_security_mode(RtOpcUaEndpointDescription *d) {
    return d ? d->security_mode : 1;
}

SnArray *sn_opcua_endpoint_description_server_certificate(RtOpcUaEndpointDescription *d) {
    if (!d || !d->server_certificate || d->server_certificate->len == 0)
        return opcua_empty_byte_array();
    return opcua_byte_array_from_buf(
        (unsigned char *)sn_array_get(d->server_certificate, 0),
        (size_t)d->server_certificate->len);
}

long long sn_opcua_endpoint_description_security_level(RtOpcUaEndpointDescription *d) {
    return d ? d->security_level : 0;
}

char *sn_opcua_endpoint_description_transport_profile_uri(RtOpcUaEndpointDescription *d) {
    return d && d->transport_profile_uri ? strdup(d->transport_profile_uri) : strdup("");
}

/* Server-provided user token policy IDs. (Populated at getEndpoints time.) */
SnArray *sn_opcua_endpoint_description_user_token_policies(RtOpcUaEndpointDescription *d) {
    (void)d;
    /* Populated at call time via internal attachment not exposed in the
     * minimal first-cut struct. Return empty array for now. */
    return opcua_empty_string_array();
}

void sn_opcua_endpoint_description_dispose(RtOpcUaEndpointDescription *d) {
    (void)d;
}

/* ============================================================================
 * OpcUaApplicationDescription
 * ============================================================================ */

static RtOpcUaApplicationDescription *opcua_from_ua_app_desc(const UA_ApplicationDescription *a) {
    RtOpcUaApplicationDescription *d = __sn__OpcUaApplicationDescription__new();
    d->application_uri      = opcua_strdup_ua_string(&a->applicationUri);
    d->product_uri          = opcua_strdup_ua_string(&a->productUri);
    d->application_name     = opcua_strdup_ua_string(&a->applicationName.text);
    d->application_type     = (long long)a->applicationType;
    d->gateway_server_uri   = opcua_strdup_ua_string(&a->gatewayServerUri);
    d->discovery_profile_uri = opcua_strdup_ua_string(&a->discoveryProfileUri);
    return d;
}

char *sn_opcua_application_description_application_uri(RtOpcUaApplicationDescription *d) {
    return d && d->application_uri ? strdup(d->application_uri) : strdup("");
}

char *sn_opcua_application_description_product_uri(RtOpcUaApplicationDescription *d) {
    return d && d->product_uri ? strdup(d->product_uri) : strdup("");
}

char *sn_opcua_application_description_application_name(RtOpcUaApplicationDescription *d) {
    return d && d->application_name ? strdup(d->application_name) : strdup("");
}

long long sn_opcua_application_description_application_type(RtOpcUaApplicationDescription *d) {
    return d ? d->application_type : 0;
}

SnArray *sn_opcua_application_description_discovery_urls(RtOpcUaApplicationDescription *d) {
    (void)d;
    return opcua_empty_string_array();
}

void sn_opcua_application_description_dispose(RtOpcUaApplicationDescription *d) {
    (void)d;
}

/* ============================================================================
 * OpcUaDataChangeEvent / MonitoredItem / Subscription internals
 * ============================================================================ */

#define OPCUA_EVENT_QUEUE_MAX 1024

typedef struct OpcUaEventNode {
    UA_UInt32   monitored_item_id;
    UA_Variant *value;   /* heap */
    UA_DateTime src_ts;
    UA_DateTime srv_ts;
    UA_StatusCode status;
    struct OpcUaEventNode *next;
} OpcUaEventNode;

typedef struct {
    opcua_mutex_t    mutex;
    opcua_cond_t     cond;
    OpcUaEventNode  *head;
    OpcUaEventNode  *tail;
    size_t           count;
    UA_UInt32        subscription_id;
    bool             deleted;
    struct RtOpcUaClient *client;  /* weak back-pointer */
} OpcUaSubscriptionInternal;

static OpcUaSubscriptionInternal *opcua_sub_internal(RtOpcUaSubscription *s) {
    return (OpcUaSubscriptionInternal *)(uintptr_t)s->internal_ptr;
}

static void opcua_event_queue_push(OpcUaSubscriptionInternal *si, OpcUaEventNode *node) {
    OPCUA_MUTEX_LOCK(&si->mutex);
    if (si->count >= OPCUA_EVENT_QUEUE_MAX) {
        /* drop oldest to keep bound */
        OpcUaEventNode *drop = si->head;
        si->head = drop->next;
        if (!si->head) si->tail = NULL;
        si->count--;
        if (drop->value) { UA_Variant_clear(drop->value); UA_free(drop->value); }
        free(drop);
    }
    node->next = NULL;
    if (si->tail) { si->tail->next = node; si->tail = node; }
    else { si->head = si->tail = node; }
    si->count++;
    OPCUA_COND_SIGNAL(&si->cond);
    OPCUA_MUTEX_UNLOCK(&si->mutex);
}

static OpcUaEventNode *opcua_event_queue_pop(OpcUaSubscriptionInternal *si, int timeout_ms) {
    OPCUA_MUTEX_LOCK(&si->mutex);
    if (si->count == 0 && timeout_ms > 0 && !si->deleted) {
        OPCUA_COND_TIMEDWAIT(&si->cond, &si->mutex, timeout_ms);
    }
    OpcUaEventNode *node = si->head;
    if (node) {
        si->head = node->next;
        if (!si->head) si->tail = NULL;
        si->count--;
    }
    OPCUA_MUTEX_UNLOCK(&si->mutex);
    return node;
}

/* ============================================================================
 * OpcUaMonitoredItem internals
 * ============================================================================ */

/* Lightweight context attached as monitored-item context so the
 * dataChangeNotificationCallback can route into the subscription queue. */
typedef struct {
    OpcUaSubscriptionInternal *sub_internal;
    UA_UInt32                  monitored_item_id;
} OpcUaMonitoredItemContext;

static void
opcua_data_change_callback(UA_Client *client, UA_UInt32 subId, void *subContext,
                           UA_UInt32 monId, void *monContext, UA_DataValue *value) {
    (void)client;
    (void)subContext;
    (void)subId;
    OpcUaMonitoredItemContext *ctx = (OpcUaMonitoredItemContext *)monContext;
    if (!ctx || !ctx->sub_internal) return;

    OpcUaEventNode *node = (OpcUaEventNode *)calloc(1, sizeof(*node));
    node->monitored_item_id = monId;
    node->value = (UA_Variant *)UA_Variant_new();
    if (value && value->hasValue) {
        UA_Variant_copy(&value->value, node->value);
    }
    node->src_ts = value && value->hasSourceTimestamp ? value->sourceTimestamp : 0;
    node->srv_ts = value && value->hasServerTimestamp ? value->serverTimestamp : 0;
    node->status = value ? value->status : UA_STATUSCODE_GOOD;

    opcua_event_queue_push(ctx->sub_internal, node);
}

static long long opcua_ua_datetime_to_unix_ms(UA_DateTime t) {
    /* UA_DateTime is 100ns intervals since 1601-01-01. Unix epoch is 1970. */
    const long long UNIX_EPOCH_OFFSET_100NS = 116444736000000000LL;
    if (t == 0) return 0;
    return (long long)((t - UNIX_EPOCH_OFFSET_100NS) / 10000LL);
}

long long sn_opcua_monitored_item_id(RtOpcUaMonitoredItem *m) {
    return m ? m->id : 0;
}

double sn_opcua_monitored_item_sampling_interval(RtOpcUaMonitoredItem *m) {
    (void)m; return -1.0;
}

long long sn_opcua_monitored_item_queue_size(RtOpcUaMonitoredItem *m) {
    (void)m; return 1;
}

/* Forward decl */
static void opcua_client_lock(RtOpcUaClient *c);
static void opcua_client_unlock(RtOpcUaClient *c);
static UA_Client *opcua_client_ua(RtOpcUaClient *c);

void sn_opcua_monitored_item_remove(RtOpcUaMonitoredItem *m) {
    if (!m || m->client_ptr == 0 || m->subscription_ptr == 0) return;
    RtOpcUaClient *client = (RtOpcUaClient *)(uintptr_t)m->client_ptr;
    RtOpcUaSubscription *sub = (RtOpcUaSubscription *)(uintptr_t)m->subscription_ptr;
    opcua_client_lock(client);
    UA_Client *ua = opcua_client_ua(client);
    if (ua) {
        UA_Client_MonitoredItems_deleteSingle(ua, (UA_UInt32)sub->subscription_id,
                                              (UA_UInt32)m->id);
    }
    opcua_client_unlock(client);
}

void sn_opcua_monitored_item_dispose(RtOpcUaMonitoredItem *m) {
    (void)m;
}

/* ============================================================================
 * OpcUaSubscription
 * ============================================================================ */

long long sn_opcua_subscription_id(RtOpcUaSubscription *s) {
    return s ? s->subscription_id : 0;
}

double sn_opcua_subscription_publish_interval(RtOpcUaSubscription *s) {
    (void)s; return 0.0;
}

RtOpcUaMonitoredItem *sn_opcua_subscription_monitor_data_change(
    RtOpcUaSubscription *sub, RtOpcUaNodeId *nodeId,
    double samplingIntervalMs, long long queueSize) {
    if (!sub) return NULL;
    RtOpcUaClient *client = (RtOpcUaClient *)(uintptr_t)sub->client_ptr;

    UA_MonitoredItemCreateRequest req = UA_MonitoredItemCreateRequest_default(
        opcua_to_ua_node_id(nodeId));
    if (samplingIntervalMs >= 0.0)
        req.requestedParameters.samplingInterval = samplingIntervalMs;
    req.requestedParameters.queueSize = (UA_UInt32)(queueSize > 0 ? queueSize : 1);
    req.requestedParameters.discardOldest = UA_TRUE;

    OpcUaMonitoredItemContext *ctx =
        (OpcUaMonitoredItemContext *)calloc(1, sizeof(*ctx));
    ctx->sub_internal = opcua_sub_internal(sub);

    opcua_client_lock(client);
    UA_Client *ua = opcua_client_ua(client);
    UA_MonitoredItemCreateResult result =
        UA_Client_MonitoredItems_createDataChange(ua, (UA_UInt32)sub->subscription_id,
            UA_TIMESTAMPSTORETURN_BOTH, req, ctx, opcua_data_change_callback, NULL);
    opcua_client_unlock(client);

    UA_NodeId_clear(&req.itemToMonitor.nodeId);

    if (result.statusCode != UA_STATUSCODE_GOOD) {
        fprintf(stderr, "OpcUaSubscription.monitor: %s\n",
                UA_StatusCode_name(result.statusCode));
        free(ctx);
        return NULL;
    }
    ctx->monitored_item_id = result.monitoredItemId;

    RtOpcUaMonitoredItem *m = __sn__OpcUaMonitoredItem__new();
    m->id               = (long long)result.monitoredItemId;
    m->subscription_ptr = (long long)(uintptr_t)sub;
    m->client_ptr       = (long long)(uintptr_t)client;
    return m;
}

RtOpcUaDataChangeEvent *sn_opcua_subscription_next_event(RtOpcUaSubscription *sub, long long timeoutMs) {
    RtOpcUaDataChangeEvent *ev = __sn__OpcUaDataChangeEvent__new();
    if (!sub) {
        ev->is_empty = 1;
        return ev;
    }
    OpcUaSubscriptionInternal *si = opcua_sub_internal(sub);
    OpcUaEventNode *node = opcua_event_queue_pop(si, (int)timeoutMs);
    if (!node) {
        ev->is_empty = 1;
        return ev;
    }
    ev->monitored_item_id   = (long long)node->monitored_item_id;
    ev->subscription_id     = (long long)si->subscription_id;
    ev->value               = opcua_wrap_variant_take(node->value);
    ev->source_timestamp_ms = opcua_ua_datetime_to_unix_ms(node->src_ts);
    ev->server_timestamp_ms = opcua_ua_datetime_to_unix_ms(node->srv_ts);
    ev->status_code         = (long long)node->status;
    ev->is_empty            = 0;
    free(node);
    return ev;
}

long long sn_opcua_data_change_event_monitored_item_id(RtOpcUaDataChangeEvent *e) { return e ? e->monitored_item_id : 0; }
long long sn_opcua_data_change_event_subscription_id(RtOpcUaDataChangeEvent *e)   { return e ? e->subscription_id : 0; }
long long sn_opcua_data_change_event_source_timestamp_ms(RtOpcUaDataChangeEvent *e) { return e ? e->source_timestamp_ms : 0; }
long long sn_opcua_data_change_event_server_timestamp_ms(RtOpcUaDataChangeEvent *e) { return e ? e->server_timestamp_ms : 0; }
long long sn_opcua_data_change_event_status_code(RtOpcUaDataChangeEvent *e)       { return e ? e->status_code : 0; }
bool      sn_opcua_data_change_event_is_empty(RtOpcUaDataChangeEvent *e)          { return e ? (e->is_empty != 0) : true; }

RtOpcUaVariant *sn_opcua_data_change_event_value(RtOpcUaDataChangeEvent *e) {
    if (!e || !e->value) return sn_opcua_variant_null();
    return (RtOpcUaVariant *)__sn__OpcUaVariant_retain(e->value);
}

void sn_opcua_data_change_event_dispose(RtOpcUaDataChangeEvent *e) {
    /* Release the event's owned Variant wrapper so its underlying UA_Variant
     * is freed via sn_opcua_variant_dispose. Previously this was a no-op,
     * leaking the Variant wrapper + UA_Variant heap memory for every event
     * — the dominant per-event memory leak in subscription-heavy clients. */
    if (!e || !e->value) return;
    __sn__OpcUaVariant_release(&e->value);
}

void sn_opcua_subscription_delete(RtOpcUaSubscription *sub) {
    if (!sub) return;
    OpcUaSubscriptionInternal *si = opcua_sub_internal(sub);
    RtOpcUaClient *client = (RtOpcUaClient *)(uintptr_t)sub->client_ptr;
    opcua_client_lock(client);
    UA_Client *ua = opcua_client_ua(client);
    if (ua) UA_Client_Subscriptions_deleteSingle(ua, (UA_UInt32)sub->subscription_id);
    opcua_client_unlock(client);

    OPCUA_MUTEX_LOCK(&si->mutex);
    si->deleted = true;
    OPCUA_COND_BROADCAST(&si->cond);
    OPCUA_MUTEX_UNLOCK(&si->mutex);
}

void sn_opcua_subscription_dispose(RtOpcUaSubscription *sub) {
    if (!sub) return;
    OpcUaSubscriptionInternal *si = opcua_sub_internal(sub);
    if (!si) return;

    /* Drain any remaining events. */
    OpcUaEventNode *n = si->head;
    while (n) {
        OpcUaEventNode *next = n->next;
        if (n->value) { UA_Variant_clear(n->value); UA_free(n->value); }
        free(n);
        n = next;
    }
    OPCUA_MUTEX_DESTROY(&si->mutex);
    OPCUA_COND_DESTROY(&si->cond);
    free(si);
    sub->internal_ptr = 0;
}

/* ============================================================================
 * OpcUaClientConfig
 * ============================================================================ */

typedef struct {
    /* Application identity */
    char *application_uri;
    char *application_name;
    char *product_uri;

    /* Security */
    int   security_policy_code;     /* 0..5 */
    int   message_security_mode;    /* 1..3 */
    bool  hostname_verification;

    /* User identity */
    int   user_kind;                /* 0..3 */
    char *username;
    char *password;
    char *user_cert_path;
    char *user_key_path;
    unsigned char *issued_token;
    size_t issued_token_len;
    char *token_type;

    /* PKI */
    char *client_cert_path;
    char *client_key_path;
    RtOpcUaTrustList *trust_list;

    /* Session */
    char   *session_name;
    double  session_timeout_ms;
    double  keepalive_interval_ms;
    double  secure_channel_lifetime_ms;
} OpcUaClientConfigInternal;

static OpcUaClientConfigInternal *opcua_client_config_internal(RtOpcUaClientConfig *c) {
    return (OpcUaClientConfigInternal *)(uintptr_t)c->internal_ptr;
}

static void opcua_free_ccfg_string(char **p) { if (*p) { free(*p); *p = NULL; } }
static void opcua_dup_ccfg_string(char **p, const char *s) {
    if (*p) free(*p);
    *p = strdup(s ? s : "");
}

RtOpcUaClientConfig *sn_opcua_client_config_defaults(void) {
    RtOpcUaClientConfig *c = __sn__OpcUaClientConfig__new();
    OpcUaClientConfigInternal *i = (OpcUaClientConfigInternal *)calloc(1, sizeof(*i));
    i->application_uri        = strdup("urn:sindarin:opcua-client");
    i->application_name       = strdup("Sindarin OPC UA Client");
    i->product_uri            = strdup("urn:sindarin:opcua-client");
    i->security_policy_code   = 0;
    i->message_security_mode  = 1;
    i->hostname_verification  = true;
    i->user_kind              = 0;
    i->username               = strdup("");
    i->password               = strdup("");
    i->user_cert_path         = strdup("");
    i->user_key_path          = strdup("");
    i->issued_token           = NULL;
    i->issued_token_len       = 0;
    i->token_type             = strdup("");
    i->client_cert_path       = strdup("");
    i->client_key_path        = strdup("");
    i->trust_list             = NULL;
    i->session_name           = strdup("Sindarin OPC UA Session");
    i->session_timeout_ms     = 60 * 60 * 1000.0;   /* 60 minutes */
    i->keepalive_interval_ms  = 5000.0;
    i->secure_channel_lifetime_ms = 10 * 60 * 1000.0; /* 10 minutes */
    c->internal_ptr = (long long)(uintptr_t)i;
    return c;
}

#define OPCUA_CFG_SET_STR(field) \
    if (!cfg) return cfg; \
    OpcUaClientConfigInternal *i = opcua_client_config_internal(cfg); \
    opcua_dup_ccfg_string(&i->field, v); \
    return cfg;

RtOpcUaClientConfig *sn_opcua_client_config_set_application_uri(RtOpcUaClientConfig *cfg, char *v) {
    OPCUA_CFG_SET_STR(application_uri)
}
RtOpcUaClientConfig *sn_opcua_client_config_set_application_name(RtOpcUaClientConfig *cfg, char *v) {
    OPCUA_CFG_SET_STR(application_name)
}
RtOpcUaClientConfig *sn_opcua_client_config_set_product_uri(RtOpcUaClientConfig *cfg, char *v) {
    OPCUA_CFG_SET_STR(product_uri)
}
RtOpcUaClientConfig *sn_opcua_client_config_set_session_name(RtOpcUaClientConfig *cfg, char *v) {
    OPCUA_CFG_SET_STR(session_name)
}

RtOpcUaClientConfig *sn_opcua_client_config_set_security_policy(RtOpcUaClientConfig *cfg, RtOpcUaSecurityPolicy *p) {
    if (!cfg || !p) return cfg;
    opcua_client_config_internal(cfg)->security_policy_code = (int)p->code;
    return cfg;
}

RtOpcUaClientConfig *sn_opcua_client_config_set_message_security_mode(RtOpcUaClientConfig *cfg, RtOpcUaMessageSecurityMode *m) {
    if (!cfg || !m) return cfg;
    opcua_client_config_internal(cfg)->message_security_mode = (int)m->code;
    return cfg;
}

RtOpcUaClientConfig *sn_opcua_client_config_set_user_identity(RtOpcUaClientConfig *cfg, RtOpcUaUserIdentity *u) {
    if (!cfg || !u) return cfg;
    OpcUaClientConfigInternal *i = opcua_client_config_internal(cfg);
    i->user_kind = (int)u->kind;
    opcua_dup_ccfg_string(&i->username,       u->username);
    opcua_dup_ccfg_string(&i->password,       u->password);
    opcua_dup_ccfg_string(&i->user_cert_path, u->cert_path);
    opcua_dup_ccfg_string(&i->user_key_path,  u->key_path);
    opcua_dup_ccfg_string(&i->token_type,     u->token_type);
    if (i->issued_token) { free(i->issued_token); i->issued_token = NULL; i->issued_token_len = 0; }
    if (u->issued_token && u->issued_token->len > 0) {
        i->issued_token_len = (size_t)u->issued_token->len;
        i->issued_token = (unsigned char *)malloc(i->issued_token_len);
        for (size_t k = 0; k < i->issued_token_len; k++) {
            unsigned char *p = (unsigned char *)sn_array_get(u->issued_token, (long long)k);
            i->issued_token[k] = p ? *p : 0;
        }
    }
    return cfg;
}

RtOpcUaClientConfig *sn_opcua_client_config_set_client_certificate(RtOpcUaClientConfig *cfg, char *certPath, char *keyPath) {
    if (!cfg) return cfg;
    OpcUaClientConfigInternal *i = opcua_client_config_internal(cfg);
    opcua_dup_ccfg_string(&i->client_cert_path, certPath);
    opcua_dup_ccfg_string(&i->client_key_path,  keyPath);
    return cfg;
}

RtOpcUaClientConfig *sn_opcua_client_config_set_trust_list(RtOpcUaClientConfig *cfg, RtOpcUaTrustList *tl) {
    if (!cfg) return cfg;
    OpcUaClientConfigInternal *i = opcua_client_config_internal(cfg);
    if (i->trust_list) { __sn__OpcUaTrustList_release(&i->trust_list); }
    i->trust_list = tl ? (RtOpcUaTrustList *)__sn__OpcUaTrustList_retain(tl) : NULL;
    return cfg;
}

RtOpcUaClientConfig *sn_opcua_client_config_set_hostname_verification(RtOpcUaClientConfig *cfg, bool enabled) {
    if (!cfg) return cfg;
    opcua_client_config_internal(cfg)->hostname_verification = enabled;
    return cfg;
}

RtOpcUaClientConfig *sn_opcua_client_config_set_session_timeout(RtOpcUaClientConfig *cfg, double ms) {
    if (!cfg) return cfg;
    opcua_client_config_internal(cfg)->session_timeout_ms = ms;
    return cfg;
}

RtOpcUaClientConfig *sn_opcua_client_config_set_keepalive_interval(RtOpcUaClientConfig *cfg, double ms) {
    if (!cfg) return cfg;
    opcua_client_config_internal(cfg)->keepalive_interval_ms = ms;
    return cfg;
}

RtOpcUaClientConfig *sn_opcua_client_config_set_secure_channel_lifetime(RtOpcUaClientConfig *cfg, double ms) {
    if (!cfg) return cfg;
    opcua_client_config_internal(cfg)->secure_channel_lifetime_ms = ms;
    return cfg;
}

void sn_opcua_client_config_dispose(RtOpcUaClientConfig *cfg) {
    if (!cfg) return;
    OpcUaClientConfigInternal *i = opcua_client_config_internal(cfg);
    if (!i) return;
    opcua_free_ccfg_string(&i->application_uri);
    opcua_free_ccfg_string(&i->application_name);
    opcua_free_ccfg_string(&i->product_uri);
    opcua_free_ccfg_string(&i->username);
    opcua_free_ccfg_string(&i->password);
    opcua_free_ccfg_string(&i->user_cert_path);
    opcua_free_ccfg_string(&i->user_key_path);
    opcua_free_ccfg_string(&i->token_type);
    opcua_free_ccfg_string(&i->client_cert_path);
    opcua_free_ccfg_string(&i->client_key_path);
    opcua_free_ccfg_string(&i->session_name);
    if (i->issued_token) free(i->issued_token);
    if (i->trust_list)   __sn__OpcUaTrustList_release(&i->trust_list);
    free(i);
    cfg->internal_ptr = 0;
}

/* ============================================================================
 * OpcUaClient
 * ============================================================================ */

typedef struct RtClientInternal {
    UA_Client         *ua;
    opcua_mutex_t      mutex;
    opcua_thread_t     pump_thread;
    bool               pump_running;
    bool               pump_stop;
    char              *endpoint_url;
    char              *active_policy_uri;
    int                active_security_mode;

    /* Track live subscription internals so the pump thread can iterate. */
    OpcUaSubscriptionInternal **subscriptions;
    size_t                     subscription_count;
    size_t                     subscription_cap;
} RtClientInternal;

static RtClientInternal *opcua_client_int(RtOpcUaClient *c) {
    return (RtClientInternal *)(uintptr_t)c->internal_ptr;
}

static UA_Client *opcua_client_ua(RtOpcUaClient *c) {
    if (!c || c->internal_ptr == 0) return NULL;
    return opcua_client_int(c)->ua;
}

static void opcua_client_lock(RtOpcUaClient *c) {
    if (!c || c->internal_ptr == 0) return;
    OPCUA_MUTEX_LOCK(&opcua_client_int(c)->mutex);
}

static void opcua_client_unlock(RtOpcUaClient *c) {
    if (!c || c->internal_ptr == 0) return;
    OPCUA_MUTEX_UNLOCK(&opcua_client_int(c)->mutex);
}

static void opcua_client_register_subscription(RtClientInternal *ci, OpcUaSubscriptionInternal *si) {
    if (ci->subscription_count >= ci->subscription_cap) {
        size_t n = ci->subscription_cap == 0 ? 8 : ci->subscription_cap * 2;
        ci->subscriptions = (OpcUaSubscriptionInternal **)realloc(ci->subscriptions,
                                                                  sizeof(void *) * n);
        ci->subscription_cap = n;
    }
    ci->subscriptions[ci->subscription_count++] = si;
}

/* Pump thread: calls UA_Client_run_iterate() every 50ms to drive
 * subscription publishing. */
#ifdef _WIN32
static unsigned __stdcall opcua_client_pump_thread(void *arg) {
    RtOpcUaClient *client = (RtOpcUaClient *)arg;
#else
static void *opcua_client_pump_thread(void *arg) {
    RtOpcUaClient *client = (RtOpcUaClient *)arg;
#endif
    RtClientInternal *ci = opcua_client_int(client);
    while (!ci->pump_stop) {
        OPCUA_MUTEX_LOCK(&ci->mutex);
        if (ci->ua) {
            UA_Client_run_iterate(ci->ua, 0);
        }
        OPCUA_MUTEX_UNLOCK(&ci->mutex);
        OPCUA_SLEEP_MS(50);
    }
#ifdef _WIN32
    return 0;
#else
    return NULL;
#endif
}

/* Apply all enabled security policies + auth plugin setup onto a client. */
static UA_StatusCode opcua_apply_security(UA_Client *ua, OpcUaClientConfigInternal *i) {
    UA_ClientConfig *cc = UA_Client_getConfig(ua);
    /* Defaults first — allocates internal logger, state callbacks, etc. */
    UA_ClientConfig_setDefault(cc);
    cc->logging = opcua_resolve_logger(cc->logging);
    cc->eventLoop->logger = cc->logging;

    /* Application description. */
    UA_String_clear(&cc->clientDescription.applicationUri);
    cc->clientDescription.applicationUri = UA_STRING_ALLOC(i->application_uri);
    UA_String_clear(&cc->clientDescription.productUri);
    cc->clientDescription.productUri     = UA_STRING_ALLOC(i->product_uri);
    UA_LocalizedText_clear(&cc->clientDescription.applicationName);
    cc->clientDescription.applicationName =
        UA_LOCALIZEDTEXT_ALLOC("en-US", i->application_name);

    /* Session parameters. */
    cc->requestedSessionTimeout = i->session_timeout_ms;
    cc->secureChannelLifeTime   = (UA_UInt32)i->secure_channel_lifetime_ms;

    /* Load client cert + key + trust list if any encryption is enabled. */
    bool need_crypto = (i->security_policy_code != 0) || (i->message_security_mode > 1);
    if (need_crypto) {
        unsigned char *cert_buf = NULL; size_t cert_len = 0;
        unsigned char *key_buf  = NULL; size_t key_len  = 0;
        if (i->client_cert_path && i->client_cert_path[0]) {
            opcua_load_cert_bytes_pem(i->client_cert_path, &cert_buf, &cert_len);
        }
        if (i->client_key_path && i->client_key_path[0]) {
            FILE *fp = fopen(i->client_key_path, "rb");
            if (fp) {
                fseek(fp, 0, SEEK_END);
                long kl = ftell(fp);
                fseek(fp, 0, SEEK_SET);
                if (kl > 0) {
                    key_buf = (unsigned char *)malloc((size_t)kl);
                    if (fread(key_buf, 1, (size_t)kl, fp) != (size_t)kl) {
                        free(key_buf); key_buf = NULL;
                    } else {
                        key_len = (size_t)kl;
                    }
                }
                fclose(fp);
            }
        }

        UA_ByteString certificate = UA_BYTESTRING_NULL;
        UA_ByteString privateKey  = UA_BYTESTRING_NULL;
        if (cert_buf) { certificate.data = cert_buf; certificate.length = cert_len; }
        if (key_buf)  { privateKey.data  = key_buf;  privateKey.length  = key_len;  }

        size_t n_trusted = 0, n_issuers = 0, n_crls = 0;
        UA_ByteString *trusted  = NULL;
        UA_ByteString *issuers  = NULL;
        UA_ByteString *crls     = NULL;
        if (i->trust_list) {
            OpcUaTrustListInternal *ti = opcua_trust_list_internal(i->trust_list);
            if (ti && !ti->no_verification) {
                n_trusted = ti->trusted_count;
                n_issuers = ti->issuers_count;
                n_crls    = ti->crls_count;
                if (n_trusted > 0) {
                    trusted = (UA_ByteString *)calloc(n_trusted, sizeof(UA_ByteString));
                    for (size_t k = 0; k < n_trusted; k++) {
                        trusted[k].data = ti->trusted[k]; trusted[k].length = ti->trusted_len[k];
                    }
                }
                if (n_issuers > 0) {
                    issuers = (UA_ByteString *)calloc(n_issuers, sizeof(UA_ByteString));
                    for (size_t k = 0; k < n_issuers; k++) {
                        issuers[k].data = ti->issuers[k]; issuers[k].length = ti->issuers_len[k];
                    }
                }
                if (n_crls > 0) {
                    crls = (UA_ByteString *)calloc(n_crls, sizeof(UA_ByteString));
                    for (size_t k = 0; k < n_crls; k++) {
                        crls[k].data = ti->crls[k]; crls[k].length = ti->crls_len[k];
                    }
                }
            } else if (ti && ti->no_verification) {
                fprintf(stderr, "OPC UA: WARNING — trust list set to no-verification; "
                                "server certificate NOT validated. Use only in tests.\n");
            }
        }

        UA_StatusCode sec_rc =
            UA_ClientConfig_setDefaultEncryption(cc, certificate, privateKey,
                                                 trusted, n_trusted,
                                                 crls, n_crls);
        /* Issuer-list wiring would go here once open62541's client config
         * exposes it across crypto backends — for now issuers are ignored. */
        (void)issuers; (void)n_issuers;

        /* UA_ClientConfig_setDefaultEncryption copies the bytestrings. We
         * can free our temporaries now. */
        if (cert_buf) free(cert_buf);
        if (key_buf)  free(key_buf);

        /* trusted/issuers/crls spines are plain calloc'd refs into our
         * internal buffers; open62541 made its own deep copies. */
        if (trusted) free(trusted);
        if (issuers) free(issuers);
        if (crls)    free(crls);

        if (sec_rc != UA_STATUSCODE_GOOD) return sec_rc;
    }

    /* Select policy + message mode. */
    UA_String_clear(&cc->securityPolicyUri);
    cc->securityPolicyUri = UA_STRING_ALLOC(
        opcua_security_policy_uri_for_code(i->security_policy_code));
    cc->securityMode = (UA_MessageSecurityMode)i->message_security_mode;

    return UA_STATUSCODE_GOOD;
}

/* Apply user identity onto the config (UA_ExtensionObject userIdentityToken). */
static void opcua_apply_user_identity(UA_Client *ua, OpcUaClientConfigInternal *i) {
    UA_ClientConfig *cc = UA_Client_getConfig(ua);
    UA_ExtensionObject_clear(&cc->userIdentityToken);

    if (i->user_kind == 1) {
        UA_UserNameIdentityToken *tok = UA_UserNameIdentityToken_new();
        tok->userName = UA_STRING_ALLOC(i->username);
        tok->password = UA_STRING_ALLOC(i->password);
        cc->userIdentityToken.encoding = UA_EXTENSIONOBJECT_DECODED;
        cc->userIdentityToken.content.decoded.type = &UA_TYPES[UA_TYPES_USERNAMEIDENTITYTOKEN];
        cc->userIdentityToken.content.decoded.data = tok;
    } else if (i->user_kind == 2) {
        UA_X509IdentityToken *tok = UA_X509IdentityToken_new();
        unsigned char *cert_buf = NULL; size_t cert_len = 0;
        if (i->user_cert_path && i->user_cert_path[0])
            opcua_load_cert_bytes_pem(i->user_cert_path, &cert_buf, &cert_len);
        if (cert_buf) {
            tok->certificateData.data = (UA_Byte *)UA_malloc(cert_len);
            memcpy(tok->certificateData.data, cert_buf, cert_len);
            tok->certificateData.length = cert_len;
            free(cert_buf);
        }
        cc->userIdentityToken.encoding = UA_EXTENSIONOBJECT_DECODED;
        cc->userIdentityToken.content.decoded.type = &UA_TYPES[UA_TYPES_X509IDENTITYTOKEN];
        cc->userIdentityToken.content.decoded.data = tok;
    } else if (i->user_kind == 3) {
        UA_IssuedIdentityToken *tok = UA_IssuedIdentityToken_new();
        if (i->issued_token && i->issued_token_len > 0) {
            tok->tokenData.data = (UA_Byte *)UA_malloc(i->issued_token_len);
            memcpy(tok->tokenData.data, i->issued_token, i->issued_token_len);
            tok->tokenData.length = i->issued_token_len;
        }
        if (i->token_type) tok->encryptionAlgorithm = UA_STRING_ALLOC(i->token_type);
        cc->userIdentityToken.encoding = UA_EXTENSIONOBJECT_DECODED;
        cc->userIdentityToken.content.decoded.type = &UA_TYPES[UA_TYPES_ISSUEDIDENTITYTOKEN];
        cc->userIdentityToken.content.decoded.data = tok;
    }
    /* kind 0 → anonymous: leave empty token. */
}

static RtOpcUaClient *opcua_client_new_internal(const char *url, OpcUaClientConfigInternal *ci_cfg) {
    UA_Client *ua = UA_Client_new();
    if (!ua) return NULL;

    /* Apply config. */
    OpcUaClientConfigInternal defaults_internal = {0};
    OpcUaClientConfigInternal *i = ci_cfg;
    if (!i) {
        i = &defaults_internal;
        i->application_uri       = (char *)"urn:sindarin:opcua-client";
        i->application_name      = (char *)"Sindarin OPC UA Client";
        i->product_uri           = (char *)"urn:sindarin:opcua-client";
        i->session_name          = (char *)"Sindarin OPC UA Session";
        i->session_timeout_ms    = 60 * 60 * 1000.0;
        i->secure_channel_lifetime_ms = 10 * 60 * 1000.0;
        i->keepalive_interval_ms = 5000.0;
        i->hostname_verification = true;
    }

    UA_StatusCode rc = opcua_apply_security(ua, i);
    if (rc != UA_STATUSCODE_GOOD) {
        fprintf(stderr, "OPC UA: security setup failed: %s\n", UA_StatusCode_name(rc));
        UA_Client_delete(ua);
        return NULL;
    }
    opcua_apply_user_identity(ua, i);

    rc = UA_Client_connect(ua, url);
    if (rc != UA_STATUSCODE_GOOD) {
        fprintf(stderr, "OPC UA: connect to %s failed: %s\n",
                url, UA_StatusCode_name(rc));
        UA_Client_delete(ua);
        return NULL;
    }

    RtOpcUaClient *client = __sn__OpcUaClient__new();
    RtClientInternal *ci = (RtClientInternal *)calloc(1, sizeof(*ci));
    ci->ua = ua;
    OPCUA_MUTEX_INIT(&ci->mutex);
    ci->pump_running = false;
    ci->pump_stop = false;
    ci->endpoint_url = strdup(url);
    ci->active_policy_uri = strdup(opcua_security_policy_uri_for_code(i->security_policy_code));
    ci->active_security_mode = i->message_security_mode;
    client->internal_ptr = (long long)(uintptr_t)ci;
    client->endpoint_url = strdup(url);

    /* Start the pump thread. */
#ifdef _WIN32
    ci->pump_thread = (HANDLE)_beginthreadex(NULL, 0, opcua_client_pump_thread, client, 0, NULL);
    ci->pump_running = ci->pump_thread != NULL;
#else
    ci->pump_running = (pthread_create(&ci->pump_thread, NULL,
                                       opcua_client_pump_thread, client) == 0);
#endif
    return client;
}

RtOpcUaClient *sn_opcua_client_connect(char *url) {
    if (!url) return NULL;
    return opcua_client_new_internal(url, NULL);
}

RtOpcUaClient *sn_opcua_client_connect_with(char *url, RtOpcUaClientConfig *config) {
    if (!url || !config) return NULL;
    return opcua_client_new_internal(url, opcua_client_config_internal(config));
}

/*
 * Null-safe connect: identical to sn_opcua_client_connect but intended for
 * reconnection paths where the caller checks the result with
 * sn_opcua_client_is_null() before dereferencing. Returns NULL if the server
 * is unreachable — no crash, no abort.
 */
RtOpcUaClient *sn_opcua_client_try_connect(char *url) {
    if (!url) return NULL;
    return opcua_client_new_internal(url, NULL);
}

/*
 * Returns 1 if the client pointer is NULL, 0 if valid. Safe to call with a
 * NULL pointer — no dereference occurs. Used by reconnection logic to check
 * whether sn_opcua_client_try_connect succeeded before touching the client.
 */
int sn_opcua_client_is_null(void *client) {
    return client == NULL ? 1 : 0;
}

/* Discovery: no session created. */
SnArray *sn_opcua_client_get_endpoints(char *discoveryUrl) {
    SnArray *arr = sn_array_new(sizeof(RtOpcUaEndpointDescription *), 4);
    arr->elem_tag     = SN_TAG_STRUCT;
    if (!discoveryUrl) return arr;

    UA_Client *ua = UA_Client_new();
    if (!ua) return arr;
    UA_ClientConfig *cc = UA_Client_getConfig(ua);
    UA_ClientConfig_setDefault(cc);
    cc->logging = opcua_resolve_logger(cc->logging);
    cc->eventLoop->logger = cc->logging;

    UA_EndpointDescription *endpoints = NULL;
    size_t n = 0;
    UA_StatusCode rc = UA_Client_getEndpoints(ua, discoveryUrl, &n, &endpoints);
    if (rc == UA_STATUSCODE_GOOD) {
        for (size_t k = 0; k < n; k++) {
            RtOpcUaEndpointDescription *e = opcua_from_ua_endpoint(&endpoints[k]);
            RtOpcUaEndpointDescription *retained =
                (RtOpcUaEndpointDescription *)__sn__OpcUaEndpointDescription_retain(e);
            sn_array_push(arr, &retained);
        }
        UA_Array_delete(endpoints, n, &UA_TYPES[UA_TYPES_ENDPOINTDESCRIPTION]);
    } else {
        fprintf(stderr, "OPC UA: getEndpoints failed: %s\n", UA_StatusCode_name(rc));
    }
    UA_Client_delete(ua);
    return arr;
}

SnArray *sn_opcua_client_find_servers(char *discoveryUrl) {
    SnArray *arr = sn_array_new(sizeof(RtOpcUaApplicationDescription *), 4);
    arr->elem_tag     = SN_TAG_STRUCT;
    if (!discoveryUrl) return arr;

    UA_Client *ua = UA_Client_new();
    if (!ua) return arr;
    UA_ClientConfig *cc = UA_Client_getConfig(ua);
    UA_ClientConfig_setDefault(cc);
    cc->logging = opcua_resolve_logger(cc->logging);
    cc->eventLoop->logger = cc->logging;

    UA_ApplicationDescription *apps = NULL;
    size_t n = 0;
    UA_StatusCode rc = UA_Client_findServers(ua, discoveryUrl, 0, NULL, 0, NULL, &n, &apps);
    if (rc == UA_STATUSCODE_GOOD) {
        for (size_t k = 0; k < n; k++) {
            RtOpcUaApplicationDescription *d = opcua_from_ua_app_desc(&apps[k]);
            RtOpcUaApplicationDescription *r =
                (RtOpcUaApplicationDescription *)__sn__OpcUaApplicationDescription_retain(d);
            sn_array_push(arr, &r);
        }
        UA_Array_delete(apps, n, &UA_TYPES[UA_TYPES_APPLICATIONDESCRIPTION]);
    } else {
        fprintf(stderr, "OPC UA: findServers failed: %s\n", UA_StatusCode_name(rc));
    }
    UA_Client_delete(ua);
    return arr;
}

/* ============================================================================
 * Attribute services
 * ============================================================================ */

RtOpcUaVariant *sn_opcua_client_read_value(RtOpcUaClient *client, RtOpcUaNodeId *nodeId) {
    if (!client || !nodeId) return sn_opcua_variant_null();

    UA_NodeId id = opcua_to_ua_node_id(nodeId);
    UA_Variant *out = (UA_Variant *)UA_Variant_new();

    opcua_client_lock(client);
    UA_StatusCode rc = UA_Client_readValueAttribute(opcua_client_ua(client), id, out);
    opcua_client_unlock(client);

    UA_NodeId_clear(&id);
    if (rc != UA_STATUSCODE_GOOD) {
        fprintf(stderr, "OPC UA: readValue failed: %s\n", UA_StatusCode_name(rc));
        UA_Variant_clear(out);
        UA_free(out);
        return sn_opcua_variant_null();
    }
    return opcua_wrap_variant_take(out);
}

void sn_opcua_client_write_value(RtOpcUaClient *client, RtOpcUaNodeId *nodeId, RtOpcUaVariant *value) {
    if (!client || !nodeId || !value) return;
    UA_NodeId id = opcua_to_ua_node_id(nodeId);
    UA_Variant *v = opcua_variant_ptr(value);

    opcua_client_lock(client);
    UA_StatusCode rc = UA_Client_writeValueAttribute(opcua_client_ua(client), id, v);
    opcua_client_unlock(client);

    UA_NodeId_clear(&id);
    if (rc != UA_STATUSCODE_GOOD) {
        fprintf(stderr, "OPC UA: writeValue failed: %s\n", UA_StatusCode_name(rc));
    }
}

RtOpcUaVariant *sn_opcua_client_read_attribute(RtOpcUaClient *client, RtOpcUaNodeId *nodeId, long long attributeId) {
    if (!client || !nodeId) return sn_opcua_variant_null();
    UA_NodeId id = opcua_to_ua_node_id(nodeId);
    UA_ReadValueId rv;
    UA_ReadValueId_init(&rv);
    rv.nodeId = id;
    rv.attributeId = (UA_UInt32)attributeId;

    UA_ReadRequest req;
    UA_ReadRequest_init(&req);
    req.nodesToRead = &rv;
    req.nodesToReadSize = 1;

    opcua_client_lock(client);
    UA_ReadResponse resp = UA_Client_Service_read(opcua_client_ua(client), req);
    opcua_client_unlock(client);

    RtOpcUaVariant *out = sn_opcua_variant_null();
    if (resp.resultsSize == 1 && resp.results[0].hasValue) {
        UA_Variant *v = (UA_Variant *)UA_Variant_new();
        UA_Variant_copy(&resp.results[0].value, v);
        if (out) { UA_Variant *old = opcua_variant_ptr(out); if (old) { UA_Variant_clear(old); UA_free(old); } }
        out->internal_ptr = (long long)(uintptr_t)v;
        out->type_code    = opcua_variant_type_code_for(v);
        out->is_array     = UA_Variant_isScalar(v) ? 0 : 1;
    }
    UA_ReadResponse_clear(&resp);
    UA_NodeId_clear(&id);
    return out;
}

/* ============================================================================
 * Browse services
 * ============================================================================ */

static SnArray *opcua_new_ref_desc_array(void) {
    SnArray *arr = sn_array_new(sizeof(RtOpcUaReferenceDescription *), 4);
    arr->elem_tag     = SN_TAG_STRUCT;
    return arr;
}

SnArray *sn_opcua_client_browse(RtOpcUaClient *client, RtOpcUaNodeId *nodeId) {
    SnArray *arr = opcua_new_ref_desc_array();
    if (!client || !nodeId) return arr;

    UA_BrowseRequest req;
    UA_BrowseRequest_init(&req);
    req.requestedMaxReferencesPerNode = 0;
    req.nodesToBrowseSize = 1;
    req.nodesToBrowse     = UA_BrowseDescription_new();
    req.nodesToBrowse[0].nodeId = opcua_to_ua_node_id(nodeId);
    req.nodesToBrowse[0].resultMask = UA_BROWSERESULTMASK_ALL;
    req.nodesToBrowse[0].browseDirection = UA_BROWSEDIRECTION_FORWARD;
    req.nodesToBrowse[0].includeSubtypes = UA_TRUE;

    opcua_client_lock(client);
    UA_BrowseResponse resp = UA_Client_Service_browse(opcua_client_ua(client), req);
    opcua_client_unlock(client);

    if (resp.resultsSize == 1 && resp.results[0].statusCode == UA_STATUSCODE_GOOD) {
        for (size_t k = 0; k < resp.results[0].referencesSize; k++) {
            RtOpcUaReferenceDescription *rd =
                opcua_from_ua_ref_desc(&resp.results[0].references[k]);
            RtOpcUaReferenceDescription *ret =
                (RtOpcUaReferenceDescription *)__sn__OpcUaReferenceDescription_retain(rd);
            sn_array_push(arr, &ret);
        }
    }
    UA_BrowseResponse_clear(&resp);
    UA_BrowseRequest_clear(&req);
    return arr;
}

SnArray *sn_opcua_client_browse_filtered(RtOpcUaClient *client, RtOpcUaNodeId *nodeId,
                                          RtOpcUaNodeId *refType, bool includeSubtypes) {
    SnArray *arr = opcua_new_ref_desc_array();
    if (!client || !nodeId) return arr;

    UA_BrowseRequest req;
    UA_BrowseRequest_init(&req);
    req.requestedMaxReferencesPerNode = 0;
    req.nodesToBrowseSize = 1;
    req.nodesToBrowse     = UA_BrowseDescription_new();
    req.nodesToBrowse[0].nodeId = opcua_to_ua_node_id(nodeId);
    req.nodesToBrowse[0].resultMask = UA_BROWSERESULTMASK_ALL;
    req.nodesToBrowse[0].browseDirection = UA_BROWSEDIRECTION_FORWARD;
    req.nodesToBrowse[0].includeSubtypes = includeSubtypes ? UA_TRUE : UA_FALSE;
    if (refType) {
        req.nodesToBrowse[0].referenceTypeId = opcua_to_ua_node_id(refType);
    }

    opcua_client_lock(client);
    UA_BrowseResponse resp = UA_Client_Service_browse(opcua_client_ua(client), req);
    opcua_client_unlock(client);

    if (resp.resultsSize == 1 && resp.results[0].statusCode == UA_STATUSCODE_GOOD) {
        for (size_t k = 0; k < resp.results[0].referencesSize; k++) {
            RtOpcUaReferenceDescription *rd =
                opcua_from_ua_ref_desc(&resp.results[0].references[k]);
            RtOpcUaReferenceDescription *ret =
                (RtOpcUaReferenceDescription *)__sn__OpcUaReferenceDescription_retain(rd);
            sn_array_push(arr, &ret);
        }
    }
    UA_BrowseResponse_clear(&resp);
    UA_BrowseRequest_clear(&req);
    return arr;
}

/* ============================================================================
 * Method services
 * ============================================================================ */

SnArray *sn_opcua_client_call_method(RtOpcUaClient *client,
                                     RtOpcUaNodeId *objectId, RtOpcUaNodeId *methodId,
                                     SnArray *inputs) {
    SnArray *out = sn_array_new(sizeof(RtOpcUaVariant *), 2);
    out->elem_tag     = SN_TAG_STRUCT;
    if (!client || !objectId || !methodId) return out;

    size_t n_in = inputs ? (size_t)inputs->len : 0;
    UA_Variant *in = n_in ? (UA_Variant *)UA_Array_new(n_in, &UA_TYPES[UA_TYPES_VARIANT]) : NULL;
    for (size_t k = 0; k < n_in; k++) {
        RtOpcUaVariant **p = (RtOpcUaVariant **)sn_array_get(inputs, (long long)k);
        UA_Variant *src = p && *p ? opcua_variant_ptr(*p) : NULL;
        if (src) UA_Variant_copy(src, &in[k]);
        else     UA_Variant_init(&in[k]);
    }

    UA_NodeId obj_id = opcua_to_ua_node_id(objectId);
    UA_NodeId m_id   = opcua_to_ua_node_id(methodId);

    size_t n_out = 0;
    UA_Variant *results = NULL;

    opcua_client_lock(client);
    UA_StatusCode rc = UA_Client_call(opcua_client_ua(client), obj_id, m_id,
                                      n_in, in, &n_out, &results);
    opcua_client_unlock(client);

    UA_NodeId_clear(&obj_id);
    UA_NodeId_clear(&m_id);
    if (in) UA_Array_delete(in, n_in, &UA_TYPES[UA_TYPES_VARIANT]);

    if (rc != UA_STATUSCODE_GOOD) {
        fprintf(stderr, "OPC UA: call failed: %s\n", UA_StatusCode_name(rc));
        return out;
    }
    for (size_t k = 0; k < n_out; k++) {
        UA_Variant *v = (UA_Variant *)UA_Variant_new();
        UA_Variant_copy(&results[k], v);
        RtOpcUaVariant *wrap = opcua_wrap_variant_take(v);
        RtOpcUaVariant *ret  = (RtOpcUaVariant *)__sn__OpcUaVariant_retain(wrap);
        sn_array_push(out, &ret);
    }
    if (results) UA_Array_delete(results, n_out, &UA_TYPES[UA_TYPES_VARIANT]);
    return out;
}

/* ============================================================================
 * Subscription services
 * ============================================================================ */

RtOpcUaSubscription *sn_opcua_client_create_subscription(RtOpcUaClient *client, double publishIntervalMs) {
    if (!client) return NULL;

    UA_CreateSubscriptionRequest req = UA_CreateSubscriptionRequest_default();
    if (publishIntervalMs > 0) req.requestedPublishingInterval = publishIntervalMs;

    opcua_client_lock(client);
    UA_CreateSubscriptionResponse resp = UA_Client_Subscriptions_create(
        opcua_client_ua(client), req, NULL, NULL, NULL);
    opcua_client_unlock(client);

    if (resp.responseHeader.serviceResult != UA_STATUSCODE_GOOD) {
        fprintf(stderr, "OPC UA: createSubscription failed: %s\n",
                UA_StatusCode_name(resp.responseHeader.serviceResult));
        return NULL;
    }

    RtOpcUaSubscription *sub = __sn__OpcUaSubscription__new();
    OpcUaSubscriptionInternal *si = (OpcUaSubscriptionInternal *)calloc(1, sizeof(*si));
    OPCUA_MUTEX_INIT(&si->mutex);
    OPCUA_COND_INIT(&si->cond);
    si->subscription_id = resp.subscriptionId;
    si->client          = client;

    sub->subscription_id = (long long)resp.subscriptionId;
    sub->client_ptr      = (long long)(uintptr_t)client;
    sub->internal_ptr    = (long long)(uintptr_t)si;

    opcua_client_register_subscription(opcua_client_int(client), si);
    return sub;
}

/* ============================================================================
 * Client introspection + lifecycle
 * ============================================================================ */

bool sn_opcua_client_is_connected(RtOpcUaClient *client) {
    if (!client) return false;
    UA_Client *ua = opcua_client_ua(client);
    if (!ua) return false;
    UA_SecureChannelState ch = UA_SECURECHANNELSTATE_CLOSED;
    UA_SessionState       se = UA_SESSIONSTATE_CLOSED;
    UA_StatusCode         cc = UA_STATUSCODE_GOOD;
    UA_Client_getState(ua, &ch, &se, &cc);
    return se == UA_SESSIONSTATE_ACTIVATED;
}

char *sn_opcua_client_endpoint_url(RtOpcUaClient *client) {
    if (!client) return strdup("");
    RtClientInternal *ci = opcua_client_int(client);
    return strdup(ci && ci->endpoint_url ? ci->endpoint_url : "");
}

char *sn_opcua_client_active_security_policy_uri(RtOpcUaClient *client) {
    if (!client) return strdup("");
    RtClientInternal *ci = opcua_client_int(client);
    return strdup(ci && ci->active_policy_uri ? ci->active_policy_uri : "");
}

long long sn_opcua_client_active_security_mode(RtOpcUaClient *client) {
    if (!client) return 1;
    RtClientInternal *ci = opcua_client_int(client);
    return (long long)(ci ? ci->active_security_mode : 1);
}

void sn_opcua_client_disconnect(RtOpcUaClient *client) {
    if (!client) return;
    RtClientInternal *ci = opcua_client_int(client);
    if (!ci) return;

    /* Stop pump first so iterate stops racing. */
    ci->pump_stop = true;
#ifdef _WIN32
    if (ci->pump_running) {
        WaitForSingleObject(ci->pump_thread, INFINITE);
        CloseHandle(ci->pump_thread);
        ci->pump_running = false;
    }
#else
    if (ci->pump_running) {
        pthread_join(ci->pump_thread, NULL);
        ci->pump_running = false;
    }
#endif

    OPCUA_MUTEX_LOCK(&ci->mutex);
    if (ci->ua) {
        UA_Client_disconnect(ci->ua);
    }
    OPCUA_MUTEX_UNLOCK(&ci->mutex);
}

void sn_opcua_client_dispose(RtOpcUaClient *client) {
    if (!client) return;
    RtClientInternal *ci = opcua_client_int(client);
    if (!ci) return;

    /* Ensure pump is stopped. */
    if (ci->pump_running) {
        ci->pump_stop = true;
#ifdef _WIN32
        WaitForSingleObject(ci->pump_thread, INFINITE);
        CloseHandle(ci->pump_thread);
#else
        pthread_join(ci->pump_thread, NULL);
#endif
        ci->pump_running = false;
    }
    if (ci->ua) { UA_Client_delete(ci->ua); ci->ua = NULL; }
    if (ci->endpoint_url)      free(ci->endpoint_url);
    if (ci->active_policy_uri) free(ci->active_policy_uri);
    if (ci->subscriptions)     free(ci->subscriptions);
    OPCUA_MUTEX_DESTROY(&ci->mutex);
    free(ci);
    client->internal_ptr = 0;
}
