/* ==============================================================================
 * test_server.sn.c - In-process open62541 OPC UA test server
 * ============================================================================== */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>

#include <open62541/server.h>
#include <open62541/server_config_default.h>
#include <open62541/plugin/log_stdout.h>
#include <open62541/types.h>

#ifdef _WIN32
    #include <windows.h>
    #include <process.h>
    typedef HANDLE srv_thread_t;
#else
    #include <pthread.h>
    #include <unistd.h>
    typedef pthread_t srv_thread_t;
#endif

typedef __sn__OpcUaTestServer RtOpcUaTestServer;

typedef struct {
    UA_Server    *server;
    srv_thread_t  thread;
    volatile UA_Boolean running;
    int           port;
    /* Pre-added Demo.Counter node id cached for fast external set. */
    UA_NodeId     counter_node;
} OpcUaTestServerInternal;

static OpcUaTestServerInternal *tsi(RtOpcUaTestServer *s) {
    return (OpcUaTestServerInternal *)(uintptr_t)s->internal_ptr;
}

/* ------------------------------------------------------------------
 * Demo.AddNumbers method callback
 * ------------------------------------------------------------------ */
static UA_StatusCode
opcua_demo_add_numbers(UA_Server *server, const UA_NodeId *sessionId, void *sessionHandle,
                      const UA_NodeId *methodId, void *methodContext,
                      const UA_NodeId *objectId, void *objectContext,
                      size_t inputSize, const UA_Variant *input,
                      size_t outputSize, UA_Variant *output) {
    (void)server; (void)sessionId; (void)sessionHandle;
    (void)methodId; (void)methodContext; (void)objectId; (void)objectContext;
    if (inputSize != 2) return UA_STATUSCODE_BADARGUMENTSMISSING;
    UA_Double a = *(UA_Double *)input[0].data;
    UA_Double b = *(UA_Double *)input[1].data;
    UA_Double sum = a + b;
    UA_Variant_setScalarCopy(output, &sum, &UA_TYPES[UA_TYPES_DOUBLE]);
    (void)outputSize;
    return UA_STATUSCODE_GOOD;
}

/* ------------------------------------------------------------------
 * Build the Demo folder and all test nodes.
 * ------------------------------------------------------------------ */
static void opcua_test_server_add_demo_nodes(UA_Server *server, OpcUaTestServerInternal *i) {
    /* Demo folder under Objects. */
    UA_NodeId folder_id;
    {
        UA_ObjectAttributes oattr = UA_ObjectAttributes_default;
        oattr.displayName = UA_LOCALIZEDTEXT("en-US", "Demo");
        UA_Server_addObjectNode(server, UA_NODEID_STRING(2, "Demo"),
            UA_NODEID_NUMERIC(0, UA_NS0ID_OBJECTSFOLDER),
            UA_NODEID_NUMERIC(0, UA_NS0ID_ORGANIZES),
            UA_QUALIFIEDNAME(2, "Demo"),
            UA_NODEID_NUMERIC(0, UA_NS0ID_BASEOBJECTTYPE),
            oattr, NULL, &folder_id);
    }

    /* Demo.Int32 */
    {
        UA_VariableAttributes vattr = UA_VariableAttributes_default;
        UA_Int32 v = 42;
        UA_Variant_setScalar(&vattr.value, &v, &UA_TYPES[UA_TYPES_INT32]);
        vattr.displayName = UA_LOCALIZEDTEXT("en-US", "Int32");
        vattr.accessLevel = UA_ACCESSLEVELMASK_READ | UA_ACCESSLEVELMASK_WRITE;
        vattr.dataType = UA_TYPES[UA_TYPES_INT32].typeId;
        UA_Server_addVariableNode(server, UA_NODEID_STRING(2, "Demo.Int32"),
            folder_id, UA_NODEID_NUMERIC(0, UA_NS0ID_HASCOMPONENT),
            UA_QUALIFIEDNAME(2, "Int32"),
            UA_NODEID_NUMERIC(0, UA_NS0ID_BASEDATAVARIABLETYPE),
            vattr, NULL, NULL);
    }

    /* Demo.Double */
    {
        UA_VariableAttributes vattr = UA_VariableAttributes_default;
        UA_Double v = 3.14;
        UA_Variant_setScalar(&vattr.value, &v, &UA_TYPES[UA_TYPES_DOUBLE]);
        vattr.displayName = UA_LOCALIZEDTEXT("en-US", "Double");
        vattr.accessLevel = UA_ACCESSLEVELMASK_READ | UA_ACCESSLEVELMASK_WRITE;
        vattr.dataType = UA_TYPES[UA_TYPES_DOUBLE].typeId;
        UA_Server_addVariableNode(server, UA_NODEID_STRING(2, "Demo.Double"),
            folder_id, UA_NODEID_NUMERIC(0, UA_NS0ID_HASCOMPONENT),
            UA_QUALIFIEDNAME(2, "Double"),
            UA_NODEID_NUMERIC(0, UA_NS0ID_BASEDATAVARIABLETYPE),
            vattr, NULL, NULL);
    }

    /* Demo.String */
    {
        UA_VariableAttributes vattr = UA_VariableAttributes_default;
        UA_String v = UA_STRING("hello");
        UA_Variant_setScalar(&vattr.value, &v, &UA_TYPES[UA_TYPES_STRING]);
        vattr.displayName = UA_LOCALIZEDTEXT("en-US", "String");
        vattr.accessLevel = UA_ACCESSLEVELMASK_READ | UA_ACCESSLEVELMASK_WRITE;
        vattr.dataType = UA_TYPES[UA_TYPES_STRING].typeId;
        UA_Server_addVariableNode(server, UA_NODEID_STRING(2, "Demo.String"),
            folder_id, UA_NODEID_NUMERIC(0, UA_NS0ID_HASCOMPONENT),
            UA_QUALIFIEDNAME(2, "String"),
            UA_NODEID_NUMERIC(0, UA_NS0ID_BASEDATAVARIABLETYPE),
            vattr, NULL, NULL);
    }

    /* Demo.Counter */
    {
        UA_VariableAttributes vattr = UA_VariableAttributes_default;
        UA_Int32 v = 0;
        UA_Variant_setScalar(&vattr.value, &v, &UA_TYPES[UA_TYPES_INT32]);
        vattr.displayName = UA_LOCALIZEDTEXT("en-US", "Counter");
        vattr.accessLevel = UA_ACCESSLEVELMASK_READ | UA_ACCESSLEVELMASK_WRITE;
        vattr.dataType = UA_TYPES[UA_TYPES_INT32].typeId;
        UA_NodeId out;
        UA_Server_addVariableNode(server, UA_NODEID_STRING(2, "Demo.Counter"),
            folder_id, UA_NODEID_NUMERIC(0, UA_NS0ID_HASCOMPONENT),
            UA_QUALIFIEDNAME(2, "Counter"),
            UA_NODEID_NUMERIC(0, UA_NS0ID_BASEDATAVARIABLETYPE),
            vattr, NULL, &out);
        UA_NodeId_copy(&out, &i->counter_node);
    }

    /* Demo.AddNumbers(a, b): double */
    {
        UA_Argument input_args[2];
        for (int k = 0; k < 2; k++) {
            UA_Argument_init(&input_args[k]);
            input_args[k].description = UA_LOCALIZEDTEXT("en-US", k == 0 ? "a" : "b");
            input_args[k].name        = UA_STRING(k == 0 ? (char *)"a" : (char *)"b");
            input_args[k].dataType    = UA_TYPES[UA_TYPES_DOUBLE].typeId;
            input_args[k].valueRank   = UA_VALUERANK_SCALAR;
        }
        UA_Argument output_arg;
        UA_Argument_init(&output_arg);
        output_arg.description = UA_LOCALIZEDTEXT("en-US", "sum");
        output_arg.name        = UA_STRING((char *)"sum");
        output_arg.dataType    = UA_TYPES[UA_TYPES_DOUBLE].typeId;
        output_arg.valueRank   = UA_VALUERANK_SCALAR;

        UA_MethodAttributes mattr = UA_MethodAttributes_default;
        mattr.description = UA_LOCALIZEDTEXT("en-US", "Add two doubles");
        mattr.displayName = UA_LOCALIZEDTEXT("en-US", "AddNumbers");
        mattr.executable  = true;
        mattr.userExecutable = true;

        UA_Server_addMethodNode(server,
            UA_NODEID_STRING(2, "Demo.AddNumbers"), folder_id,
            UA_NODEID_NUMERIC(0, UA_NS0ID_HASCOMPONENT),
            UA_QUALIFIEDNAME(2, "AddNumbers"), mattr,
            &opcua_demo_add_numbers,
            2, input_args, 1, &output_arg, NULL, NULL);
    }
}

/* ------------------------------------------------------------------
 * Server iterate thread
 * ------------------------------------------------------------------ */
#ifdef _WIN32
static unsigned __stdcall opcua_test_server_thread(void *arg) {
#else
static void *opcua_test_server_thread(void *arg) {
#endif
    OpcUaTestServerInternal *i = (OpcUaTestServerInternal *)arg;
    UA_StatusCode rc = UA_Server_run_startup(i->server);
    if (rc != UA_STATUSCODE_GOOD) {
        fprintf(stderr, "TestServer startup failed: %s\n", UA_StatusCode_name(rc));
        i->running = false;
    }
    while (i->running) {
        UA_Server_run_iterate(i->server, true);
    }
    UA_Server_run_shutdown(i->server);
#ifdef _WIN32
    return 0;
#else
    return NULL;
#endif
}

/* Helper: load a file into a UA_ByteString (caller must UA_ByteString_clear). */
static UA_ByteString opcua_load_bytestring(const char *path) {
    UA_ByteString bs = UA_BYTESTRING_NULL;
    FILE *fp = fopen(path, "rb");
    if (!fp) return bs;
    fseek(fp, 0, SEEK_END);
    long n = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    if (n > 0) {
        bs.data = (UA_Byte *)UA_malloc((size_t)n);
        if (bs.data && fread(bs.data, 1, (size_t)n, fp) == (size_t)n) {
            bs.length = (size_t)n;
        } else if (bs.data) {
            UA_free(bs.data); bs.data = NULL;
        }
    }
    fclose(fp);
    return bs;
}

/* ------------------------------------------------------------------
 * Public entry points
 * ------------------------------------------------------------------ */
RtOpcUaTestServer *sn_opcua_test_server_start(long long port, long long mode) {
    UA_Server *server = UA_Server_new();
    if (!server) return NULL;

    UA_ServerConfig *sc = UA_Server_getConfig(server);

    if (mode == 0) {
        UA_ServerConfig_setMinimal(sc, (UA_UInt16)port, NULL);
    } else {
        /* Secured mode: load server PKI + register all policies. */
        UA_ByteString cert = opcua_load_bytestring("tests/pki/server/cert.der");
        UA_ByteString key  = opcua_load_bytestring("tests/pki/server/key.pem");
        UA_ByteString ca   = opcua_load_bytestring("tests/pki/trusted/certs/ca.der");

        UA_ByteString trusted[1];  size_t n_trusted  = 0;
        UA_ByteString issuers[1];  size_t n_issuers  = 0;
        UA_ByteString crls[1];     size_t n_crls     = 0;
        if (ca.length > 0) { trusted[0] = ca; n_trusted = 1; }

        UA_StatusCode rc = UA_ServerConfig_setDefaultWithSecurityPolicies(
            sc, (UA_UInt16)port,
            &cert, &key,
            trusted, n_trusted,
            issuers, n_issuers,
            crls,    n_crls);
        if (rc != UA_STATUSCODE_GOOD) {
            fprintf(stderr, "TestServer secure config failed: %s\n", UA_StatusCode_name(rc));
            UA_ByteString_clear(&cert); UA_ByteString_clear(&key); UA_ByteString_clear(&ca);
            UA_Server_delete(server);
            return NULL;
        }
        UA_ByteString_clear(&cert);
        UA_ByteString_clear(&key);
        UA_ByteString_clear(&ca);

        /* Match applicationUri with the SAN URI.1 embedded in server cert. */
        UA_String_clear(&sc->applicationDescription.applicationUri);
        sc->applicationDescription.applicationUri =
            UA_STRING_ALLOC("urn:sindarin:opcua-test-server");
    }

    /* Populate test nodes. */
    OpcUaTestServerInternal *i = (OpcUaTestServerInternal *)calloc(1, sizeof(*i));
    i->server  = server;
    i->port    = (int)port;
    i->running = true;

    /* Register our test namespace (index 2). */
    UA_UInt16 ns_idx = UA_Server_addNamespace(server, "urn:sindarin:opcua-test");
    if (ns_idx != 2) {
        fprintf(stderr, "TestServer: expected ns=2, got ns=%u\n", ns_idx);
    }

    opcua_test_server_add_demo_nodes(server, i);

    /* Start iterate thread. */
#ifdef _WIN32
    i->thread = (HANDLE)_beginthreadex(NULL, 0, opcua_test_server_thread, i, 0, NULL);
#else
    pthread_create(&i->thread, NULL, opcua_test_server_thread, i);
#endif

    /* Give the server ~100ms to bind. */
#ifdef _WIN32
    Sleep(100);
#else
    usleep(100 * 1000);
#endif

    RtOpcUaTestServer *ts = __sn__OpcUaTestServer__new();
    ts->internal_ptr = (long long)(uintptr_t)i;
    ts->bound_port   = (long long)port;
    return ts;
}

long long sn_opcua_test_server_port(RtOpcUaTestServer *s) {
    return s ? s->bound_port : 0;
}

char *sn_opcua_test_server_url(RtOpcUaTestServer *s) {
    if (!s) return strdup("");
    char buf[128];
    snprintf(buf, sizeof(buf), "opc.tcp://localhost:%d", (int)s->bound_port);
    return strdup(buf);
}

void sn_opcua_test_server_set_counter(RtOpcUaTestServer *s, long long value) {
    if (!s) return;
    OpcUaTestServerInternal *i = tsi(s);
    if (!i || !i->server) return;
    UA_Int32 v = (UA_Int32)value;
    UA_Variant var;
    UA_Variant_setScalar(&var, &v, &UA_TYPES[UA_TYPES_INT32]);
    UA_Server_writeValue(i->server, i->counter_node, var);
}

void sn_opcua_test_server_stop(RtOpcUaTestServer *s) {
    if (!s) return;
    OpcUaTestServerInternal *i = tsi(s);
    if (!i) return;
    if (i->running) {
        i->running = false;
#ifdef _WIN32
        WaitForSingleObject(i->thread, INFINITE);
        CloseHandle(i->thread);
#else
        pthread_join(i->thread, NULL);
#endif
    }
}

void sn_opcua_test_server_dispose(RtOpcUaTestServer *s) {
    if (!s) return;
    OpcUaTestServerInternal *i = tsi(s);
    if (!i) return;
    if (i->running) {
        i->running = false;
#ifdef _WIN32
        WaitForSingleObject(i->thread, INFINITE);
        CloseHandle(i->thread);
#else
        pthread_join(i->thread, NULL);
#endif
    }
    if (i->server) UA_Server_delete(i->server);
    UA_NodeId_clear(&i->counter_node);
    free(i);
    s->internal_ptr = 0;
}
