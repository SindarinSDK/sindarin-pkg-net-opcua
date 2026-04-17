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

/* Silence open62541's own logging unless OPCUA_VERBOSE=1. */
static void ts_null_log_cb(void *ctx, UA_LogLevel level, UA_LogCategory cat,
                           const char *msg, va_list args) {
    (void)ctx; (void)level; (void)cat; (void)msg; (void)args;
}
static UA_Logger TS_NULL_LOGGER = { ts_null_log_cb, NULL, NULL };
static bool ts_verbose(void) {
    const char *v = getenv("OPCUA_VERBOSE");
    return v && v[0] && v[0] != '0';
}
static UA_Logger *ts_resolve_logger(UA_Logger *current) {
    return ts_verbose() ? current : &TS_NULL_LOGGER;
}

/* Redirect stdout to /dev/null for the duration of the test server's life.
 * open62541 writes its INFO/WARN diagnostics directly to stdout via its
 * default logger, which pollutes .expected-file comparisons in the test
 * runner. Tests only care about the PASS marker, which is printed from
 * Sindarin AFTER server.stop() restores stdout. */
#include <fcntl.h>
#ifdef _WIN32
#include <io.h>
#define TS_STDOUT_FD   _fileno(stdout)
#define TS_STDERR_FD   _fileno(stderr)
#define TS_DUP(fd)     _dup(fd)
#define TS_DUP2(o,n)   _dup2((o),(n))
#define TS_CLOSE(fd)   _close(fd)
#define TS_OPEN_NULL() _open("NUL", _O_WRONLY)
#else
#define TS_STDOUT_FD   STDOUT_FILENO
#define TS_STDERR_FD   STDERR_FILENO
#define TS_DUP(fd)     dup(fd)
#define TS_DUP2(o,n)   dup2((o),(n))
#define TS_CLOSE(fd)   close(fd)
#define TS_OPEN_NULL() open("/dev/null", O_WRONLY)
#endif

static int ts_stdout_saved_fd = -1;
static void ts_stdout_silence(void) {
    if (ts_verbose() || ts_stdout_saved_fd >= 0) return;
    fflush(stdout);
    fflush(stderr);
    ts_stdout_saved_fd = TS_DUP(TS_STDOUT_FD);
    int null_fd = TS_OPEN_NULL();
    if (null_fd >= 0) {
        TS_DUP2(null_fd, TS_STDOUT_FD);
        TS_DUP2(null_fd, TS_STDERR_FD);
        TS_CLOSE(null_fd);
    }
}
static void ts_stdout_restore(void) {
    if (ts_verbose() || ts_stdout_saved_fd < 0) return;
    fflush(stdout);
    fflush(stderr);
    TS_DUP2(ts_stdout_saved_fd, TS_STDOUT_FD);
    TS_DUP2(ts_stdout_saved_fd, TS_STDERR_FD);
    TS_CLOSE(ts_stdout_saved_fd);
    ts_stdout_saved_fd = -1;
}

typedef struct {
    UA_Server    *server;
    srv_thread_t  thread;
    volatile UA_Boolean running;
    int           port;
    /* Pre-added node ids cached for fast external set. */
    UA_NodeId     counter_node;
    UA_NodeId     analog_node;
    UA_NodeId     alarm_node;
    UA_NodeId     demo_folder_id;
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
    UA_NodeId_copy(&folder_id, &i->demo_folder_id);

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

    /* Demo.Analog — AnalogItemType (Double, RW) */
    {
        UA_VariableAttributes vattr = UA_VariableAttributes_default;
        UA_Double v = 25.0;
        UA_Variant_setScalar(&vattr.value, &v, &UA_TYPES[UA_TYPES_DOUBLE]);
        vattr.displayName = UA_LOCALIZEDTEXT("en-US", "Analog");
        vattr.accessLevel = UA_ACCESSLEVELMASK_READ | UA_ACCESSLEVELMASK_WRITE;
        vattr.dataType = UA_TYPES[UA_TYPES_DOUBLE].typeId;
        UA_NodeId out;
        UA_Server_addVariableNode(server, UA_NODEID_STRING(2, "Demo.Analog"),
            folder_id, UA_NODEID_NUMERIC(0, UA_NS0ID_HASCOMPONENT),
            UA_QUALIFIEDNAME(2, "Analog"),
            UA_NODEID_NUMERIC(0, UA_NS0ID_ANALOGITEMTYPE),
            vattr, NULL, &out);
        UA_NodeId_copy(&out, &i->analog_node);
    }
    /* Demo.Analog → EURange (HasProperty) */
    {
        UA_VariableAttributes vattr = UA_VariableAttributes_default;
        UA_Range range;
        range.low  = 0.0;
        range.high = 100.0;
        UA_Variant_setScalar(&vattr.value, &range, &UA_TYPES[UA_TYPES_RANGE]);
        vattr.displayName = UA_LOCALIZEDTEXT("en-US", "EURange");
        vattr.dataType = UA_TYPES[UA_TYPES_RANGE].typeId;
        UA_Server_addVariableNode(server, UA_NODEID_STRING(2, "Demo.Analog.EURange"),
            i->analog_node, UA_NODEID_NUMERIC(0, UA_NS0ID_HASPROPERTY),
            UA_QUALIFIEDNAME(0, "EURange"),
            UA_NODEID_NUMERIC(0, UA_NS0ID_PROPERTYTYPE),
            vattr, NULL, NULL);
    }
    /* Demo.Analog → EngineeringUnits (HasProperty) */
    {
        UA_VariableAttributes vattr = UA_VariableAttributes_default;
        UA_EUInformation eu;
        memset(&eu, 0, sizeof(eu));
        eu.namespaceUri = UA_STRING("http://www.opcfoundation.org/UA/units/un/cefact");
        eu.unitId = 4408652;  /* degree Celsius */
        eu.displayName = UA_LOCALIZEDTEXT("en-US", "\xc2\xb0""C");
        eu.description = UA_LOCALIZEDTEXT("en-US", "degree Celsius");
        UA_Variant_setScalar(&vattr.value, &eu, &UA_TYPES[UA_TYPES_EUINFORMATION]);
        vattr.displayName = UA_LOCALIZEDTEXT("en-US", "EngineeringUnits");
        vattr.dataType = UA_TYPES[UA_TYPES_EUINFORMATION].typeId;
        UA_Server_addVariableNode(server, UA_NODEID_STRING(2, "Demo.Analog.EngineeringUnits"),
            i->analog_node, UA_NODEID_NUMERIC(0, UA_NS0ID_HASPROPERTY),
            UA_QUALIFIEDNAME(0, "EngineeringUnits"),
            UA_NODEID_NUMERIC(0, UA_NS0ID_PROPERTYTYPE),
            vattr, NULL, NULL);
    }

    /* Demo.Alarm — TwoStateDiscreteType (Boolean) */
    {
        UA_VariableAttributes vattr = UA_VariableAttributes_default;
        UA_Boolean v = false;
        UA_Variant_setScalar(&vattr.value, &v, &UA_TYPES[UA_TYPES_BOOLEAN]);
        vattr.displayName = UA_LOCALIZEDTEXT("en-US", "Alarm");
        vattr.accessLevel = UA_ACCESSLEVELMASK_READ | UA_ACCESSLEVELMASK_WRITE;
        vattr.dataType = UA_TYPES[UA_TYPES_BOOLEAN].typeId;
        UA_NodeId out;
        UA_Server_addVariableNode(server, UA_NODEID_STRING(2, "Demo.Alarm"),
            folder_id, UA_NODEID_NUMERIC(0, UA_NS0ID_HASCOMPONENT),
            UA_QUALIFIEDNAME(2, "Alarm"),
            UA_NODEID_NUMERIC(0, UA_NS0ID_TWOSTATEDISCRETETYPE),
            vattr, NULL, &out);
        UA_NodeId_copy(&out, &i->alarm_node);
    }
    /* Demo.Alarm → TrueState (HasProperty) */
    {
        UA_VariableAttributes vattr = UA_VariableAttributes_default;
        UA_LocalizedText ts = UA_LOCALIZEDTEXT("en-US", "Active");
        UA_Variant_setScalar(&vattr.value, &ts, &UA_TYPES[UA_TYPES_LOCALIZEDTEXT]);
        vattr.displayName = UA_LOCALIZEDTEXT("en-US", "TrueState");
        vattr.dataType = UA_TYPES[UA_TYPES_LOCALIZEDTEXT].typeId;
        UA_Server_addVariableNode(server, UA_NODEID_STRING(2, "Demo.Alarm.TrueState"),
            i->alarm_node, UA_NODEID_NUMERIC(0, UA_NS0ID_HASPROPERTY),
            UA_QUALIFIEDNAME(0, "TrueState"),
            UA_NODEID_NUMERIC(0, UA_NS0ID_PROPERTYTYPE),
            vattr, NULL, NULL);
    }
    /* Demo.Alarm → FalseState (HasProperty) */
    {
        UA_VariableAttributes vattr = UA_VariableAttributes_default;
        UA_LocalizedText fs = UA_LOCALIZEDTEXT("en-US", "Inactive");
        UA_Variant_setScalar(&vattr.value, &fs, &UA_TYPES[UA_TYPES_LOCALIZEDTEXT]);
        vattr.displayName = UA_LOCALIZEDTEXT("en-US", "FalseState");
        vattr.dataType = UA_TYPES[UA_TYPES_LOCALIZEDTEXT].typeId;
        UA_Server_addVariableNode(server, UA_NODEID_STRING(2, "Demo.Alarm.FalseState"),
            i->alarm_node, UA_NODEID_NUMERIC(0, UA_NS0ID_HASPROPERTY),
            UA_QUALIFIEDNAME(0, "FalseState"),
            UA_NODEID_NUMERIC(0, UA_NS0ID_PROPERTYTYPE),
            vattr, NULL, NULL);
    }

    /* Demo.Temperature — Variable with Description attribute */
    {
        UA_VariableAttributes vattr = UA_VariableAttributes_default;
        UA_Double v = 36.6;
        UA_Variant_setScalar(&vattr.value, &v, &UA_TYPES[UA_TYPES_DOUBLE]);
        vattr.displayName = UA_LOCALIZEDTEXT("en-US", "Temperature");
        vattr.description = UA_LOCALIZEDTEXT("en-US", "Process temperature sensor");
        vattr.accessLevel = UA_ACCESSLEVELMASK_READ | UA_ACCESSLEVELMASK_WRITE;
        vattr.dataType = UA_TYPES[UA_TYPES_DOUBLE].typeId;
        UA_Server_addVariableNode(server, UA_NODEID_STRING(2, "Demo.Temperature"),
            folder_id, UA_NODEID_NUMERIC(0, UA_NS0ID_HASCOMPONENT),
            UA_QUALIFIEDNAME(2, "Temperature"),
            UA_NODEID_NUMERIC(0, UA_NS0ID_BASEDATAVARIABLETYPE),
            vattr, NULL, NULL);
    }

    /* Make Demo folder event-notifiable. */
    UA_Server_writeEventNotifier(server, folder_id,
                                 UA_EVENTNOTIFIERTYPE_SUBSCRIBETOEVENTS);
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
    ts_stdout_silence();
    UA_Server *server = UA_Server_new();
    if (!server) { ts_stdout_restore(); return NULL; }

    UA_ServerConfig *sc = UA_Server_getConfig(server);

    if (mode == 0) {
        UA_ServerConfig_setMinimal(sc, (UA_UInt16)port, NULL);
        sc->logging = ts_resolve_logger(sc->logging);
        if (sc->eventLoop) sc->eventLoop->logger = sc->logging;
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

        sc->logging = ts_resolve_logger(sc->logging);
        if (sc->eventLoop) sc->eventLoop->logger = sc->logging;
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

void sn_opcua_test_server_set_analog(RtOpcUaTestServer *s, double value) {
    if (!s) return;
    OpcUaTestServerInternal *i = tsi(s);
    if (!i || !i->server) return;
    UA_Double v = value;
    UA_Variant var;
    UA_Variant_setScalar(&var, &v, &UA_TYPES[UA_TYPES_DOUBLE]);
    UA_Server_writeValue(i->server, i->analog_node, var);
}

void sn_opcua_test_server_set_alarm(RtOpcUaTestServer *s, bool active) {
    if (!s) return;
    OpcUaTestServerInternal *i = tsi(s);
    if (!i || !i->server) return;
    UA_Boolean v = active ? UA_TRUE : UA_FALSE;
    UA_Variant var;
    UA_Variant_setScalar(&var, &v, &UA_TYPES[UA_TYPES_BOOLEAN]);
    UA_Server_writeValue(i->server, i->alarm_node, var);
}

void sn_opcua_test_server_trigger_event(RtOpcUaTestServer *s, long long severity, char *message) {
#ifdef UA_ENABLE_SUBSCRIPTIONS_EVENTS
    if (!s) return;
    OpcUaTestServerInternal *i = tsi(s);
    if (!i || !i->server) return;

    UA_NodeId eventNodeId;
    UA_StatusCode rc = UA_Server_createEvent(i->server,
        UA_NODEID_NUMERIC(0, UA_NS0ID_BASEEVENTTYPE), &eventNodeId);
    if (rc != UA_STATUSCODE_GOOD) {
        fprintf(stderr, "TestServer: createEvent failed: %s\n", UA_StatusCode_name(rc));
        return;
    }

    /* Severity (UInt16) */
    UA_UInt16 sev = (UA_UInt16)severity;
    UA_Server_writeObjectProperty_scalar(i->server, eventNodeId,
        UA_QUALIFIEDNAME(0, "Severity"), &sev, &UA_TYPES[UA_TYPES_UINT16]);

    /* Message (LocalizedText) */
    UA_LocalizedText msg = UA_LOCALIZEDTEXT("en-US", message ? message : "");
    UA_Server_writeObjectProperty_scalar(i->server, eventNodeId,
        UA_QUALIFIEDNAME(0, "Message"), &msg, &UA_TYPES[UA_TYPES_LOCALIZEDTEXT]);

    /* SourceName (String) */
    UA_String srcName = UA_STRING("Demo");
    UA_Server_writeObjectProperty_scalar(i->server, eventNodeId,
        UA_QUALIFIEDNAME(0, "SourceName"), &srcName, &UA_TYPES[UA_TYPES_STRING]);

    /* Time (DateTime) */
    UA_DateTime now = UA_DateTime_now();
    UA_Server_writeObjectProperty_scalar(i->server, eventNodeId,
        UA_QUALIFIEDNAME(0, "Time"), &now, &UA_TYPES[UA_TYPES_DATETIME]);

    /* Trigger on Demo folder. */
    rc = UA_Server_triggerEvent(i->server, eventNodeId, i->demo_folder_id, NULL, UA_TRUE);
    if (rc != UA_STATUSCODE_GOOD) {
        fprintf(stderr, "TestServer: triggerEvent failed: %s\n", UA_StatusCode_name(rc));
    }
#else
    (void)s; (void)severity; (void)message;
#endif
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
    ts_stdout_restore();
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
    UA_NodeId_clear(&i->analog_node);
    UA_NodeId_clear(&i->alarm_node);
    UA_NodeId_clear(&i->demo_folder_id);
    free(i);
    s->internal_ptr = 0;
}
