#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdbool.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>

// Include netifd headers
#include "netifd.h"
#include "interface.h"
#include "interface-ip.h"
#include "proto.h"
#include "config.h"
#include "device.h"
#include "system.h"
#include "extdev.h"

// Include UCI for configuration parsing
#include <uci.h>

// Include libubox for blob message handling
#include <libubox/blobmsg.h>
#include <libubox/blobmsg_json.h>
#include <libubox/blob.h>

// Extdev structure definitions (from extdev.c)
struct extdev_type {
    struct device_type handler;
    const char *name;
    uint32_t peer_id;
    struct ubus_subscriber ubus_sub;
    bool subscribed;
    struct ubus_event_handler obj_wait;
    struct uci_blob_param_list *config_params;
    char *config_strbuf;
    struct uci_blob_param_list *info_params;
    char *info_strbuf;
    struct uci_blob_param_list *stats_params;
    char *stats_strbuf;
};

struct extdev_device {
    struct device dev;
    struct extdev_type *etype;
    const char *dep_name;
    struct uloop_timeout retry;
};

struct extdev_bridge {
    struct extdev_device edev;
    device_state_cb set_state;
    struct blob_attr *config;
    bool empty;
    struct blob_attr *ifnames;
    bool active;
    bool force_active;
    struct uloop_timeout retry;
    struct vlist_tree members;
    int n_present;
    int n_failed;
};

struct extdev_bridge_member {
    struct vlist_node node;
    struct extdev_bridge *parent_br;
    struct device_user dev_usr;
    bool present;
    char *name;
};

// Function prototypes for the functions we want to fuzz (high branch depth targets)
extern void config_parse_route(struct uci_section *s, bool v6);
extern void proto_shell_parse_route_list(struct interface *iface, struct blob_attr *attr, bool v6);
extern void config_parse_interface(struct uci_section *s, bool alias);
extern enum dev_change_type __bridge_reload(struct extdev_bridge *ebr, struct blob_attr *config);

// Forward declarations
static struct interface *create_mock_interface(void);
static struct uci_section *create_mock_uci_section(void);
static struct extdev_bridge *create_mock_bridge(void);
static struct blob_attr *create_blob_from_fuzz_data(const uint8_t *data, size_t size);
static void fuzz_config_parse_route(const uint8_t *data, size_t size);
static void fuzz_proto_shell_parse_route_list(const uint8_t *data, size_t size);
static void fuzz_config_parse_interface(const uint8_t *data, size_t size);
static void fuzz_bridge_reload(const uint8_t *data, size_t size);
static void cleanup_mock_structures(void);

// Global mock structures for testing
static struct interface *g_mock_iface = NULL;
static struct uci_section *g_mock_section = NULL;
static struct extdev_bridge *g_mock_bridge = NULL;

// Global fuzzing state
static bool g_fuzzing_mode = false;

// Initialize minimal netifd state for fuzzing
static void init_netifd_for_fuzzing(void) {
    static bool initialized = false;
    if (initialized) return;
    
    // Set fuzzing mode flag (though we removed the stub functions)
    g_fuzzing_mode = true;
    
    // Initialize ubus context for fuzzing - use a dummy path since we won't actually connect
    // This will set ubus_ctx to NULL if connection fails, but that's expected in fuzzing
    extern int netifd_ubus_init(const char *path);
    netifd_ubus_init("/tmp/dummy_ubus_socket");
    
    // If ubus init failed (which is expected in fuzzing), create a minimal mock context
    extern struct ubus_context *ubus_ctx;
    if (!ubus_ctx) {
        ubus_ctx = calloc(1, sizeof(struct ubus_context));
        if (ubus_ctx) {
            // Initialize basic ubus context fields to prevent null pointer dereferences
            ubus_ctx->sock.fd = -1; // Invalid fd to indicate not connected
            ubus_ctx->local_id = 0xffffffff; // Invalid ID
            
            // Initialize the pending list to prevent crashes in ubus operations
            INIT_LIST_HEAD(&ubus_ctx->pending);
            INIT_LIST_HEAD(&ubus_ctx->requests);
        }
    }
    
    initialized = true;
}

// Create a mock interface for fuzzing
static struct interface *create_mock_interface(void) {
    struct interface *iface = calloc(1, sizeof(struct interface));
    if (!iface) return NULL;
    
    // Initialize basic fields
    iface->name = "fuzz_interface";
    iface->state = IFS_DOWN;
    iface->config_state = IFC_NORMAL;
    iface->enabled = true;
    iface->autostart = true;
    
    // Initialize lists
    INIT_LIST_HEAD(&iface->errors);
    INIT_LIST_HEAD(&iface->users);
    INIT_LIST_HEAD(&iface->assignment_classes);
    
    // Initialize IP settings
    memset(&iface->config_ip, 0, sizeof(iface->config_ip));
    memset(&iface->proto_ip, 0, sizeof(iface->proto_ip));
    
    // Initialize vlists for IP settings
    vlist_init(&iface->proto_ip.addr, avl_strcmp, NULL);
    vlist_init(&iface->proto_ip.route, avl_strcmp, NULL);
    vlist_init(&iface->proto_ip.prefix, avl_strcmp, NULL);
    
    return iface;
}

// Create a mock UCI section for config parsing
static struct uci_section *create_mock_uci_section(void) {
    // Allocate UCI context first if needed (needed for proper UCI initialization)
    static struct uci_context *mock_ctx = NULL;
    static struct uci_package *mock_pkg = NULL;
    
    if (!mock_ctx) {
        mock_ctx = calloc(1, sizeof(struct uci_context));
        if (!mock_ctx) return NULL;
        
        // Initialize the context with basic required fields
        mock_ctx->root.next = &mock_ctx->root;
        mock_ctx->root.prev = &mock_ctx->root;
        mock_ctx->backends.next = &mock_ctx->backends;
        mock_ctx->backends.prev = &mock_ctx->backends;
        mock_ctx->delta_path.next = &mock_ctx->delta_path;
        mock_ctx->delta_path.prev = &mock_ctx->delta_path;
    }
    
    if (!mock_pkg) {
        mock_pkg = calloc(1, sizeof(struct uci_package));
        if (!mock_pkg) return NULL;
        
        // Initialize package element
        mock_pkg->e.type = 2; // UCI_TYPE_PACKAGE
        mock_pkg->e.name = "mock_package";
        mock_pkg->e.list.next = &mock_pkg->e.list;
        mock_pkg->e.list.prev = &mock_pkg->e.list;
        
        // Initialize sections list
        mock_pkg->sections.next = &mock_pkg->sections;
        mock_pkg->sections.prev = &mock_pkg->sections;
        
        // Initialize delta lists
        mock_pkg->delta.next = &mock_pkg->delta;
        mock_pkg->delta.prev = &mock_pkg->delta;
        mock_pkg->saved_delta.next = &mock_pkg->saved_delta;
        mock_pkg->saved_delta.prev = &mock_pkg->saved_delta;
        
        mock_pkg->ctx = mock_ctx;
    }
    
    struct uci_section *section = calloc(1, sizeof(struct uci_section));
    if (!section) return NULL;
    
    // Initialize the embedded uci_element structure properly
    section->e.type = 3; // UCI_TYPE_SECTION
    section->e.name = "mock_section";
    section->e.list.next = &section->e.list;
    section->e.list.prev = &section->e.list;
    
    // Initialize the options list
    section->options.next = &section->options;
    section->options.prev = &section->options;
    
    // Set basic fields
    section->type = "interface"; // Changed from "route" to "interface" for interface parsing
    section->package = mock_pkg;
    section->anonymous = false;
    
    return section;
}

// Create a mock bridge for bridge reload testing
static struct extdev_bridge *create_mock_bridge(void) {
    struct extdev_bridge *bridge = calloc(1, sizeof(struct extdev_bridge));
    if (!bridge) return NULL;
    
    // Create mock extdev_type with config_params
    static struct extdev_type mock_extdev_type = {0};
    static struct uci_blob_param_list mock_config_params = {0};
    static struct device_type mock_device_type = {0};
    
    // Initialize mock config params
    mock_config_params.n_params = 0;
    mock_config_params.params = NULL;
    
    // Initialize mock device type
    mock_device_type.config_params = &mock_config_params;
    mock_device_type.name = "mock_bridge";
    
    // Initialize mock extdev_type
    mock_extdev_type.handler = mock_device_type;
    mock_extdev_type.name = "mock_bridge";
    mock_extdev_type.config_params = &mock_config_params;
    mock_extdev_type.subscribed = false;
    
    // Initialize the bridge structure
    bridge->edev.dev.type = &mock_device_type;
    strcpy(bridge->edev.dev.ifname, "mock_bridge0");
    bridge->edev.dev.present = false;
    bridge->edev.dev.active = false;
    bridge->edev.dev.config_pending = false;
    bridge->edev.etype = &mock_extdev_type;
    bridge->edev.dep_name = NULL;
    
    // Initialize bridge-specific fields
    bridge->config = NULL;
    bridge->empty = false;
    bridge->ifnames = NULL;
    bridge->active = false;
    bridge->force_active = false;
    bridge->n_present = 0;
    bridge->n_failed = 0;
    
    // Initialize lists
    INIT_SAFE_LIST(&bridge->edev.dev.users);
    vlist_init(&bridge->members, avl_strcmp, NULL);
    
    return bridge;
}

// Cleanup mock structures
static void cleanup_mock_structures(void) {
    if (g_mock_iface) {
        struct interface_error *error, *tmp;
        list_for_each_entry_safe(error, tmp, &g_mock_iface->errors, list) {
            list_del(&error->list);
            free(error);
        }
        free(g_mock_iface);
        g_mock_iface = NULL;
    }
    
    if (g_mock_section) {
        // The section contains static references to mock_ctx and mock_pkg
        // which are managed by create_mock_uci_section, so we only free the section itself
        free(g_mock_section);
        g_mock_section = NULL;
    }
    
    if (g_mock_bridge) {
        // Free the config blob that might have been allocated by __bridge_reload
        if (g_mock_bridge->config) {
            free(g_mock_bridge->config);
            g_mock_bridge->config = NULL;
        }
        free(g_mock_bridge);
        g_mock_bridge = NULL;
    }
    
    // Clean up the ubus context if we created it
    extern struct ubus_context *ubus_ctx;
    if (g_fuzzing_mode && ubus_ctx) {
        // Check if this is our mock context (fd == -1) vs a real context
        if (ubus_ctx->sock.fd == -1) {
            free(ubus_ctx);
            ubus_ctx = NULL;
        } else {
            // Let netifd_ubus_done handle real contexts
            extern void netifd_ubus_done(void);
            netifd_ubus_done();
        }
    }
}

// Create blob data from fuzz input
// This mimics exactly how netifd handles blob validation - it trusts the blob functions
static struct blob_attr *create_blob_from_fuzz_data(const uint8_t *data, size_t size) {
    // Minimum size check - same as what netifd would expect
    if (size < sizeof(struct blob_attr)) return NULL;
    
    // Cast to blob_attr directly - this is exactly what netifd code does
    struct blob_attr *attr = (struct blob_attr *)data;
    
    // Use the same validation pattern as the real netifd code:
    // Only do basic bounds checking to prevent immediate buffer overflows
    
    // Check if the blob length makes sense using the actual blob_len() function
    // but protect against it reading out of bounds first
    size_t claimed_len = blob_len(attr);
    size_t total_len = claimed_len + sizeof(struct blob_attr);
    
    // Basic overflow protection - this is the minimum netifd would need
    if (total_len > size || total_len < sizeof(struct blob_attr)) {
        return NULL;
    }
    
    // Let the blob functions and target functions handle everything else,
    // just like the real netifd code does
    return attr;
}

// Fuzz config_parse_route function (branch depth: 246)
// This mimics exactly how config.c validates UCI sections - it doesn't use blob data at all!
// config_parse_route works with UCI sections, not blob attributes
static void fuzz_config_parse_route(const uint8_t *data, size_t size) {
    if (!g_mock_section || size == 0) return;
    
    // Use the exact same pattern as config.c:
    // config_parse_route() just takes a UCI section and calls uci_to_blob() internally
    // It doesn't validate blob data - it validates UCI section data
    
    // Set section type for route parsing
    g_mock_section->type = "route";
    
    // Alternate between IPv4 and IPv6 routes based on data
    bool v6 = (data[0] % 2) == 1;
    
    // Call the target function - it will do its own uci_to_blob() conversion and
    // then call interface_ip_add_route() with the resulting blob, exactly like the real code
    config_parse_route(g_mock_section, v6);
}

// Fuzz proto_shell_parse_route_list function (branch depth: 247)
// This mimics exactly how proto-shell.c validates and processes blob data
static void fuzz_proto_shell_parse_route_list(const uint8_t *data, size_t size) {
    if (!g_mock_iface) return;
    
    struct blob_attr *attr = create_blob_from_fuzz_data(data, size);
    if (!attr) return;
    
    // Use the exact same pattern as proto-shell.c:
    // Just check for NULL attribute (line 603 in proto-shell.c: "if (!attr) goto out;")
    // and let the function handle the rest
    
    // Alternate between IPv4 and IPv6 routes based on data
    bool v6 = (data[0] % 2) == 1;
    
    // Call the target function - it will do its own validation using blobmsg_for_each_attr
    // and blobmsg_type checks, exactly like the real code
    proto_shell_parse_route_list(g_mock_iface, attr, v6);
}

// Fuzz config_parse_interface function (branch depth: 44)
// This mimics exactly how config.c validates UCI sections - it doesn't use blob data at all!
// config_parse_interface works with UCI sections, not blob attributes
static void fuzz_config_parse_interface(const uint8_t *data, size_t size) {
    if (!g_mock_section || size == 0) return;
    
    // Use the exact same pattern as config.c:
    // config_parse_interface() just takes a UCI section and calls uci_to_blob() internally
    // It doesn't validate blob data - it validates UCI section data
    
    // Alternate between alias and non-alias interfaces
    bool alias = (data[0] % 2) == 1;
    
    // Update section type for interface parsing
    g_mock_section->type = "interface";
    
    // Call the target function - it will do its own uci_to_blob() conversion,
    // exactly like the real code
    config_parse_interface(g_mock_section, alias);
}

// Fuzz __bridge_reload function (branch depth: 40)  
// This mimics exactly how extdev.c validates and processes blob data
// Note: __bridge_reload calls blob_memdup() which allocates memory and stores it in ebr->config.
// We need to carefully manage this memory to avoid leaks during fuzzing iterations.
static void fuzz_bridge_reload(const uint8_t *data, size_t size) {
    if (!g_mock_bridge) return;
    
    struct blob_attr *attr = create_blob_from_fuzz_data(data, size);
    if (!attr) return;
    
    // Use the exact same pattern as __bridge_reload in extdev.c:
    // It just checks "if (config)" and then immediately does blob_memdup() and blobmsg_parse()
    // No other validation is done at the input level
    
    // Save the current config pointer to free it later if it gets replaced
    struct blob_attr *old_config = g_mock_bridge->config;
    
    // Call the target function - it will do its own validation using blobmsg_parse
    // and blobmsg_data/blobmsg_len functions, exactly like the real code
    __bridge_reload(g_mock_bridge, attr);
    
    // Clean up the old config if it was replaced
    if (old_config && old_config != g_mock_bridge->config) {
        free(old_config);
    }
}

// Note: Removed duplicate function definitions that are already defined in netifd source
// The original functions from system-dummy.o and ubus.o will be used instead

// Main fuzzing entry point
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Initialize netifd state if needed
    init_netifd_for_fuzzing();
    
    // Create mock structures if needed
    if (!g_mock_iface) {
        g_mock_iface = create_mock_interface();
        if (!g_mock_iface) return 0;
    }
    
    if (!g_mock_section) {
        g_mock_section = create_mock_uci_section();
        if (!g_mock_section) return 0;
    }
    
    if (!g_mock_bridge) {
        g_mock_bridge = create_mock_bridge();
        if (!g_mock_bridge) return 0;
    }
    
    // Skip very small inputs
    if (size < 2) return 0;
    
    // Use first byte to determine which high-complexity function to fuzz
    uint8_t strategy = data[0] % 4;
    const uint8_t *fuzz_data = data + 1;
    size_t fuzz_size = size - 1;
    
    switch (strategy) {
        case 0:
            // Fuzz config_parse_route (highest branch depth: 246)
            fuzz_config_parse_route(fuzz_data, fuzz_size);
            break;
        case 1:
            // Fuzz proto_shell_parse_route_list (highest branch depth: 247)
            fuzz_proto_shell_parse_route_list(fuzz_data, fuzz_size);
            break;
        case 2:
            // Fuzz config_parse_interface (branch depth: 44)
            fuzz_config_parse_interface(fuzz_data, fuzz_size);
            break;
        case 3:
            // Fuzz __bridge_reload (branch depth: 40)
            fuzz_bridge_reload(fuzz_data, fuzz_size);
            break;
    }
    
    // Clean up any allocated memory from this test case
    if (g_mock_bridge && g_mock_bridge->config) {
        free(g_mock_bridge->config);
        g_mock_bridge->config = NULL;
    }
    
    // Reset other bridge state that might have been modified
    if (g_mock_bridge) {
        g_mock_bridge->ifnames = NULL; // This points into config data, so don't free separately
        g_mock_bridge->empty = false;
        g_mock_bridge->active = false;
        g_mock_bridge->force_active = false;
        g_mock_bridge->n_present = 0;
        g_mock_bridge->n_failed = 0;
    }
    
    return 0;
}

// Cleanup function called at program termination
__attribute__((destructor))
static void fuzz_cleanup(void) {
    cleanup_mock_structures();
}