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
#include <limits.h>
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
extern void interface_ip_add_route(struct interface *iface, struct blob_attr *attr, bool v6);
extern void iprule_add(struct blob_attr *attr, bool v6);
extern void config_parse_interface(struct uci_section *s, bool alias);
extern enum dev_change_type __bridge_reload(struct extdev_bridge *ebr, struct blob_attr *config);

// Forward declarations
static struct interface *create_mock_interface(void);
static struct uci_section *create_mock_uci_section(void);
static struct extdev_bridge *create_mock_bridge(void);
static struct blob_attr *create_blob_from_fuzz_data(const uint8_t *data, size_t size);
static void fuzz_config_parse_route(const uint8_t *data, size_t size);
static void fuzz_interface_ip_add_route(const uint8_t *data, size_t size);
static void fuzz_iprule_add(const uint8_t *data, size_t size);
static void fuzz_config_parse_interface(const uint8_t *data, size_t size);
static void fuzz_bridge_reload(const uint8_t *data, size_t size);
static void fuzz_bonding_create(const uint8_t *data, size_t size);
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
    
    // Initialize device types that we want to fuzz
    // This ensures bonding device type is available for fuzzing
    extern void bonding_device_type_init(void);
    bonding_device_type_init();
    
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

// Create valid blob data from fuzz input
// Instead of passing raw fuzz data as blob (which can cause buffer overflows),
// we create a properly structured blob using the official blob API
static struct blob_attr *create_blob_from_fuzz_data(const uint8_t *data, size_t size) {
    static struct blob_buf fuzz_buf;
    void *array_cookie;
    
    if (size == 0) return NULL;
    
    // Initialize blob buffer - this creates a valid blob structure
    blob_buf_init(&fuzz_buf, 0);
    
    // Create an array to hold route entries (this is what proto_shell_parse_route_list expects)
    array_cookie = blobmsg_open_array(&fuzz_buf, "routes");
    
    // Add fuzz data as blob entries
    // We'll create multiple table entries from the fuzz data
    size_t offset = 0;
    int entry_count = 0;
    
    while (offset < size && entry_count < 10) { // Limit to 10 entries max
        void *table_cookie = blobmsg_open_table(&fuzz_buf, NULL);
        
        // Add some fields that route parsing expects
        if (offset < size) {
            // Use fuzz data to create route fields
            uint8_t field_selector = data[offset] % 4;
            offset++;
            
            switch (field_selector) {
                case 0:
                    if (offset + 4 <= size) {
                        blobmsg_add_string(&fuzz_buf, "target", "192.168.1.0");
                        blobmsg_add_string(&fuzz_buf, "netmask", "255.255.255.0");
                        offset += 4;
                    }
                    break;
                case 1:
                    if (offset + 4 <= size) {
                        blobmsg_add_string(&fuzz_buf, "gateway", "192.168.1.1");
                        offset += 4;
                    }
                    break;
                case 2:
                    if (offset + 4 <= size) {
                        uint32_t metric;
                        memcpy(&metric, data + offset, sizeof(uint32_t));
                        blobmsg_add_u32(&fuzz_buf, "metric", metric % 1000);
                        offset += 4;
                    }
                    break;
                case 3:
                    blobmsg_add_string(&fuzz_buf, "interface", "fuzz_iface");
                    break;
            }
        }
        
        blobmsg_close_table(&fuzz_buf, table_cookie);
        entry_count++;
        
        if (offset >= size) break;
    }
    
    blobmsg_close_array(&fuzz_buf, array_cookie);
    
    // Return the properly constructed blob data
    return blob_data(fuzz_buf.head);
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

// Fuzz interface_ip_add_route function (branch depth: 247)
// This targets the function where user input has FULL control over blob data
// interface_ip_add_route directly calls blobmsg_parse() on user data with minimal validation
static void fuzz_interface_ip_add_route(const uint8_t *data, size_t size) {
    if (!g_mock_iface || size < 8) return;
    
    // Pass raw fuzz data directly as blob - this gives us full control over the blob structure
    // We cast the raw fuzz data to a blob_attr, which is exactly what a real attacker would do
    struct blob_attr *attr = (struct blob_attr *)data;
    
    // Alternate between IPv4 and IPv6 routes based on first byte
    bool v6 = (data[0] % 2) == 1;
    
    // Call the target function directly with raw fuzz data
    // This function will call blobmsg_parse() on our raw data, giving us full control
    // over what gets parsed and how the blob parsing behaves
    interface_ip_add_route(g_mock_iface, attr, v6);
}

// Fuzz iprule_add function (branch depth: 300+)
// This targets another function where user input has FULL control over blob data
// iprule_add directly calls blobmsg_parse() on user data with minimal validation
static void fuzz_iprule_add(const uint8_t *data, size_t size) {
    if (size < 8) return;
    
    // Pass raw fuzz data directly as blob - this gives us full control over the blob structure
    // We cast the raw fuzz data to a blob_attr, which is exactly what a real attacker would do
    struct blob_attr *attr = (struct blob_attr *)data;
    
    // Alternate between IPv4 and IPv6 rules based on first byte
    bool v6 = (data[0] % 2) == 1;
    
    // Call the target function directly with raw fuzz data
    // This function will call blobmsg_parse() on our raw data, giving us full control
    // over what gets parsed and how the blob parsing behaves
    iprule_add(attr, v6);
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

// Fuzz bonding device creation through the realistic device_create entry point
// This targets the bonding_create function through device_create, which is called
// from config_init_devices when parsing UCI "device" sections of type "bonding"
static void fuzz_bonding_create(const uint8_t *data, size_t size) {
    if (size < 8) return;
    
    // Create a structured blob for bonding configuration based on fuzz data
    static struct blob_buf bonding_buf;
    blob_buf_init(&bonding_buf, 0);
    
    size_t offset = 0;
    
    // Add basic bonding configuration fields using fuzz data
    if (offset < size) {
        // Use fuzz data to select bonding policy
        uint8_t policy_idx = data[offset] % 7; // 7 bonding modes available
        const char *policies[] = {
            "balance-rr", "active-backup", "balance-xor", "broadcast",
            "802.3ad", "balance-tlb", "balance-alb"
        };
        blobmsg_add_string(&bonding_buf, "policy", policies[policy_idx]);
        offset++;
    }
    
    // Add ports array
    if (offset + 1 < size) {
        void *ports_array = blobmsg_open_array(&bonding_buf, "ports");
        
        // Add 1-4 ports based on fuzz data
        uint8_t num_ports = 1 + (data[offset] % 4);
        offset++;
        
        for (int i = 0; i < num_ports && offset < size; i++) {
            char port_name[16];
            snprintf(port_name, sizeof(port_name), "eth%d", i);
            blobmsg_add_string(&bonding_buf, NULL, port_name);
        }
        
        blobmsg_close_array(&bonding_buf, ports_array);
    }
    
    // Add other bonding parameters based on remaining fuzz data
    if (offset + 4 <= size) {
        uint32_t min_links;
        memcpy(&min_links, data + offset, sizeof(uint32_t));
        blobmsg_add_u32(&bonding_buf, "min_links", min_links % 8); // Reasonable range
        offset += 4;
    }
    
    if (offset + 4 <= size) {
        uint32_t monitor_interval;
        memcpy(&monitor_interval, data + offset, sizeof(uint32_t));
        blobmsg_add_u32(&bonding_buf, "monitor_interval", monitor_interval % 1000);
        offset += 4;
    }
    
    if (offset < size) {
        blobmsg_add_bool(&bonding_buf, "all_ports_active", data[offset] & 1);
        offset++;
    }
    
    if (offset < size) {
        blobmsg_add_bool(&bonding_buf, "use_carrier", data[offset] & 1);
        offset++;
    }
    
    // Add xmit_hash_policy if balance-xor, balance-tlb, or 802.3ad
    if (offset < size) {
        uint8_t hash_policy_idx = data[offset] % 4;
        const char *hash_policies[] = {
            "layer2", "layer2+3", "layer3+4", "encap2+3"
        };
        blobmsg_add_string(&bonding_buf, "xmit_hash_policy", hash_policies[hash_policy_idx]);
        offset++;
    }
    
    // Add primary port selection
    if (offset < size) {
        char primary_port[16];
        snprintf(primary_port, sizeof(primary_port), "eth%d", data[offset] % 4);
        blobmsg_add_string(&bonding_buf, "primary", primary_port);
        offset++;
    }
    
    // Add additional bonding parameters based on remaining fuzz data
    if (offset + 4 <= size) {
        uint32_t ad_actor_sys_prio;
        memcpy(&ad_actor_sys_prio, data + offset, sizeof(uint32_t));
        blobmsg_add_u32(&bonding_buf, "ad_actor_sys_prio", ad_actor_sys_prio % 65536);
        offset += 4;
    }
    
    if (offset + 4 <= size) {
        uint32_t packets_per_port;
        memcpy(&packets_per_port, data + offset, sizeof(uint32_t));
        blobmsg_add_u32(&bonding_buf, "packets_per_port", packets_per_port % 100);
        offset += 4;
    }
    
    if (offset + 4 <= size) {
        uint32_t updelay;
        memcpy(&updelay, data + offset, sizeof(uint32_t));
        blobmsg_add_u32(&bonding_buf, "updelay", updelay % 1000);
        offset += 4;
    }
    
    if (offset + 4 <= size) {
        uint32_t downdelay;
        memcpy(&downdelay, data + offset, sizeof(uint32_t));
        blobmsg_add_u32(&bonding_buf, "downdelay", downdelay % 1000);
        offset += 4;
    }
    
    if (offset < size) {
        const char *primary_reselect_opts[] = {"always", "better", "failure"};
        uint8_t reselect_idx = data[offset] % 3;
        blobmsg_add_string(&bonding_buf, "primary_reselect", primary_reselect_opts[reselect_idx]);
        offset++;
    }
    
    if (offset < size) {
        const char *failover_mac_opts[] = {"none", "active", "follow"};
        uint8_t failover_idx = data[offset] % 3;
        blobmsg_add_string(&bonding_buf, "failover_mac", failover_mac_opts[failover_idx]);
        offset++;
    }
    
    // Add ARP monitoring configuration
    if (offset < size && (data[offset] & 1)) {
        blobmsg_add_string(&bonding_buf, "monitor_mode", "arp");
        
        // Add ARP targets array
        if (offset + 1 < size) {
            void *arp_targets = blobmsg_open_array(&bonding_buf, "arp_target");
            blobmsg_add_string(&bonding_buf, NULL, "192.168.1.1");
            blobmsg_add_string(&bonding_buf, NULL, "192.168.1.254");
            blobmsg_close_array(&bonding_buf, arp_targets);
        }
        
        if (offset + 1 < size) {
            blobmsg_add_bool(&bonding_buf, "arp_all_targets", data[offset + 1] & 1);
        }
        
        offset += 2;
    }
    
    // Get the bonding device type
    extern struct device_type *device_type_get(const char *name);
    struct device_type *bonding_type = device_type_get("bonding");
    if (!bonding_type) {
        // If bonding type is not registered, we can't test it
        return;
    }
    
    // Create a unique bonding device name for each test
    static int bonding_counter = 0;
    char bonding_name[32];
    snprintf(bonding_name, sizeof(bonding_name), "bond%d", bonding_counter++);
    
    // Call device_create which will invoke bonding_create through the function pointer
    // This is the exact same path used by config_init_devices() in config.c
    extern struct device *device_create(const char *name, struct device_type *type, struct blob_attr *config);
    struct device *bonding_dev = device_create(bonding_name, bonding_type, blob_data(bonding_buf.head));
    
    // Clean up the created device to prevent resource leaks
    if (bonding_dev) {
        // Use the device's own cleanup mechanism
        extern void device_cleanup(struct device *dev);
        
        // Mark it as not current to allow cleanup
        bonding_dev->current_config = false;
        
        // Set it as not present to trigger cleanup
        extern void device_set_present(struct device *dev, bool state);
        device_set_present(bonding_dev, false);
        
        // Call the bonding-specific free function if available
        if (bonding_dev->type && bonding_dev->type->free) {
            bonding_dev->type->free(bonding_dev);
        } else {
            // Fallback cleanup
            if (bonding_dev->config) {
                free(bonding_dev->config);
                bonding_dev->config = NULL;
            }
            device_cleanup(bonding_dev);
        }
    }
}

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
    uint8_t strategy = data[0] % 6;
    const uint8_t *fuzz_data = data + 1;
    size_t fuzz_size = size - 1;
    
    switch (strategy) {
        case 0:
            // Fuzz config_parse_route (branch depth: 246)
            fuzz_config_parse_route(fuzz_data, fuzz_size);
            break;
        case 1:
            // Fuzz interface_ip_add_route (branch depth: 247) - DIRECT USER CONTROL
            fuzz_interface_ip_add_route(fuzz_data, fuzz_size);
            break;
        case 2:
            // Fuzz iprule_add (branch depth: 300+) - DIRECT USER CONTROL
            fuzz_iprule_add(fuzz_data, fuzz_size);
            break;
        case 3:
            // Fuzz config_parse_interface (branch depth: 44)
            fuzz_config_parse_interface(fuzz_data, fuzz_size);
            break;
        case 4:
            // Fuzz __bridge_reload (branch depth: 40)
            fuzz_bridge_reload(fuzz_data, fuzz_size);
            break;
        case 5:
            // Fuzz bonding_create through device_create entry point
            fuzz_bonding_create(fuzz_data, fuzz_size);
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


// #ifndef __AFL_FUZZ_TESTCASE_LEN

// ssize_t fuzz_len;
// unsigned char fuzz_buf[1024000];

// #define __AFL_FUZZ_TESTCASE_LEN fuzz_len
// #define __AFL_FUZZ_TESTCASE_BUF fuzz_buf  
// #define __AFL_FUZZ_INIT() void sync(void);
// #define __AFL_LOOP(x) \
//     ((fuzz_len = read(0, fuzz_buf, sizeof(fuzz_buf))) > 0 ? 1 : 0)
// #define __AFL_INIT() sync()

// #endif

// __AFL_FUZZ_INIT();

// #pragma clang optimize off
// #pragma GCC optimize("O0")

// int main(int argc, char **argv)
// {
//     (void)argc; (void)argv; 
    
//     ssize_t len;
//     unsigned char *buf;

//     __AFL_INIT();
//     buf = __AFL_FUZZ_TESTCASE_BUF;
//     while (__AFL_LOOP(INT_MAX)) {
//         len = __AFL_FUZZ_TESTCASE_LEN;
//         LLVMFuzzerTestOneInput(buf, (size_t)len);
//     }
    
//     return 0;
// }
