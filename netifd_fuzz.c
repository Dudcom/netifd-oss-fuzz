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

// Initialize minimal netifd state for fuzzing
static void init_netifd_for_fuzzing(void) {
    static bool initialized = false;
    if (initialized) return;
    
    // Initialize minimal required state
    // Note: This is a simplified initialization for fuzzing purposes
    
    initialized = true;
}

// Create a mock interface for fuzzing
static struct interface *create_mock_interface(void) {
    struct interface *iface = calloc(1, sizeof(struct interface));
    if (!iface) return NULL;
    
    // Initialize basic fields
    iface->name = "fuzz_interface";
    iface->ifname = "fuzz0";
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
    struct uci_section *section = calloc(1, sizeof(struct uci_section));
    if (!section) return NULL;
    
    // Initialize basic fields
    section->type = "route";
    section->e.name = "mock_section";
    
    return section;
}

// Create a mock bridge for bridge reload testing
static struct extdev_bridge *create_mock_bridge(void) {
    struct extdev_bridge *bridge = calloc(1, sizeof(struct extdev_bridge));
    if (!bridge) return NULL;
    
    // Initialize basic fields - this is a simplified mock
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
        free(g_mock_section);
        g_mock_section = NULL;
    }
    
    if (g_mock_bridge) {
        free(g_mock_bridge);
        g_mock_bridge = NULL;
    }
}

// Create blob data from fuzz input
static struct blob_attr *create_blob_from_fuzz_data(const uint8_t *data, size_t size) {
    if (size < 4) return NULL;
    
    // Use the fuzz data directly as blob data with some safety checks
    struct blob_attr *attr = (struct blob_attr *)data;
    
    // Basic sanity check on blob header
    if (blob_len(attr) > size - sizeof(struct blob_attr)) {
        return NULL;
    }
    
    return attr;
}

// Fuzz config_parse_route function (branch depth: 246)
static void fuzz_config_parse_route(const uint8_t *data, size_t size) {
    if (!g_mock_section || size == 0) return;
    
    // Alternate between IPv4 and IPv6 routes based on data
    bool v6 = (data[0] % 2) == 1;
    
    // Call the target function - this will parse route configuration
    config_parse_route(g_mock_section, v6);
}

// Fuzz proto_shell_parse_route_list function (branch depth: 247)
static void fuzz_proto_shell_parse_route_list(const uint8_t *data, size_t size) {
    if (!g_mock_iface) return;
    
    struct blob_attr *attr = create_blob_from_fuzz_data(data, size);
    if (!attr) return;
    
    // Alternate between IPv4 and IPv6 routes based on data
    bool v6 = (data[0] % 2) == 1;
    
    // Call the target function
    proto_shell_parse_route_list(g_mock_iface, attr, v6);
}

// Fuzz config_parse_interface function (branch depth: 44)
static void fuzz_config_parse_interface(const uint8_t *data, size_t size) {
    if (!g_mock_section || size == 0) return;
    
    // Alternate between alias and non-alias interfaces
    bool alias = (data[0] % 2) == 1;
    
    // Update section type for interface parsing
    g_mock_section->type = "interface";
    
    // Call the target function
    config_parse_interface(g_mock_section, alias);
}

// Fuzz __bridge_reload function (branch depth: 40)  
static void fuzz_bridge_reload(const uint8_t *data, size_t size) {
    if (!g_mock_bridge) return;
    
    struct blob_attr *attr = create_blob_from_fuzz_data(data, size);
    if (!attr) return;
    
    // Call the target function
    __bridge_reload(g_mock_bridge, attr);
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
    
    return 0;
}

// Cleanup function called at program termination
__attribute__((destructor))
static void fuzz_cleanup(void) {
    cleanup_mock_structures();
}