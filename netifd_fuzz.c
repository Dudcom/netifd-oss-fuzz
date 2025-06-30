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
#include "netifd.h"
#include "interface.h"
#include "interface-ip.h"
#include "proto.h"
#include "config.h"
#include "device.h"
#include "system.h"
#include "extdev.h"
#include <uci.h>
#include <libubox/blobmsg.h>
#include <libubox/blobmsg_json.h>
#include <libubox/blob.h>

extern int blobmsg_add_u8(struct blob_buf *buf, const char *name, uint8_t val);
extern int blobmsg_add_u32(struct blob_buf *buf, const char *name, uint32_t val);
extern int blobmsg_add_string(struct blob_buf *buf, const char *name, const char *str);
extern void *blobmsg_open_array(struct blob_buf *buf, const char *name);
extern void blobmsg_close_array(struct blob_buf *buf, void *cookie);
extern void *blob_data(const struct blob_attr *attr);

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

extern void config_parse_route(struct uci_section *s, bool v6);
extern void interface_ip_add_route(struct interface *iface, struct blob_attr *attr, bool v6);
extern void iprule_add(struct blob_attr *attr, bool v6);
extern void config_parse_interface(struct uci_section *s, bool alias);
extern enum dev_change_type __bridge_reload(struct extdev_bridge *ebr, struct blob_attr *config);

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

static struct interface *g_mock_iface = NULL;
static struct uci_section *g_mock_section = NULL;
static struct extdev_bridge *g_mock_bridge = NULL;

static bool g_fuzzing_mode = false;

static void init_netifd_for_fuzzing(void) {
    static bool initialized = false;
    if (initialized) return;
    
    g_fuzzing_mode = true;
    
    extern int netifd_ubus_init(const char *path);
    netifd_ubus_init("/tmp/dummy_ubus_socket");
    
    extern struct ubus_context *ubus_ctx;
    if (!ubus_ctx) {
        ubus_ctx = calloc(1, sizeof(struct ubus_context));
        if (ubus_ctx) {
            ubus_ctx->sock.fd = -1;
            ubus_ctx->local_id = 0xffffffff;
            
            INIT_LIST_HEAD(&ubus_ctx->pending);
            INIT_LIST_HEAD(&ubus_ctx->requests);
        }
    }

    extern void bonding_device_type_init(void);
    bonding_device_type_init();
    
    initialized = true;
}

static struct interface *create_mock_interface(void) {
    struct interface *iface = calloc(1, sizeof(struct interface));
    if (!iface) return NULL;
    
    iface->name = "fuzz_interface";
    iface->state = IFS_DOWN;
    iface->config_state = IFC_NORMAL;
    iface->enabled = true;
    iface->autostart = true;
    
    INIT_LIST_HEAD(&iface->errors);
    INIT_LIST_HEAD(&iface->users);
    INIT_LIST_HEAD(&iface->assignment_classes);
    
    memset(&iface->config_ip, 0, sizeof(iface->config_ip));
    memset(&iface->proto_ip, 0, sizeof(iface->proto_ip));
    
    vlist_init(&iface->proto_ip.addr, avl_strcmp, NULL);
    vlist_init(&iface->proto_ip.route, avl_strcmp, NULL);
    vlist_init(&iface->proto_ip.prefix, avl_strcmp, NULL);
    
    return iface;
}

static struct uci_section *create_mock_uci_section(void) {
    static struct uci_context *mock_ctx = NULL;
    static struct uci_package *mock_pkg = NULL;
    
    if (!mock_ctx) {
        mock_ctx = calloc(1, sizeof(struct uci_context));
        if (!mock_ctx) return NULL;
        
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
        
        mock_pkg->e.type = 2;
        mock_pkg->e.name = "mock_package";
        mock_pkg->e.list.next = &mock_pkg->e.list;
        mock_pkg->e.list.prev = &mock_pkg->e.list;
        
        mock_pkg->sections.next = &mock_pkg->sections;
        mock_pkg->sections.prev = &mock_pkg->sections;
        
        mock_pkg->delta.next = &mock_pkg->delta;
        mock_pkg->delta.prev = &mock_pkg->delta;
        mock_pkg->saved_delta.next = &mock_pkg->saved_delta;
        mock_pkg->saved_delta.prev = &mock_pkg->saved_delta;
        
        mock_pkg->ctx = mock_ctx;
    }
    
    struct uci_section *section = calloc(1, sizeof(struct uci_section));
    if (!section) return NULL;
    
    section->e.type = 3;
    section->e.name = "mock_section";
    section->e.list.next = &section->e.list;
    section->e.list.prev = &section->e.list;
    
    section->options.next = &section->options;
    section->options.prev = &section->options;
    
    section->type = "interface";
    section->package = mock_pkg;
    section->anonymous = false;
    
    return section;
}

static struct extdev_bridge *create_mock_bridge(void) {
    struct extdev_bridge *bridge = calloc(1, sizeof(struct extdev_bridge));
    if (!bridge) return NULL;
    
    static struct extdev_type mock_extdev_type = {0};
    static struct uci_blob_param_list mock_config_params = {0};
    static struct device_type mock_device_type = {0};
    
    mock_config_params.n_params = 0;
    mock_config_params.params = NULL;
    
    mock_device_type.config_params = &mock_config_params;
    mock_device_type.name = "mock_bridge";
    
    mock_extdev_type.handler = mock_device_type;
    mock_extdev_type.name = "mock_bridge";
    mock_extdev_type.config_params = &mock_config_params;
    mock_extdev_type.subscribed = false;
    
    bridge->edev.dev.type = &mock_device_type;
    strcpy(bridge->edev.dev.ifname, "mock_bridge0");
    bridge->edev.dev.present = false;
    bridge->edev.dev.active = false;
    bridge->edev.dev.config_pending = false;
    bridge->edev.etype = &mock_extdev_type;
    bridge->edev.dep_name = NULL;
    
    bridge->config = NULL;
    bridge->empty = false;
    bridge->ifnames = NULL;
    bridge->active = false;
    bridge->force_active = false;
    bridge->n_present = 0;
    bridge->n_failed = 0;
    
    INIT_SAFE_LIST(&bridge->edev.dev.users);
    vlist_init(&bridge->members, avl_strcmp, NULL);
    
    return bridge;
}

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
        if (g_mock_bridge->config) {
            free(g_mock_bridge->config);
            g_mock_bridge->config = NULL;
        }
        free(g_mock_bridge);
        g_mock_bridge = NULL;
    }
    
    extern struct ubus_context *ubus_ctx;
    if (g_fuzzing_mode && ubus_ctx) {
        if (ubus_ctx->sock.fd == -1) {
            free(ubus_ctx);
            ubus_ctx = NULL;
        } else {
            extern void netifd_ubus_done(void);
            netifd_ubus_done();
        }
    }
}

static struct blob_attr *create_blob_from_fuzz_data(const uint8_t *data, size_t size) {
    static struct blob_buf fuzz_buf;
    void *array_cookie;
    
    if (size == 0) return NULL;
    
    blob_buf_init(&fuzz_buf, 0);
    
    array_cookie = blobmsg_open_array(&fuzz_buf, "routes");
    
    size_t offset = 0;
    int entry_count = 0;
    
    while (offset < size && entry_count < 10) {
        void *table_cookie = blobmsg_open_table(&fuzz_buf, NULL);
        
        if (offset < size) {
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
    
    return blob_data(fuzz_buf.head);
}

static void fuzz_config_parse_route(const uint8_t *data, size_t size) {
    if (!g_mock_section || size == 0) return;

    g_mock_section->type = "route";
    bool v6 = (data[0] % 2) == 1;
    config_parse_route(g_mock_section, v6);
}

static void fuzz_interface_ip_add_route(const uint8_t *data, size_t size) {
    if (!g_mock_iface || size < 8) return;
    
    struct blob_attr *attr = (struct blob_attr *)data;
    bool v6 = (data[0] % 2) == 1;
    
    interface_ip_add_route(g_mock_iface, attr, v6);
}

static void fuzz_iprule_add(const uint8_t *data, size_t size) {
    if (size < 8) return;
    
    struct blob_attr *attr = (struct blob_attr *)data;
    bool v6 = (data[0] % 2) == 1;
    
    iprule_add(attr, v6);
}

static void fuzz_config_parse_interface(const uint8_t *data, size_t size) {
    if (!g_mock_section || size == 0) return;

    bool alias = (data[0] % 2) == 1;
    
    g_mock_section->type = "interface";

    config_parse_interface(g_mock_section, alias);
}

static void fuzz_bridge_reload(const uint8_t *data, size_t size) {
    if (!g_mock_bridge) return;
    
    struct blob_attr *attr = create_blob_from_fuzz_data(data, size);
    if (!attr) return;

    struct blob_attr *old_config = g_mock_bridge->config;

    __bridge_reload(g_mock_bridge, attr);

    if (old_config && old_config != g_mock_bridge->config) {
        free(old_config);
    }
}

static void fuzz_bonding_create(const uint8_t *data, size_t size) {
    if (size < 8) return;
    
    static struct blob_buf bonding_buf;
    blob_buf_init(&bonding_buf, 0);
    
    size_t offset = 0;
    
    if (offset < size) {
        uint8_t policy_idx = data[offset] % 7; // 7 bonding modes available
        const char *policies[] = {
            "balance-rr", "active-backup", "balance-xor", "broadcast",
            "802.3ad", "balance-tlb", "balance-alb"
        };
        blobmsg_add_string(&bonding_buf, "policy", policies[policy_idx]);
        offset++;
    }
    
    if (offset + 1 < size) {
        void *ports_array = blobmsg_open_array(&bonding_buf, "ports");
        
        uint8_t num_ports = 1 + (data[offset] % 4);
        offset++;
        
        for (int i = 0; i < num_ports && offset < size; i++) {
            char port_name[16];
            snprintf(port_name, sizeof(port_name), "eth%d", i);
            blobmsg_add_string(&bonding_buf, NULL, port_name);
        }
        
        blobmsg_close_array(&bonding_buf, ports_array);
    }
    
    if (offset + 4 <= size) {
        uint32_t min_links;
        memcpy(&min_links, data + offset, sizeof(uint32_t));
        blobmsg_add_u32(&bonding_buf, "min_links", min_links % 8);
        offset += 4;
    }
    
    if (offset + 4 <= size) {
        uint32_t monitor_interval;
        memcpy(&monitor_interval, data + offset, sizeof(uint32_t));
        blobmsg_add_u32(&bonding_buf, "monitor_interval", monitor_interval % 1000);
        offset += 4;
    }
    
    if (offset < size) {
        blobmsg_add_u8(&bonding_buf, "all_ports_active", data[offset] & 1);
        offset++;
    }
    
    if (offset < size) {
        blobmsg_add_u8(&bonding_buf, "use_carrier", data[offset] & 1);
        offset++;
    }
    
    if (offset < size) {
        uint8_t hash_policy_idx = data[offset] % 4;
        const char *hash_policies[] = {
            "layer2", "layer2+3", "layer3+4", "encap2+3"
        };
        blobmsg_add_string(&bonding_buf, "xmit_hash_policy", hash_policies[hash_policy_idx]);
        offset++;
    }

    if (offset < size) {
        char primary_port[16];
        snprintf(primary_port, sizeof(primary_port), "eth%d", data[offset] % 4);
        blobmsg_add_string(&bonding_buf, "primary", primary_port);
        offset++;
    }
    
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
    
    if (offset < size && (data[offset] & 1)) {
        blobmsg_add_string(&bonding_buf, "monitor_mode", "arp");
        
        if (offset + 1 < size) {
            void *arp_targets = blobmsg_open_array(&bonding_buf, "arp_target");
            blobmsg_add_string(&bonding_buf, NULL, "192.168.1.1");
            blobmsg_add_string(&bonding_buf, NULL, "192.168.1.254");
            blobmsg_close_array(&bonding_buf, arp_targets);
        }
        
        if (offset + 1 < size) {
            blobmsg_add_u8(&bonding_buf, "arp_all_targets", data[offset + 1] & 1);
        }
        
        offset += 2;
    }
    
    extern struct device_type *device_type_get(const char *name);
    struct device_type *bonding_type = device_type_get("bonding");
    if (!bonding_type) {
        return;
    }
    
    static int bonding_counter = 0;
    char bonding_name[32];
    snprintf(bonding_name, sizeof(bonding_name), "bond%d", bonding_counter++);
    
    extern struct device *device_create(const char *name, struct device_type *type, struct blob_attr *config);
    struct device *bonding_dev = device_create(bonding_name, bonding_type, blob_data(bonding_buf.head));
    
    if (bonding_dev) {
        bonding_dev->current_config = false;
        
        extern void _device_set_present(struct device *dev, bool state);
        _device_set_present(bonding_dev, false);
        
        if (bonding_dev->type && bonding_dev->type->free) {
            bonding_dev->type->free(bonding_dev);
        } else {    
            if (bonding_dev->config) {
                free(bonding_dev->config);
                bonding_dev->config = NULL;
            }
            extern void device_cleanup(struct device *dev);
            device_cleanup(bonding_dev);
        }
    }
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    init_netifd_for_fuzzing();
    
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
    
    if (size < 2) return 0;
    
    uint8_t strategy = data[0] % 6;
    const uint8_t *fuzz_data = data + 1;
    size_t fuzz_size = size - 1;
    
    switch (strategy) {
        case 0:
            fuzz_config_parse_route(fuzz_data, fuzz_size);
            break;
        case 1:
            fuzz_interface_ip_add_route(fuzz_data, fuzz_size);
            break;
        case 2:
            fuzz_iprule_add(fuzz_data, fuzz_size);
            break;
        case 3:
            fuzz_config_parse_interface(fuzz_data, fuzz_size);
            break;
        case 4:
            fuzz_bridge_reload(fuzz_data, fuzz_size);
            break;
        case 5:
            fuzz_bonding_create(fuzz_data, fuzz_size);
            break;
    }

    if (g_mock_bridge && g_mock_bridge->config) {
        free(g_mock_bridge->config);
        g_mock_bridge->config = NULL;
    }
    
    if (g_mock_bridge) {
        g_mock_bridge->ifnames = NULL;
        g_mock_bridge->empty = false;
        g_mock_bridge->active = false;
        g_mock_bridge->force_active = false;
        g_mock_bridge->n_present = 0;
        g_mock_bridge->n_failed = 0;
    }
    
    return 0;
}

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
