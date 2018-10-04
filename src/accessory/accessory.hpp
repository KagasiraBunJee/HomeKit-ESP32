#include <iostream>

struct hap_info {
    char *config_number;
    char *accessory_id;
    char *deviceName;
    char *protocol_number;
    char *current_state;
    char *category;
    char *pairState;
};

struct accessory_info {
    char accessory_id[32];
    char *deviceName;
    struct hap_info hap;
};

struct accessory {
    struct accessory_info info;
};

class esp_accessory {
    struct accessory accessory_object;
    public:
        esp_accessory();
        ~esp_accessory();
        void hap_init();
    private:
        void init_mdns();
};