#include <Arduino.h>
#include <WiFi.h>

// #include <Crypto.h>
#include "mdns.h"
#include "esp_wifi.h"
//this include is in gitignore, store security credentials there
#include "access/access.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "hap/hap_defines.h"
// #include "Ed25519.h"
// #include "utils/mongoose.h"
#include "utils/httpd.h"
#include "security/ed25519/src/ed25519.h"
// #include "hap/src/hap.h"

#define PORT 14000

//SERVICE
#define HAP_SERVICE "_hap"
#define HAP_PROTO "_tcp"
#define DEVICE_NAME "RGB Light"

#include "stdio.h"

const int WIFI_CONNECTED_BIT = BIT0;
void *bindb;

WiFiServer server(PORT);

void mdns_setup() {

    esp_err_t status = mdns_init();
    // delay(2000);
    if (status) {
        Serial.println("Error mdns_init");
    } else {
        Serial.println("mdns_init ok...");
    }

    status = mdns_hostname_set("led.local");
    // delay(1000);
    if (status) {
        Serial.println("Error mdns_hostname_set");
    } else {
        Serial.println("mdns_hostname_set ok...");
    }
    // delay(1000);
    status = mdns_instance_name_set(DEVICE_NAME);
    if (status) {
        Serial.println("Error mdns_instance_name_set");
    } else {
        Serial.println("mdns_instance_name_set ok...");
    }

    // delay(1000);
    status = mdns_service_add(DEVICE_NAME, HAP_SERVICE, HAP_PROTO, 14000, NULL, 0);
    if (status) {
        Serial.println("Error mdns_service_add");
    } else {
        Serial.println("mdns_service_add ok...");
    }
    
    uint8_t mac[6];
    esp_wifi_get_mac(ESP_IF_WIFI_STA, mac);
    char accessory_id[32] = {0,};
    sprintf(accessory_id, "%02X:%02X:%02X:%02X:%02X:%02X", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    Serial.print("Accessory ID: ");
    Serial.print(accessory_id);
    Serial.println("");

    char pairState[4];
    char category[4];
    memset(pairState, 0, sizeof(pairState));
    sprintf(pairState, "%d", 1);
    memset(category, 0, sizeof(category));
    sprintf(category, "%d", HAP_ACCESSORY_CATEGORY_LIGHTBULB);
    
    mdns_txt_item_t hap_service_txt[8] = {
        {(char*)"c#", (char*)"1.0"},
        {(char*)"ff", (char*)"0"},
        {(char*)"pv", (char*)"1.0"},
        {(char*)"id", (char*)accessory_id},
        {(char*)"md", (char*)DEVICE_NAME},
        {(char*)"s#", (char*)"1"},
        {(char*)"sf", (char*)pairState},
        {(char*)"ci", (char*)category},
    };
    // delay(1000);
    status = mdns_service_txt_set(HAP_SERVICE, HAP_PROTO, hap_service_txt, 8);
    if (status) {
        Serial.println("Error mdns_service_txt_set");
    } else {
        Serial.println("mdns_service_txt_set ok...");
    }
    
    
}

static esp_err_t event_handler(void *ctx, system_event_t *event) {
    switch (event->event_id) {
        case SYSTEM_EVENT_STA_START:
            Serial.println("Conneting...");
            esp_wifi_connect();
            break;
        case SYSTEM_EVENT_STA_DISCONNECTED:
            Serial.println("Disconnected");
            esp_wifi_connect();
            break;
        case SYSTEM_EVENT_STA_CONNECTED:
            Serial.println("SYSTEM_EVENT_STA_CONNECTED");
            break;
        case SYSTEM_EVENT_STA_GOT_IP:
            Serial.println("");
            Serial.print("Connected to ");
            Serial.print(WIFI_SSID);
            Serial.print(" with IPv4: ");
            Serial.print(ip4addr_ntoa(&event->event_info.got_ip.ip_info.ip));
            Serial.print(" with IPv6: ");
            Serial.print(ip6addr_ntoa(&event->event_info.got_ip6.ip6_info.ip));
            Serial.println("");
            break;
        default:
            break;

    }
    mdns_handle_system_event(ctx, event);
    return ESP_OK;
}

void wifi_sta_setup() {

    tcpip_adapter_init();
    esp_event_loop_init(event_handler, NULL);
    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    esp_wifi_init(&cfg);
    wifi_config_t wifi_config;

    memset(&wifi_config, 0, sizeof(wifi_config_t));
    strcpy(reinterpret_cast<char*>(wifi_config.sta.ssid), WIFI_SSID);
    strcpy(reinterpret_cast<char*>(wifi_config.sta.password), WIFI_PASS);

    esp_wifi_set_mode(WIFI_MODE_STA);
    esp_wifi_set_config(ESP_IF_WIFI_STA, &wifi_config);
    esp_wifi_start();
}

void wifi_setup() {
    
    delay(1000);
    Serial.println("Connecting to network");
    
    WiFi.begin(WIFI_SSID, WIFI_PASS);
    while (WiFi.status() != WL_CONNECTED) {
        Serial.print(".");
        delay(100);
    }
    WiFi.enableIpV6();
    delay(2000);
    Serial.println("");
    Serial.print("Connected to ");
    Serial.print(WIFI_SSID);
    Serial.print(" with IPv4: ");
    Serial.print(WiFi.localIP());
    Serial.print(" with IPv6: ");
    Serial.print(WiFi.localIPv6());
    Serial.println("");
}

static void _msg_recv(void* connection, struct mg_connection* nc, char* msg, int len)
{
    Serial.println("_msg_recv");

    struct http_message shm, *hm = &shm;
    char* http_raw_msg = msg;
    int http_raw_msg_len = len;
    mg_parse_http(http_raw_msg, http_raw_msg_len, hm, 1);

    char addr[32];
    mg_sock_addr_to_str(&nc->sa, addr, sizeof(addr),
            MG_SOCK_STRINGIFY_IP | MG_SOCK_STRINGIFY_PORT);
    
    printf("HTTP request from %s: %.*s %.*s %.*s", addr, (int) hm->method.len,
            hm->method.p, (int) hm->uri.len, hm->uri.p, (int)hm->message.len, hm->message.p);

    if (strncmp(hm->uri.p, "/pair-setup", strlen("/pair-setup")) == 0) {
        Serial.println("want to pair");
    }
    // struct hap_connection* hc = connection;

    // if (hc->pair_verified) {
    //     _encrypted_msg_recv(connection, nc, msg, len);
    // }
    // else {
    //     _plain_msg_recv(connection, nc, msg, len);
    // }
}

static void _hap_connection_close(void* connection, struct mg_connection* nc)
{
    Serial.println("_hap_connection_close");
    // struct hap_connection* hc = connection;


    // if (hc->pair_setup)
    //     pair_setup_cleanup(hc->pair_setup);

    // if (hc->pair_verify)
    //     pair_verify_cleanup(hc->pair_setup);

    // xSemaphoreTake(_hap_desc->mutex, 0);
    // list_del(&hc->list);
    // xSemaphoreGive(_hap_desc->mutex);

    // free(hc);
}

static void _hap_connection_accept(void* accessory, struct mg_connection* nc)
{
    Serial.println("_hap_connection_accept");
    // struct hap_accessory* a = accessory;
    // struct hap_connection* hc = calloc(1, sizeof(struct hap_connection));

    // hc->nc = nc;
    // hc->a = a;
    // hc->pair_verified = false;


    // //INIT_LIST_HEAD(&hc->event_head);
    // nc->user_data = hc;

    // xSemaphoreTake(_hap_desc->mutex, 0);
    // list_add(&hc->list, &a->connections);
    // xSemaphoreGive(_hap_desc->mutex);
}

void setup() {
    Serial.begin(115200);
    delay(1000);

    wifi_setup();
    mdns_setup();

    delay(10000);
    Serial.println("httpd_init");
    struct httpd_ops httpd_ops = {
        .accept = _hap_connection_accept,
        .close = _hap_connection_close,
        .recv = _msg_recv,
    };
    httpd_init(&httpd_ops);

    bindb = httpd_bind(PORT, NULL);
    // httpd_setup();
    // delay(1000);
    // httpd_b();
    const char* preSeed = "3ed4f50fd9a9c2182bb814a7b084fbd824adf1019ac353020842c64e14a7ce59";
    int len = sizeof(preSeed);
    char seed[32];
    // strcpy(seed, preSeed);
    ed25519_create_seed((unsigned char*)seed);
    Serial.println(seed);
    // ed25519_create_seed((unsigned char*)seed);
}

void loop() {
    
    // WiFiClient client = server.available();
    // if (!client) {
    //     return;
    // }

    // Serial.println("New Client");
    // Serial.println(client.readString());

    // delay(1000);
}