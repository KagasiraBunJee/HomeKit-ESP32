#include <Arduino.h>
#include <WiFi.h>
// #include "wolfssl/wolfcrypt/srp.h"

// #include <Crypto.h>
#include <os.h>
#include "utils/srp.h"
#include "utils/tlv.h"
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

#define SRP_SALT_LENGTH 16

#include "stdio.h"

const int WIFI_CONNECTED_BIT = BIT0;
static EventGroupHandle_t wifi_event_group;
void *bindb;
srp_context_t serverSrp;

void mdns_setup()
{

    esp_err_t status = mdns_init();
    // delay(2000);
    if (status)
    {
        Serial.println("Error mdns_init");
    }
    else
    {
        Serial.println("mdns_init ok...");
    }

    status = mdns_hostname_set("led.local");
    // delay(1000);
    if (status)
    {
        Serial.println("Error mdns_hostname_set");
    }
    else
    {
        Serial.println("mdns_hostname_set ok...");
    }
    // delay(1000);
    status = mdns_instance_name_set(DEVICE_NAME);
    if (status)
    {
        Serial.println("Error mdns_instance_name_set");
    }
    else
    {
        Serial.println("mdns_instance_name_set ok...");
    }

    // delay(1000);
    status = mdns_service_add(DEVICE_NAME, HAP_SERVICE, HAP_PROTO, 14000, NULL, 0);
    if (status)
    {
        Serial.println("Error mdns_service_add");
    }
    else
    {
        Serial.println("mdns_service_add ok...");
    }

    uint8_t mac[6];
    esp_wifi_get_mac(ESP_IF_WIFI_STA, mac);
    char accessory_id[32] = {
        0,
    };
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
        {(char *)"c#", (char *)"1.0"},
        {(char *)"ff", (char *)"0"},
        {(char *)"pv", (char *)"1.0"},
        {(char *)"id", (char *)accessory_id},
        {(char *)"md", (char *)DEVICE_NAME},
        {(char *)"s#", (char *)"1"},
        {(char *)"sf", (char *)pairState},
        {(char *)"ci", (char *)category},
    };
    // delay(1000);
    status = mdns_service_txt_set(HAP_SERVICE, HAP_PROTO, hap_service_txt, 8);
    if (status)
    {
        Serial.println("Error mdns_service_txt_set");
    }
    else
    {
        Serial.println("mdns_service_txt_set ok...");
    }
}

void wifi_setup() {
    delay(1000);
    Serial.println("Connecting to network");

    WiFi.begin(WIFI_SSID, WIFI_PASS);
    while (WiFi.status() != WL_CONNECTED)
    {
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

static int _setup_m2(struct pair_setup *ps,
                     uint8_t *device_msg, int device_msg_length,
                     uint8_t** acc_msg, int* acc_msg_length)
{

    unsigned char seed[32], publicKey[32], privateKey[64], signature[64];
    size_t acc_msg_size = 0;
    ed25519_create_keypair(publicKey, privateKey, seed);

    const unsigned char message[] = "Hello, world!";
    const int message_len = strlen((char *)message);
    ed25519_sign(signature, message, message_len, publicKey, privateKey);

    if (ed25519_verify(signature, message, message_len, publicKey))
    {
        Serial.println("valid signature");
    }
    else
    {
        Serial.println("invalid signature");
    }

    Serial.println("init SRP");
    srp_init(NULL, 0);
    // mbedtls_mpi *salt;
    Serial.println("srp_set_username");
    serverSrp = srp_new_server(SRP_TYPE_3072, SRP_CRYPTO_HASH_ALGORITHM_SHA512);
    srp_set_username(serverSrp, "Pair-Setup");

    Serial.println("srp_set_auth_password");
    // srp_set_params(serverSrp, NULL, NULL, salt);
    const unsigned char *t = reinterpret_cast<const unsigned char *>(LIGHTS_CODE);
    srp_set_auth_password(serverSrp, t, strlen(LIGHTS_CODE));
    // srp_set_params(serverSrp, NULL, NULL, tlv_salt);

    Serial.println("srp_gen_pub");
    srp_gen_pub(serverSrp);

    Serial.println("srp_get_public_key");
    mbedtls_mpi *public_k = srp_get_public_key(serverSrp);
    mbedtls_mpi *salt = srp_get_salt(serverSrp);

    int bodySize = 0;

    uint8_t state[] = {0x02};
    bodySize += tlv_encode_length(sizeof(state));
    bodySize += tlv_encode_length(SRP_PUBLIC_KEY_LENGTH);
    bodySize += tlv_encode_length(SRP_SALT_LENGTH);
    Serial.print(public_k->n);
    Serial.print("-");
    Serial.print(SRP_PUBLIC_KEY_LENGTH);
    Serial.println("");
    Serial.print(salt->n);
    Serial.print("-");
    Serial.print(SRP_SALT_LENGTH);
    Serial.println("");
    
    Serial.println("malloc acc_msg");
    *acc_msg = (uint8_t *)(malloc(bodySize));
    Serial.println("malloc acc_msg success");
    
    uint8_t* tlv_encode_ptr = *acc_msg;

    tlv_encode_ptr += tlv_encode(HAP_TLV_TYPE_SALT, SRP_SALT_LENGTH, (uint8_t *)(salt->p), *acc_msg);
    Serial.println("tlv_encode HAP_TLV_TYPE_SALT success");
    tlv_encode_ptr += tlv_encode(HAP_TLV_TYPE_PUBLICKEY, public_k->n, (uint8_t *)public_k->p, *acc_msg);
    Serial.println("tlv_encode HAP_TLV_TYPE_PUBLICKEY success");
    tlv_encode_ptr += tlv_encode(HAP_TLV_TYPE_STATE, sizeof(state), state, *acc_msg);
    Serial.println("tlv_encode HAP_TLV_TYPE_STATE success");

    *acc_msg_length = bodySize;
    
    return 0;
}

int pair_setup_do(void* _ps, char* req_body, int req_body_len, char** res_body, int* res_body_len) {

    return _setup_m2(NULL, (uint8_t*)req_body, req_body_len, (uint8_t**)res_body, res_body_len);
}

static void _msg_recv(void *connection, struct mg_connection *nc, char *msg, int len)
{
    Serial.println(heap_caps_get_free_size(MALLOC_CAP_DEFAULT));
    Serial.println("_msg_recv");

    struct http_message shm, *hm = &shm;
    char *http_raw_msg = msg;
    int http_raw_msg_len = len;
    mg_parse_http(http_raw_msg, http_raw_msg_len, hm, 1);

    char addr[32];
    mg_sock_addr_to_str(&nc->sa, addr, sizeof(addr),
                        MG_SOCK_STRINGIFY_IP | MG_SOCK_STRINGIFY_PORT);

    printf("HTTP request from %s: %.*s %.*s %.*s", addr, (int)hm->method.len,
           hm->method.p, (int)hm->uri.len, hm->uri.p, (int)hm->body.len, hm->body.p);

    if (strncmp(hm->uri.p, "/pair-setup", strlen("/pair-setup")) == 0)
    {
        Serial.println("want to pair");
        struct tlv *state_tlv = tlv_decode((uint8_t *)hm->body.p, hm->body.len,
                                           HAP_TLV_TYPE_STATE);
        if (state_tlv == NULL)
        {
            printf("tlv_decode failed. type:%d\n", HAP_TLV_TYPE_STATE);
        }

        uint8_t state = ((uint8_t *)&state_tlv->value)[0];
        switch (state)
        {
        case 0x01:
        {
            Serial.println("0x01");

            // srp_init(seed, sizeof(seed));

            char *res_header = NULL;
            int res_header_len = 0;

            char *res_body = NULL;
            int body_len = 0;
            
            char *req_body = strdup(hm->body.p);
            
            if (pair_setup_do(NULL, req_body, (int)hm->body.len, &res_body, &body_len)) {
                Serial.println("test fail");
            }
            if (res_body == NULL) {
                Serial.println("ERROR");
            }
            Serial.println("tlv_decode");
            struct tlv *new_state_tlv = tlv_decode((uint8_t*)res_body, body_len, HAP_TLV_TYPE_STATE);
            Serial.println("tlv_decode success");
            uint8_t new_state = ((uint8_t *)&new_state_tlv->value)[0];
            Serial.println("tlv_decode success get raw state");
            if (new_state == 0x02) {
                Serial.println("success");
            }

            char *signedBody = reinterpret_cast<char*>(res_body);
            printf(signedBody);
            static const char *header_fmt =
                "HTTP/1.1 200 OK\r\n"
                "Content-Length: %d\r\n"
                "Content-Type: application/pairing+tlv8\r\n"
                "\r\n";
            
            
            res_header = (char *)malloc(strlen(header_fmt));
            sprintf(res_header, header_fmt, body_len);
            res_header_len = sizeof(res_header);
            Serial.println("send to ios");
            if (res_header) {
                mg_send(nc, "1234", 4);
            }
            
            // if (res_body) {
            //     mg_send(nc, res_body, body_len);
            // }

            // error = _setup_m2(ps, (uint8_t*)req_body, req_body_len, (uint8_t**)res_body, res_body_len);
            break;
        }
        // case 0x03:
        //     Serial.println("0x03");
        //     // error = _setup_m4(ps, (uint8_t*)req_body, req_body_len, (uint8_t**)res_body, res_body_len);
        //     break;
        // case 0x05:
        //     Serial.println("0x05");
        //     // error = _setup_m6(ps, (uint8_t*)req_body, req_body_len, (uint8_t**)res_body, res_body_len);
        //     break;
        default:
            printf("[PAIR-SETUP][ERR] Invalid state number. %d\n", state);
            break;
        }

        // tlv_decoded_item_free(state_tlv);
    }

    
    // struct hap_connection* hc = connection;

    // if (hc->pair_verified) {
    //     _encrypted_msg_recv(connection, nc, msg, len);
    // }
    // else {
    //     _plain_msg_recv(connection, nc, msg, len);
    // }
}

static void _hap_connection_close(void *connection, struct mg_connection *nc)
{
    Serial.println("_hap_connection_close");
    srp_free(serverSrp);
}

static void _hap_connection_accept(void *accessory, struct mg_connection *nc)
{
    Serial.println("_hap_connection_accept");
}

void setup()
{
    wifi_event_group = xEventGroupCreate();
    
    Serial.begin(115200);
    delay(1000);

    wifi_setup();
    mdns_setup();

    delay(10000);
    xEventGroupSetBits(wifi_event_group, WIFI_CONNECTED_BIT);
    {
        Serial.println("httpd_init");
        struct httpd_ops httpd_ops = {
            .accept = _hap_connection_accept,
            .close = _hap_connection_close,
            .recv = _msg_recv,
        };
        httpd_init(&httpd_ops);

        bindb = httpd_bind(PORT, NULL);
    }

    // httpd_setup();
    // delay(1000);
    // httpd_b();

    // printf(reinterpret_cast<char*>(seed));
    // Serial.println(reinterpret_cast<char*>(seed));
    // ed25519_create_seed((unsigned char*)seed);
}

void loop()
{

    // WiFiClient client = server.available();
    // if (!client) {
    //     return;
    // }

    // Serial.println("New Client");
    // Serial.println(client.readString());

    // delay(1000);
}