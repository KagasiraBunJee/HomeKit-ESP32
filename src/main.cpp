#include <os.h>
#include "esp_wifi.h"

#include <Arduino.h>
#include <WiFi.h>


#include "utils/srp.h"
#include "utils/tlv.h"
#include "mdns.h"

//this include is in gitignore, store security credentials there
#include "access/access.h"
#include "hap/hap_defines.h"

#define PORT 811
#define DEVICE_NAME "RGBLight"
#define HAP_SERVICE "_hap"
#define HAP_PROTO "_tcp"

srp_context_t serverSrp;

void mdns_setup()
{

    esp_err_t status = mdns_init();
    
    if (status) {
        Serial.println("Error mdns_init");
    }
    else {
        Serial.println("mdns_init ok...");
    }

    status = mdns_hostname_set("led");
    
    if (status) {
        Serial.println("Error mdns_hostname_set");
    }
    else {
        Serial.println("mdns_hostname_set ok...");
    }
    
    status = mdns_instance_name_set(DEVICE_NAME);
    if (status) {
        Serial.println("Error mdns_instance_name_set");
    }
    else {
        Serial.println("mdns_instance_name_set ok...");
    }

    status = mdns_service_add(DEVICE_NAME, HAP_SERVICE, HAP_PROTO, PORT, NULL, 0);
    if (status) {
        Serial.println("Error mdns_service_add");
    }
    else {
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
        {(char *)"c#", (char *)"1.0"},
        {(char *)"ff", (char *)"0"},
        {(char *)"pv", (char *)"1.0"},
        {(char *)"id", (char *)accessory_id},
        {(char *)"md", (char *)DEVICE_NAME},
        {(char *)"s#", (char *)"1"},
        {(char *)"sf", (char *)pairState},
        {(char *)"ci", (char *)category},
    };
    
    status = mdns_service_txt_set(HAP_SERVICE, HAP_PROTO, hap_service_txt, 8);
    if (status) {
        Serial.println("Error mdns_service_txt_set");
    } else {
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

void create_srp() {
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
}

void setup() {
    Serial.begin(115200);
    delay(1000);

    wifi_setup();
    mdns_setup();
    create_srp();

}

void loop() {

}