#include <Arduino.h>
// #include "hap.h"
#include <WiFi.h>
#include "mdns.h"
#include "esp_wifi.h"
//this include is in gitignore, store security credentials there
#include "access/access.h"

#define PORT 14000

//SERVICE
#define HAP_SERVICE "_hap"
#define HAP_PROTO "_tcp"
#define DEVICE_NAME "RGB Light"

WiFiServer server(80);

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

void mdns_setup() {

    esp_err_t status = mdns_init();
    delay(2000);
    if (status) {
        Serial.println("Error mdns_init");
    } else {
        Serial.println("mdns_init ok...");
    }

    status = mdns_hostname_set("lights.local");
    delay(2000);
    if (status) {
        Serial.println("Error mdns_hostname_set");
    } else {
        Serial.println("mdns_hostname_set ok...");
    }
    
    status = mdns_instance_name_set(DEVICE_NAME);
    if (status) {
        Serial.println("Error mdns_instance_name_set");
    } else {
        Serial.println("mdns_instance_name_set ok...");
    }


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
    sprintf(category, "%d", 1);
    
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
    
    status = mdns_service_txt_set(HAP_SERVICE, HAP_PROTO, hap_service_txt, 8);
    if (status) {
        Serial.println("Error mdns_service_txt_set");
    } else {
        Serial.println("mdns_service_txt_set ok...");
    }
    
}

void setup() {
    Serial.begin(9600);
    wifi_setup();
    mdns_setup();
}

void loop() {
    
}