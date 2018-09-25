#include <Arduino.h>
// #include "hap.h"
#include <WiFi.h>
#include "mdns.h"

#define WIFI_SSID "Historic"
#define WIFI_PASS "Cedk49bV48"
#define PORT 14000

WiFiServer server(80);

void wifi_setup() {
    Serial.println("Connecting to network");

    delay(1000);
    
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

    Serial.println("start mdns_init");
    esp_err_t status = mdns_init();
    delay(2000);
    if (status) {
        Serial.println("Error mdns_init");
    } else {
        Serial.println("mdns_init ok...");
    }

    Serial.println("start mdns_hostname_set");
    status = mdns_hostname_set("lights.local");
    delay(2000);
    if (status) {
        Serial.println("Error mdns_hostname_set");
    } else {
        Serial.println("mdns_hostname_set ok...");
    }
    
}

void setup() {
    Serial.begin(115200);
    wifi_setup();
    mdns_setup();
}

void loop() {
    
}