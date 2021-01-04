/*
    This sketch establishes a TCP connection to a "quote of the day" service.
    It sends a "hello" message, and then prints received data.
*/

#include <ESP8266WiFi.h>

#define DEBUG_ESP_SSL 1
#define DEBUG_ESP_PORT Serial
#include <WiFiClientSecureBearSSL.h>

#ifndef STASSID
#define STASSID "JOY_2G"
#define STAPSK  "0856868216"
#endif

const char* ssid     = STASSID;
const char* password = STAPSK;

const char* host = "192.168.250.2";
const uint16_t port = 443;

// The server's public certificate which must be shared
const char server_cert[] PROGMEM = R"EOF(
-----BEGIN CERTIFICATE-----
MIIDdzCCAl+gAwIBAgIIAyATuaOg2XwwDQYJKoZIhvcNAQELBQAwMzELMAkGA1UE
BhMCVEgxDDAKBgNVBAgMA1NSVDEWMBQGA1UEAwwNMTkyLjE2OC4yNTAuMjAeFw0y
MDEyMzAxNzUzNThaFw0zMDEyMjgxNzUzNThaMDMxCzAJBgNVBAYTAlRIMQwwCgYD
VQQIDANTUlQxFjAUBgNVBAMMDTE5Mi4xNjguMjUwLjIwggEiMA0GCSqGSIb3DQEB
AQUAA4IBDwAwggEKAoIBAQChh1bYPdkRLD5buGba06A/SrugV2v0Npkvkn2JH09y
Z8Xm+q0MCUu/s4bdKXzPq9inQ7wUfhgil4JCDwptVZlapjXpDXTsIfaJLpOPpZOD
r/pnPU0PnXUCEXhlSSt8F3KPldJAm1eWEx4pIsVgy/GhHOsz19Xer35hsOqy0NJo
yPErq0ACJSvrfYtowtIwk6WfYYAF+2oBAGnpWFvnqCEZHp5aJ8EePRf3SppzHKGd
SVwvGazCQywtUI9ZRRif5Z/9lOJ6ScpK/zLs0kYI8Gk13jf+h7DnQ4Yd/xcWsTJA
nYdOtkw7rDOgM+dsRVX8lZLDmExveYCwDY9xZz1XLQRNAgMBAAGjgY4wgYswDgYD
VR0PAQH/BAQDAgWgMBMGA1UdJQQMMAoGCCsGAQUFBwMBMB0GA1UdDgQWBBROQHB0
iNKH8x144hMOxZhaD48/kTAfBgNVHSMEGDAWgBTNd1IxwaKrG27aPn37FzlSWxQC
ZjAkBglghkgBhvhCAQ0EFxYVR2VuZXJhdGVkIGJ5IFJvdXRlck9TMA0GCSqGSIb3
DQEBCwUAA4IBAQBE8em3UD/NOynPhFkG48VRAmQPrXzTV2mmklr1WBPtDSEwNFIU
zuuXMfVJW6cXEYjjkq6ortNh3PqSZpkpj7QX7fdDWEXif6/MOK3htX5ePqs4kbb+
sUB5fU4S6awc2JiSnA/yCBaWs+RxeRARSGsByjHWjz8z8etrmWaaHkjJui5QgpCB
GTvVgVazsTNBlqaRptm7yULIvA4NVmwIJpho9lAFuLWTMBLVWaDEba0cx3GZlqET
pzw0XMBpXHAzONiUT76rQrBcFEpcr6nEPIthgQH36chGN2IeTN0auHv5xG0UiV1/
mRTIg/7TJNOqAwppwxXBJi6vk2ssaDtiOkG3
-----END CERTIFICATE-----
)EOF";


std::unique_ptr<BearSSL::WiFiClientSecure>client(new BearSSL::WiFiClientSecure);
//const unsigned char SSTP_guid[16] = {0x3b, 0x5a, 0x47, 0x27, 0x63, 0x90, 0x43, 0xab, 0x99, 0x26, 0x97, 0xba, 0x33, 0xe5, 0x79, 0x9e};
const char *SSTP_guid = "3b5a4727-6390-43ab-9926-97ba33e5799e";

BearSSL::PublicKey serverCert(server_cert);

void setup() {
  Serial.begin(115200);

  // We start by connecting to a WiFi network

  Serial.println();
  Serial.println();
  Serial.print("Connecting to ");
  Serial.println(ssid);

  /* Explicitly set the ESP8266 to be a WiFi-client, otherwise, it by default,
     would try to act as both a client and an access-point and could cause
     network-issues with your other WiFi-devices on your WiFi-network. */
  WiFi.mode(WIFI_STA);
  WiFi.begin(ssid, password);

  while (WiFi.status() != WL_CONNECTED) {
    delay(500);
    Serial.print(".");
  }

  Serial.println("");
  Serial.println("WiFi connected");
  Serial.println("IP address: ");
  Serial.println(WiFi.localIP());

  DEBUG_ESP_PORT.printf("Hello From debug\n");
  //client->setInsecure();

  BearSSL::X509List *serverCertList = new BearSSL::X509List(server_cert);
  client->setTrustAnchors(serverCertList);

  const br_x509_certificate *x509Cert = serverCertList->getX509Certs();
  Serial.printf("Cert Length: %d\n", x509Cert->data_len);

  HashSHA256 sha256;
  sha256.begin();
  sha256.add(x509Cert->data, x509Cert->data_len);
  sha256.end();
  
  Serial.printf("SHA256 Length: %d\n", sha256.len());
  uint8_t *dt = (uint8_t*)sha256.hash();
  for (int i=0;i< sha256.len(); i++) {
    Serial.printf("%02X ", dt[i]);
  }
  Serial.println("\n++++++++++++++++");
}

bool SSTP_SendInit() {
  //char buf[200];
  String buf;
  char *p;
  char resp[200];
  
  //for avoiding internal reallocations
  buf.reserve(250);

  buf += "SSTP_DUPLEX_POST /sra_{BA195980-CD49-458b-9E23-C84EE0ADCD75}/ HTTP/1.1\r\n";
  buf += "SSTPCORRELATIONID: {" + String(SSTP_guid) + "}\r\n";
  buf += "Content-Length: 18446744073709551615\r\n";
  buf += "Host: " + String(host) + "\r\n";
  buf += "\r\n";

  p = (char*)buf.c_str();
  client->write((const uint8_t*)p, strlen(p));

  // wait for data to be available
  unsigned long timeout = millis();
  while (client->available() < 100) {
    if (millis() - timeout > 5000) {
      Serial.println("SSTP_SendInit >>> Client Timeout !");
      return false;
    }
  }

  int len = client->read((uint8_t*)resp, 200);
  resp[len] = '\0';
  Serial.print("SSTP_SendInit >>> Response Len: ");
  Serial.println(len);
  Serial.println(resp);
  Serial.println("============================");

  if (strlen(resp) > len) {
    Serial.println("SSTP_SendInit >>> Fail, strlen(resp) > len");
    return false;
  }

  char *pHttpCode;
  const char *httpCodeStart = "HTTP/1.1 ";
  pHttpCode = strstr(resp, httpCodeStart);
  if (pHttpCode == NULL) {
    Serial.println("SSTP_SendInit >>> Fail, \"HTTP/1.1 \" word not found");
    return false;
  }

  pHttpCode += strlen(httpCodeStart);
  int httpCode = atoi(pHttpCode);
  Serial.print("SSTP_SendInit >>> Response HTTP Code: ");
  Serial.println(httpCode);

  if (httpCode != 200) {
    Serial.print("SSTP_SendInit >>> Fail, HTTP Response code: ");
    Serial.print(httpCode);
    Serial.print(" != 200");
    return false;
  }

  Serial.println("SSTP_SendInit >>> 200 OK");
  return true;
}

char err_str[100];
void loop() {
  Serial.print("connecting to ");
  Serial.print(host);
  Serial.print(':');
  Serial.println(port);

  // Use WiFiClient class to create TCP connections
  //WiFiClient client;
  //std::unique_ptr<BearSSL::WiFiClientSecure>client(new BearSSL::WiFiClientSecure);
  //client->setFingerprint(fingerprint);
  //client->setInsecure();
    
  if (!client->connect(host, port)) {
    client->getLastSSLError(err_str, 100);
    Serial.println("connection failed");
    Serial.println(err_str);
    delay(5000);
    return;
  }

  Serial.println("Send SSTP_DUPLEX_POST");
  bool ret = SSTP_SendInit();
  Serial.print("SSTP_DUPLEX_POST Result: ");
  Serial.println(ret);

  /*
  // This will send a string to the server
  Serial.println("sending data to server");
  if (client->connected()) {
    client->println("hello from ESP8266");
  }
  */

  // Close the connection
  Serial.println();
  Serial.println("closing connection");
  client->stop();

  while(1) {
    delay(100);
  }
/*
  // wait for data to be available
  unsigned long timeout = millis();
  while (client->available() == 0) {
    if (millis() - timeout > 5000) {
      Serial.println(">>> Client Timeout !");
      client->stop();
      delay(60000);
      return;
    }
  }

  // Read all the lines of the reply from server and print them to Serial
  Serial.println("receiving from remote server");
  // not testing 'client.connected()' since we do not need to send data here
  while (client->available()) {
    char ch = static_cast<char>(client->read());
    Serial.print(ch);
  }

  // Close the connection
  Serial.println();
  Serial.println("closing connection");
  client->stop();

  delay(300000); // execute once every 5 minutes, don't flood remote service

  */
}
