#include <IRremote.h>
#include <DHT.h>
#include <math.h>
#include "mbedtls/gcm.h"
#include <WiFi.h>
#include <PubSubClient.h>

// ================== Wi-Fi ==================
const char* ssid = "Ooredoo-4F1105";
const char* password = "to44&$MP";

// ================== MQTT ==================
const char* mqtt_server = "broker.hivemq.com";
const char* mqtt_topic = "capteurs";

WiFiClient espClient;
PubSubClient client(espClient);

// ================== PINS ==================
#define IR_PIN     15
#define KY013_PIN  34
#define DHT_PIN     4
#define DHTTYPE    DHT11

// ================== OBJETS ==================
DHT dht(DHT_PIN, DHTTYPE);

// ================== CLÉ & IV (AEAD) ==================
uint8_t aesKey[16] = {
  0x10,0x11,0x12,0x13,
  0x20,0x21,0x22,0x23,
  0x30,0x31,0x32,0x33,
  0x40,0x41,0x42,0x43
};

uint8_t iv[12] = {
  0x01,0x02,0x03,0x04,
  0x05,0x06,0x07,0x08,
  0x09,0x0A,0x0B,0x0C
};

// ================== AEAD FUNCTION ==================
void encryptAEAD(const char *plaintext, String &cipher_hex, String &tag_hex) {
  mbedtls_gcm_context ctx; ///creer objet aes gcm
  mbedtls_gcm_init(&ctx);//l'initialiser

  uint8_t ciphertext[128];
  uint8_t tag[16];

  mbedtls_gcm_setkey(&ctx, MBEDTLS_CIPHER_ID_AES, aesKey, 128);// charger cle cle:aeskey sur 128 bits

  mbedtls_gcm_crypt_and_tag(
    &ctx,//le chiffreur
    MBEDTLS_GCM_ENCRYPT, // pour dire qu'on va chiffrer
    strlen(plaintext),//taille msg
    iv, sizeof(iv),
    NULL, 0,                 // AAD (optionnel)
    (uint8_t*)plaintext,//msg
    ciphertext,//sortie
    16, tag//tag sur 16 octet
  );

  // Convertir en hex pour MQTT
  cipher_hex = "";
  tag_hex = "";
  for (int i = 0; i < strlen(plaintext); i++) {
    char buf[3];
    sprintf(buf, "%02X", ciphertext[i]);
    cipher_hex += buf;
  }
  for (int i = 0; i < 16; i++) {
    char buf[3];
    sprintf(buf, "%02X", tag[i]);
    tag_hex += buf;
  }

  mbedtls_gcm_free(&ctx);
}

// ================== WIFI + MQTT ==================
void setup_wifi() {
  Serial.print("Connexion au WiFi");
  WiFi.begin(ssid, password);
  while (WiFi.status() != WL_CONNECTED) {
    delay(500);
    Serial.print(".");
  }
  Serial.println("\n✅ WiFi connecté");
}

void reconnect() {
  while (!client.connected()) {
    Serial.print("Connexion au broker MQTT...");
    if (client.connect("esp32-aead")) {
      Serial.println("✅ Connecté");
    } else {
      Serial.print("❌ Échec, code : ");
      Serial.println(client.state());
      delay(5000);
    }
  }
}

// ================== SETUP ==================
void setup() {
  Serial.begin(115200);
  dht.begin();
  setup_wifi();
  client.setServer(mqtt_server, 1883);

  analogSetAttenuation(ADC_11db);
  IrReceiver.begin(IR_PIN, ENABLE_LED_FEEDBACK);

  Serial.println("Systeme IoT Security + AEAD + MQTT demarre");
}

// ================== LOOP ==================
void loop() {

  if (!client.connected()) reconnect();
  client.loop();

  // ---------- IR KY-022 ----------
  if (IrReceiver.decode()) {
    Serial.print("Code IR : 0x");
    Serial.println(IrReceiver.decodedIRData.decodedRawData, HEX);
    IrReceiver.resume();
  }

  // ---------- KY-013 ----------
  int adcValue = analogRead(KY013_PIN);
  float temperatureKY = NAN;

  if (adcValue > 0) {
    float resistance = (4095.0 / adcValue - 1.0) * 10000.0;
    float beta = 3950.0;
    float r0 = 10000.0;
    float t0 = 298.15;

    float tempK = 1.0 / ((1.0 / t0) + (1.0 / beta) * log(resistance / r0));
    temperatureKY = tempK - 273.15;

    Serial.print("KY-013 Temp : ");
    Serial.print(temperatureKY);
    Serial.println(" °C");
  } else {
    Serial.println("Erreur KY-013");
  }

  // ---------- DHT11 ----------
  float h = dht.readHumidity();
  float t = dht.readTemperature();

  if (isnan(h) || isnan(t)) {
    Serial.println("Erreur DHT11");
  } else {
    Serial.print("DHT11 Temp : ");
    Serial.print(t);
    Serial.println(" °C");

    Serial.print("Humidite   : ");
    Serial.print(h);
    Serial.println(" %");
  }

  // ---------- MESSAGE + AEAD ----------
  if (!isnan(t) && !isnan(h)) { // AEAD basé sur DHT
    char message[100];
    snprintf(message, sizeof(message),
             "KY=%.2f,DHT=%.2f,H=%.2f",
             temperatureKY, t, h);

    Serial.print("Message clair : ");
    Serial.println(message);

    String cipher_hex, tag_hex;
    encryptAEAD(message, cipher_hex, tag_hex);

    Serial.println("Ciphertext : " + cipher_hex);
    Serial.println("Auth Tag   : " + tag_hex);

    // ----- Publication MQTT -----
    String payload = "{";
    payload += "\"ciphertext\":\"" + cipher_hex + "\",";
    payload += "\"auth_tag\":\"" + tag_hex + "\"";
    payload += "}";

    client.publish(mqtt_topic, payload.c_str());
    Serial.println("📤 Données chiffrées envoyées MQTT : " + payload);
  }

  Serial.println("-------------------------------");
  delay(5000);
}
