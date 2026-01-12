import paho.mqtt.client as mqtt
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import binascii
import json

# ================== MQTT ==================
MQTT_BROKER = "broker.hivemq.com"
MQTT_TOPIC = "capteurs"

# ================== CLÉ & IV ==================
key = bytes([
    0x10,0x11,0x12,0x13,
    0x20,0x21,0x22,0x23,
    0x30,0x31,0x32,0x33,
    0x40,0x41,0x42,0x43
]) 

iv = bytes([
    0x01,0x02,0x03,0x04,
    0x05,0x06,0x07,0x08,
    0x09,0x0A,0x0B,0x0C
]) 

aesgcm = AESGCM(key)

# ================== CALLBACK MQTT ==================
def on_connect(client, userdata, flags, rc):
    print("✅ Connecté au broker MQTT")
    client.subscribe(MQTT_TOPIC)

def on_message(client, userdata, msg):
    try:
        payload = json.loads(msg.payload.decode())
        cipher_hex = payload["ciphertext"]
        tag_hex    = payload["auth_tag"]

        ciphertext = binascii.unhexlify(cipher_hex)
        tag        = binascii.unhexlify(tag_hex)

        # AES-GCM attend ciphertext + tag ensemble
        decrypted = aesgcm.decrypt(iv, ciphertext + tag, None)
        print("📥 Message déchiffré :", decrypted.decode())
    except Exception as e:
        print("❌ Erreur déchiffrement :", e)

# ================== CLIENT MQTT ==================
client = mqtt.Client()
client.on_connect = on_connect
client.on_message = on_message

client.connect(MQTT_BROKER, 1883, 60)
client.loop_forever()

