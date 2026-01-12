# Projet-iot
Ce projet met en place un système IoT sécurisé dans lequel un ESP32 collecte des données de capteurs (KY-013, DHT11 et IR), les chiffre avec l’algorithme AES-GCM (AEAD) puis les publie sur un broker MQTT. Le récepteur Python se connecte au même broker, vérifie l’intégrité du message via le tag GCM et déchiffre le contenu.
AES-GCM assure à la fois la confidentialité (chiffrement) et l’authenticité/intégrité (via le tag de 128 bits). Toute modification réseau (ex : attaque MITM) provoque un échec du déchiffrement, rendant le message inutilisable.
Ce mini-système illustre comment ajouter de la sécurité moderne dans une architecture IoT à faible coût en utilisant uniquement un ESP32, MQTT et un client Python standard.
