# Introduction

Ce projet a pour objectif de surveiller les communications des appareils IoT utilisant des protocoles sans fil. Il permet de détecter et d'afficher les équipements à portée à l'aide de différents récepteurs compatibles.

# Protocoles pris en charge

## Bluetooth

Cette partie du projet permet d'afficher les différents appareils Bluetooth détectés par les deux récepteurs pris en charge.

Les principaux scripts disponibles sont les suivants :

* **`sniffer_display_nordic.py`** : utilise le dongle **nRF52840** équipé du firmware Bluetooth.
* **`sniffer_display_wch.py`** : utilise le **BLE Analyzer Pro**.

Le fichier **`wch_read_packets.py`** est une bibliothèque utilisée par `sniffer_display_wch.py` pour la lecture des paquets Bluetooth.

### nRF52840 Dongle

Ce récepteur fonctionne avec le script `sniffer_display_nordic.py` et nécessite que le firmware Bluetooth adapté soit installé sur le dongle.

### BLE Analyzer Pro

Pour utiliser `sniffer_display_wch.py`, il est nécessaire d'installer le pilote en C fourni par le projet **BLE Analyzer Pro Linux Capture**. Celui-ci est disponible sur GitHub : https://github.com/xecaz/BLE-Analyzer-pro-linux-capture

Ce pilote est utilisé par le script Python afin d'accéder aux données reçues par le récepteur et de les traiter.
