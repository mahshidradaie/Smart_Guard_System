#!/bin/bash

echo "=========================================="
echo "  Smart Guard - Auto Run Script (Part 4)  "
echo "=========================================="



echo "[1/3] Compiling the latest C code..."
gcc server.c -o webserver -Wall -pthread -lssl -lcrypto -lcurl -lsqlite3 -lmosquitto

echo "[2/3] Starting the Secure HTTPS Server..."
sudo EMAIL_APP_PASS="frqfcqlcqtxreozx" MQTT_BROKER_PASS="124673Mr" ./webserver
