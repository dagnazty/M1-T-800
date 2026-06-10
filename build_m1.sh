#!/usr/bin/env bash
set -e
cd "$(dirname "$0")"

export ESP_AT_PROJECT_PLATFORM=PLATFORM_ESP32C6
export ESP_AT_MODULE_NAME=ESP32C6-SPI
export ESP_AT_PROJECT_PATH="$(pwd)"
export SILENCE=0

# Bring up the bundled ESP-IDF toolchain environment.
export IDF_PATH="$(pwd)/esp-idf"
# shellcheck disable=SC1091
. "$IDF_PATH/export.sh"

# Build for the ESP32-C6 target.
idf.py -DIDF_TARGET=esp32c6 build
