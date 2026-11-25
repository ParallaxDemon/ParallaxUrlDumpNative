#!/bin/sh
# Local / Termux build. Set ANDROID_NDK_HOME to your NDK root first.
set -e

NDK=${ANDROID_NDK_HOME:-}
if [ -z "$NDK" ]; then
    echo "Set ANDROID_NDK_HOME to your Android NDK directory." >&2
    exit 1
fi

"$NDK/ndk-build" -C app/src/main/jni
echo "Built libs are in app/src/main/libs/<abi>/liburldump.so"
