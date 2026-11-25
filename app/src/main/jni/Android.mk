LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)
LOCAL_MODULE := urldump
LOCAL_SRC_FILES := UrlDump.cpp

LOCAL_C_INCLUDES := $(LOCAL_PATH)

LOCAL_CFLAGS := -D_FILE_OFFSET_BITS=64 -fvisibility=hidden -ffunction-sections -fdata-sections -Wno-error=format-security
LOCAL_CPPFLAGS := -std=c++17 -D_FILE_OFFSET_BITS=64 -fvisibility=hidden -ffunction-sections -fdata-sections -Wno-error=format-security

LOCAL_LDLIBS := -ldl
LOCAL_LDFLAGS := -Wl,--gc-sections -Wl,--strip-all

include $(BUILD_SHARED_LIBRARY)
