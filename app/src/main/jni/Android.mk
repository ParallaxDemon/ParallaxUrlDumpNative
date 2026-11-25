LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)
LOCAL_MODULE := urldump
LOCAL_SRC_FILES := UrlDump.cpp

LOCAL_C_INCLUDES := $(LOCAL_PATH)

LOCAL_CFLAGS := -fvisibility=hidden -ffunction-sections -fdata-sections -Wno-error=format-security -w
LOCAL_CPPFLAGS := -std=c++17 -fvisibility=hidden -ffunction-sections -fdata-sections -Wno-error=format-security -w

LOCAL_LDLIBS := -ldl
LOCAL_LDFLAGS := -Wl,--gc-sections -Wl,--strip-all

include $(BUILD_SHARED_LIBRARY)
