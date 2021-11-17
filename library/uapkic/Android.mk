DIR_ROOT := ../../uapkic
DIR_SRC := $(DIR_ROOT)/src

LOCAL_PATH := $(abspath $(call my-dir))
include $(CLEAR_VARS)
LOCAL_MODULE := uapkic
LOCAL_CFLAGS := -DUAPKIC_LIBRARY
#for support iconv will usage APP_PLATFORM := android-28

LOCAL_C_INCLUDES += \
	$(DIR_ROOT)/include \
	$(DIR_SRC)

LOCAL_SRC_FILES := \
	$(DIR_SRC)/aes.c \
	$(DIR_SRC)/byte-array.c \
	$(DIR_SRC)/byte-array-internal.c \
	$(DIR_SRC)/byte-utils-internal.c \
	$(DIR_SRC)/des.c \
	$(DIR_SRC)/drbg.c \
	$(DIR_SRC)/dstu4145.c \
	$(DIR_SRC)/dstu7564.c \
	$(DIR_SRC)/dstu7624.c \
	$(DIR_SRC)/dstu8845.c \
	$(DIR_SRC)/ec.c \
	$(DIR_SRC)/ecdsa.c \
	$(DIR_SRC)/ecgdsa.c \
	$(DIR_SRC)/eckcdsa.c \
	$(DIR_SRC)/ecrdsa.c \
	$(DIR_SRC)/ec-cache.c \
	$(DIR_SRC)/ec-default-params.c \
	$(DIR_SRC)/ec-internal.c \
	$(DIR_SRC)/entropy.c \
	$(DIR_SRC)/gost28147.c \
	$(DIR_SRC)/gost34311.c \
	$(DIR_SRC)/gostr3411-2012.c \
	$(DIR_SRC)/hash.c \
	$(DIR_SRC)/hmac.c \
	$(DIR_SRC)/jitterentropy.c \
	$(DIR_SRC)/keywrap.c \
	$(DIR_SRC)/math-ec2m-internal.c \
	$(DIR_SRC)/math-ecp-internal.c \
	$(DIR_SRC)/math-ec-point-internal.c \
	$(DIR_SRC)/math-ec-precomp-internal.c \
	$(DIR_SRC)/math-gf2m-internal.c \
	$(DIR_SRC)/math-gfp-internal.c \
	$(DIR_SRC)/math-int-internal.c \
	$(DIR_SRC)/md5.c \
	$(DIR_SRC)/paddings.c \
	$(DIR_SRC)/pbkdf.c \
	$(DIR_SRC)/pthread-impl.c \
	$(DIR_SRC)/ripemd.c \
	$(DIR_SRC)/rsa.c \
	$(DIR_SRC)/sha1.c \
	$(DIR_SRC)/sha2.c \
	$(DIR_SRC)/sha3.c \
	$(DIR_SRC)/sm2dsa.c \
	$(DIR_SRC)/sm3.c \
	$(DIR_SRC)/stacktrace.c \
	$(DIR_SRC)/uapkic.c \
	$(DIR_SRC)/whirlpool.c \
	$(DIR_SRC)/word-internal.c

include $(BUILD_SHARED_LIBRARY)
