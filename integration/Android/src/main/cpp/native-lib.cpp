#include <jni.h>
#include "uapki-bridge.h"


static UapkiBridge uapki_bridge;


extern "C" JNIEXPORT jboolean JNICALL
Java_com_uapki_Bridge_nativeLoad(
        JNIEnv* env,
        jobject unused,
        jstring className,
        jint sleepMs)
{
    return uapki_bridge.load(env, className, sleepMs);
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_uapki_Bridge_nativeProcess(
        JNIEnv* env,
        jobject unused,
        jstring jsonRequest)
{
    return uapki_bridge.process(env, jsonRequest);
}
