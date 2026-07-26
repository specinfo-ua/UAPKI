#ifndef UAPKI_BRIDGE_H
#define UAPKI_BRIDGE_H


#include <jni.h>
#include "common/loaders/uapki-loader.h"

using f_uapki_bridge_setjni = int (*)(JNIEnv* env, const char* className, int sleepMs, void* paramPtr);

class UapkiBridge {
    UapkiLoader     m_LibUapki;
    f_uapki_bridge_setjni m_SetJni = nullptr;
    std::string     m_ClassName = "com/uapki/HttpClient";
    int             m_SleepMs = 20;

public:
    UapkiBridge ();

public:
    jboolean load (JNIEnv* env, jstring className, jint sleepMs);
    jstring process (JNIEnv* env, jstring jsonRequest);

};


#endif
