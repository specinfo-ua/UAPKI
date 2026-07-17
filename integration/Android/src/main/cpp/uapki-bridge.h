#ifndef UAPKI_BRIDGE_H
#define UAPKI_BRIDGE_H


#include <jni.h>
#include "common/loaders/uapki-loader.h"


typedef int (*f_uapki_bridge_setjni) (JNIEnv* env, const char* className, int sleepMs, void* paramPtr);

class UapkiBridge {
    UapkiLoader     m_LibUapki;
    f_uapki_bridge_setjni
                    m_SetJni;
    std::string     m_ClassName;
    int             m_SleepMs;

public:
    UapkiBridge ();

public:
    jboolean load (JNIEnv* env, jstring className, jint sleepMs);
    jstring process (JNIEnv* env, jstring jsonRequest);

};


#endif
