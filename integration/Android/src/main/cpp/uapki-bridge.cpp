#include "uapki-bridge.h"
//#include <android/log.h>


static const char* STR_JNI_ERROR = "{\"errorCode\":8193,\"method\":\"\",\"result\":{},\"error\":\"JNI_ERROR\"}";


UapkiBridge::UapkiBridge ()
    : m_SetJni(nullptr)
    , m_ClassName(std::string("com/uapki/HttpClient"))
    , m_SleepMs(20)
{
//    __android_log_print(ANDROID_LOG_DEBUG, "UAPKI-DEV", "UapkiBridge::UapkiBridge()");
}

jboolean UapkiBridge::load (JNIEnv* env, jstring className, jint sleepMs)
{
//    __android_log_print(ANDROID_LOG_DEBUG, "UAPKI-DEV", "UapkiBridge::load(env=%p, className, sleepMs)", env);
    const char* s_classname = env->GetStringUTFChars(className, nullptr);
    if (s_classname && (strlen(s_classname) > 0)) {
        m_ClassName = std::string(s_classname);
    }
    env->ReleaseStringUTFChars(className, s_classname);
    if (sleepMs > 0) {
        m_SleepMs = sleepMs;
    }

//    __android_log_print(ANDROID_LOG_DEBUG, "UAPKI-DEV", "UapkiBridge::load(env, className='%s', sleepMs=%d)", m_ClassName.c_str(), m_SleepMs);
    if (!m_LibUapki.load()) return JNI_FALSE;

    m_SetJni = (f_uapki_bridge_setjni) DL_GET_PROC_ADDRESS(m_LibUapki.getHandle(), "set_jni");
//    __android_log_print(ANDROID_LOG_DEBUG, "UAPKI-DEV", "UapkiBridge::load(), set m_SetJni=%p", m_SetJni);

    return (m_SetJni) ? JNI_TRUE : JNI_FALSE;
}

jstring UapkiBridge::process (JNIEnv* env, jstring jsonRequest)
{
//    __android_log_print(ANDROID_LOG_DEBUG, "UAPKI-DEV", "UapkiBridge::process(env=%p, jsonRequest), m_SetJni=%p", env, m_SetJni);
    if (m_SetJni(env, m_ClassName.c_str(), m_SleepMs, nullptr) != 0) {
        return env->NewStringUTF(STR_JNI_ERROR);
    }

    jstring rv_js = nullptr;
    const char* s_jsonreq = env->GetStringUTFChars(jsonRequest, nullptr);
//    __android_log_print(ANDROID_LOG_DEBUG, "UAPKI-DEV", "UapkiBridge::process(env, jsonRequest='%s')", s_jsonreq);
    if (s_jsonreq) {
        char* s_jsonresult = m_LibUapki.process(s_jsonreq);
//        __android_log_print(ANDROID_LOG_DEBUG, "UAPKI-DEV", "UapkiBridge::process(env, jsonRequest), result=%s", s_jsonresult);
        if (s_jsonresult) {
            rv_js = env->NewStringUTF(s_jsonresult);
            m_LibUapki.jsonFree(s_jsonresult);
        }
    }
    env->ReleaseStringUTFChars(jsonRequest, s_jsonreq);

    return (rv_js) ? rv_js : env->NewStringUTF(STR_JNI_ERROR);
}
