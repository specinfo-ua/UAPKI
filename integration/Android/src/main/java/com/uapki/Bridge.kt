package com.uapki

object Bridge {
    const val CLASS_NAME_HTTP_CLIENT : String = "com/uapki/HttpClient"
    const val SLEEP_MS : Int = 20

    var loaded: Boolean = false
        private set

    external fun nativeLoad (className: String, sleepMs: Int): Boolean
    external fun nativeProcess (jsonRequest: String): String

    fun load (): Boolean {
        loaded = nativeLoad(CLASS_NAME_HTTP_CLIENT, SLEEP_MS)
        return loaded
    }

    fun process (jsonRequest: String): String {
        return nativeProcess(jsonRequest)
    }
}
