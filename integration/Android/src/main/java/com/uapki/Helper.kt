package com.uapki

import com.google.gson.Gson
import java.util.Base64

data class Request (
    val method: String,
    val parameters: Map<String, Any> = emptyMap()
)

data class Response (
    val errorCode: Int = 0,
    val method: String = "",
    val result: Map<String, Any> = emptyMap(),
    val error: String = ""
)

object Helper {
    val gson = Gson()

    var jsonRequest: String = ""
        private set

    var jsonResponse: String = ""
        private set

    fun fromJson (json: String): Response {
        try {
            return gson.fromJson(json, Response::class.java)
        } catch (e: Exception) {
            return Response(errorCode = 8194, error = e.toString())
        }
    }

    fun toJson (method: String, parameters: Map<String, Any> = emptyMap()): String {
        return gson.toJson(Request(method, parameters))
    }

    fun process (json: String): Response {
        jsonRequest = json;
        jsonResponse = Bridge.process(jsonRequest)
        return fromJson(jsonResponse)
    }

    fun process (method: String, parameters: Map<String, Any>): Response {
        jsonRequest = toJson(method, parameters);
        jsonResponse = Bridge.process(jsonRequest)
        return fromJson(jsonResponse)
    }
}

fun ByteArray.toBase64(): String =
    Base64.getEncoder().encodeToString(this)

fun ByteArray.toHex(): String =
    joinToString("") { "%02x".format(it) }