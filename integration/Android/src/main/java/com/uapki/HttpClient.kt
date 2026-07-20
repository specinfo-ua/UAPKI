package com.uapki

//import android.util.Log
import java.io.IOException
import java.time.format.DateTimeFormatter
import java.time.LocalDateTime
import java.util.Locale
import okhttp3.*
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import okhttp3.Response

object HttpClient {
    private val client = OkHttpClient()
    private val logs = mutableListOf<String>()
    private val formatter: DateTimeFormatter = DateTimeFormatter.ofPattern("yyyy:MM:dd HH:mm:ss.SSS", Locale.getDefault())

    var countErrors: Int = 0
        private set

    var countRequests: Int = 0
        private set

    var countResponses: Int = 0
        private set

    var url: String = ""
        private set

    @JvmStatic
    var busy: Boolean = false
        private set

    @JvmStatic
    var statusCode: Int = 0
        private set

    @JvmStatic
    var message: String = ""
        private set

    @JvmStatic
    var responseBytes: ByteArray = ByteArray(0)
        private set

    @JvmStatic
    fun clear() {
        url = ""
        statusCode = 0
        message = ""
        responseBytes = ByteArray(0)
    }

    @JvmStatic
    fun doGet(url: String): Boolean {
//        Log.d("UAPKI-DEV", "doGet(url='$url')")
        if (isBusy()) return false

        busy = true
        clear()
        countRequests++
        this.url = url
        addLog(url)

        val request = Request.Builder()
            .url(url).build()

        client.newCall(request).enqueue(object : Callback {
            override fun onFailure(call: Call, e: IOException) {
                statusCode = -1
                message = "Error: ${e.message}"
                countErrors++
                addLog(statusCode, message)
//                Log.d("UAPKI-DEV", "doPost(): error: $message")
                busy = false
            }

            override fun onResponse(call: Call, response: Response) {
//                Log.d("UAPKI-DEV", "doGet(): onResponse, code=${response.code}")
                responseBytes = response.body.bytes()
                statusCode = response.code
                message = response.message
                response.close()
                countResponses++
                addLog(statusCode, message, responseBytes)
//                Log.d("UAPKI-DEV", "doGet(): onResponse, size=${responseBytes.size}")
                busy = false
            }
        })

        return true
    }

    @JvmStatic
    fun doPost(url: String, contentType: String, dataBytes: ByteArray): Boolean {
//        Log.d("UAPKI-DEV", "doPost(url='$url'; contentType='$contentType)'")
        if (isBusy()) return false

        busy = true
        clear()
        countRequests++
        this.url = url
        addLog(url, contentType, dataBytes)

        val body: RequestBody = dataBytes.toRequestBody(
            contentType.toMediaTypeOrNull(),
            0,
            dataBytes.size
        )

        val request = Request.Builder()
            .url(url).post(body).build()

        client.newCall(request).enqueue(object : Callback {
            override fun onFailure(call: Call, e: IOException) {
                statusCode = -1
                message = "Error: ${e.message}"
                countErrors++
                addLog(statusCode, message)
//                Log.d("UAPKI-DEV", "doPost(): error: $message")
                busy = false
            }

            override fun onResponse(call: Call, response: Response) {
//                Log.d("UAPKI-DEV", "doPost(): onResponse, code=${response.code}")
                responseBytes = response.body.bytes()
                statusCode = response.code
                message = response.message
                response.close()
                countResponses++
                addLog(statusCode, message, responseBytes)
//                Log.d("UAPKI-DEV", "doPost(): onResponse, size=${responseBytes.size}")
                busy = false
            }
        })

        return true
    }

    @JvmStatic
    fun isBusy(): Boolean {
        return busy
    }

    private fun timeStamp(): String = LocalDateTime.now().format(formatter)

    fun addLog(url: String) {
        val entry = "  GET  url='$url'"
        logs.add(timeStamp() + entry)
    }

    fun addLog(url: String, contentType: String, bodyBytes: ByteArray) {
        val entry = "  POST  url='$url'  contentType='$contentType'  bodyBytes=" + bodyBytes.toHex()
        logs.add(timeStamp() + entry)
    }

    fun addLog(statusCode: Int, message: String) {
        val entry = "  RECV  statusCode=$statusCode  message='$message'"
        logs.add(timeStamp() + entry)
    }

    fun addLog(statusCode: Int, message: String, bodyBytes: ByteArray) {
        val entry = "  RECV  statusCode=$statusCode  message='$message'  bodyBytes=" + bodyBytes.toHex()
        logs.add(timeStamp() + entry)
    }

    fun clearLogs() {
        logs.clear()
    }

    fun getLogs(): List<String> = logs.toList();

}

fun String.toMediaTypeOrNull(): MediaType? {
    return try {
        if (this.isNotEmpty()) this.toMediaType()
        else null
    } catch (e: IllegalArgumentException) {
        null
    }
}