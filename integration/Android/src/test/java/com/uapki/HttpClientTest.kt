package com.uapki

import org.junit.Assert
import org.junit.Test

class HttpClientTest {
    @Test
    fun testGetRequest() {
        var url = "http://ca.specinfosystems.com/download/crls/sis-dstu-2025-delta.crl"
        if (!HttpClient.doGet(url)) {
            println("testGetRequest, GET is failed: isBusy")
            return
        }
        while (HttpClient.isBusy()) {
            Thread.sleep(100)
        }
        println("testGetRequest, HTTP-method GET(url=${HttpClient.url})" +
                " statusCode = ${HttpClient.statusCode}," +
                " message = '${HttpClient.message}'," +
                " responseBytes.size = ${HttpClient.responseBytes.size}")
        Assert.assertTrue(HttpClient.responseBytes.isNotEmpty())
        var hexValue = HttpClient.responseBytes.toHex()
        println("UapkiHttpClient.responseBytes, hex = $hexValue")

        Thread.sleep(500)

        url = "http://ca.specinfosystems.com/download/crls/sis-dstu-2025-full.crl"
        if (!HttpClient.doGet(url)) {
            println("testGetRequest, GET is failed: isBusy")
            return
        }
        while (HttpClient.isBusy()) {
            Thread.sleep(100)
        }
//        println("testGetRequest, HTTP-method GET(url='${UapkiHttpClient.url}')" +
//                " statusCode = ${UapkiHttpClient.statusCode}," +
//                " message = '${UapkiHttpClient.message}'," +
//                " responseBytes.size = ${UapkiHttpClient.responseBytes.size}")
//        assertTrue(UapkiHttpClient.responseBytes.isNotEmpty())
//        hexValue = UapkiHttpClient.responseBytes.toHex()
//        println("UapkiHttpClient.responseBytes, hex = $hexValue")

        println("UapkiHttpClient.getLogs():\n" + HttpClient.getLogs().joinToString("\n"))
    }

    @Test
    fun testPostRequest() {
        var url = "http://ca.informjust.ua/services/tsp/"
        var contentType = "application/timestamp-query"
//        contentType = ""
        var requestBytes : ByteArray = ("30350201013030300c060a2a86240201010101020104201122334455667788" +
                "aaaaaaaabbbbbbbb1122334455667788ccccccccdddddddd").hexToByteArray()
        if (!HttpClient.doPost(url, contentType, requestBytes)) {
            println("testPostRequest, POST is failed: isBusy")
            return
        }
        while (HttpClient.isBusy()) {
            Thread.sleep(100)
        }
        println("testPostRequest, HTTP-method POST(url='${HttpClient.url}'; contentType='$contentType')" +
                " statusCode = ${HttpClient.statusCode}," +
                " message = '${HttpClient.message}'," +
                " responseBytes.size = ${HttpClient.responseBytes.size}")
        Assert.assertTrue(HttpClient.responseBytes.isNotEmpty())
        var hexValue = HttpClient.responseBytes.toHex()
        println("UapkiHttpClient.responseBytes, hex = $hexValue")

        Thread.sleep(1500)

        if (!HttpClient.doPost(url, contentType, requestBytes)) {
            println("testPostRequest, POST is failed: isBusy")
            return
        }
        while (HttpClient.isBusy()) {
            Thread.sleep(100)
        }
//        println("testPostRequest, HTTP-method POST(url='${UapkiHttpClient.url}'; contentType='$contentType')" +
//                " statusCode = ${UapkiHttpClient.statusCode}," +
//                " message = '${UapkiHttpClient.message}'," +
//                " responseBytes.size = ${UapkiHttpClient.responseBytes.size}")
//        assertTrue(UapkiHttpClient.responseBytes.isNotEmpty())
//        hexValue = UapkiHttpClient.responseBytes.toHex()
//        println("UapkiHttpClient.responseBytes, hex = $hexValue")

        println("UapkiHttpClient.getLogs():\n" + HttpClient.getLogs().joinToString("\n"))
    }
}