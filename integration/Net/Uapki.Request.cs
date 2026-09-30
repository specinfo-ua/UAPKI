/*
 * Copyright (c) 2026, The UAPKI Project Authors.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *
 * 1. Redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 * notice, this list of conditions and the following disclaimer in the
 * documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS
 * IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 * TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A
 * PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED
 * TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
 * PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 * LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;
using System.Text.Json.Serialization.Metadata;

namespace UapkiNet;

public static partial class Uapki
{
    private static readonly JsonWriterOptions requestWriterOpts = new JsonWriterOptions
    {
        Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping
    };

    /// <summary>
    /// Запит без параметрів: {"method":"..."}
    /// </summary>
    private static string Request(string method)
    {
        return BuildRequest(method, null);
    }

    /// <summary>
    /// Запит з параметрами, які записує writeParameters: {"method":"...","parameters":{...}}
    /// </summary>
    private static string Request(string method, Action<Utf8JsonWriter> writeParameters)
    {
        return BuildRequest(method, writer =>
        {
            writer.WriteStartObject();
            writeParameters(writer);
            writer.WriteEndObject();
        });
    }

    /// <summary>
    /// Запит з параметрами-об'єктом, серіалізованим за typeInfo: {"method":"...","parameters":{...}}
    /// </summary>
    private static string Request<T>(string method, T parameters, JsonTypeInfo<T> typeInfo)
    {
        return BuildRequest(method, writer => JsonSerializer.Serialize(writer, parameters, typeInfo));
    }

    private static string BuildRequest(string method, Action<Utf8JsonWriter>? writeParameters)
    {
        using var stream = new MemoryStream();
        using (var writer = new Utf8JsonWriter(stream, requestWriterOpts))
        {
            writer.WriteStartObject();
            writer.WriteString("method", method);
            if (writeParameters is not null)
            {
                writer.WritePropertyName("parameters");
                writeParameters(writer);
            }
            writer.WriteEndObject();
        }
        return Encoding.UTF8.GetString(stream.ToArray());
    }
}
