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

using System.Globalization;

namespace UapkiNet;

[Serializable]
public class UapkiException : Exception
{
    public int ErrorCode { get; }

    /// <summary>
    /// Опис коду помилки UAPKI/cm-* без префікса; null, якщо код невідомий.
    /// Мова — culture або поточна мова інтерфейсу.
    /// </summary>
    public static string? Describe(int error, CultureInfo? culture = null) =>
        UapkiResources.ResourceManager.GetString("Error_" + error.ToString("X4"), culture);

    private static string MessageFor(int error)
    {
        var description = Describe(error) ?? string.Format(UapkiResources.ErrorUnknownCode, error.ToString("X"));
        return UapkiResources.ErrorPrefix + ". " + description;
    }

    public UapkiException(int error)
        : base(MessageFor(error))
    {
        ErrorCode = error;
    }

    public UapkiException(string error)
        : base(error)
    {
        ErrorCode = 0;
    }

    public UapkiException(int error, Exception inner)
        : base(MessageFor(error), inner)
    {
        ErrorCode = error;
    }

    public UapkiException(string error, Exception inner)
        : base(error, inner)
    {
        ErrorCode = 0;
    }
}
