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

package com.specinfosystems.uapki;

import com.sun.jna.Native;
import com.sun.jna.Pointer;

import java.nio.ByteBuffer;
import java.util.Objects;

/**
 * Дані для підпису: файл (бібліотека читає його блоками) або дані в пам'яті процесу (бібліотека гешує їх
 * на місці, без копій і Base64). Пам'ять має бути доступна до кінця виклику
 *
 * @param file файл або null
 * @param ptr  адреса даних у пам'яті процесу або null
 * @param size розмір даних у пам'яті
 */
public record SignSource(String file, Pointer ptr, long size) {
    public SignSource {
        if ((file == null) == (ptr == null))
            throw new IllegalArgumentException("either a file or a pointer");
        if (size < 0)
            throw new IllegalArgumentException("size < 0");
    }

    /**
     * Файл
     */
    public static SignSource ofFile(String file) {
        return new SignSource(Objects.requireNonNull(file), null, 0);
    }

    /**
     * Дані в пам'яті процесу, наприклад з {@code MemorySegment.address()} або JNA {@code Memory}
     */
    public static SignSource ofMemory(Pointer ptr, long size) {
        return new SignSource(null, Objects.requireNonNull(ptr), size);
    }

    /**
     * Дані від position до limit прямого буфера, наприклад {@code FileChannel.map(...)}.
     * Буфер має лишатися досяжним до кінця виклику
     */
    public static SignSource ofBuffer(ByteBuffer buffer) {
        return new SignSource(null, address(buffer), buffer.remaining());
    }

    // Адреса position прямого буфера
    static Pointer address(ByteBuffer buffer) {
        if (!buffer.isDirect())
            throw new IllegalArgumentException("a direct buffer is required (ByteBuffer.allocateDirect, FileChannel.map)");
        return Native.getDirectBufferPointer(buffer).share(buffer.position());
    }

    // Адреса для запиту: hex, big-endian, розміром у вказівник
    static String hexAddress(Pointer ptr) {
        long address = Pointer.nativeValue(ptr);
        return Native.POINTER_SIZE == 8 ? String.format("%016X", address) : String.format("%08X", (int) address);
    }
}
