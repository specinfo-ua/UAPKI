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

import java.util.List;

/**
 * Сховище ключів (метод STORAGES) або файлове сховище
 */
public final class KeyStorage {
    private String id = "";
    private String manufacturer = "";
    private String model = "";
    private String description = "";
    private String serial = "";
    private String label = "";
    private boolean passwordCountLow;
    private boolean passwordFinalTry;
    private boolean passwordLocked;
    private boolean passwordToBeChanged;
    private int passwordAttemptsLeft = 255;
    private int passwordMinLen = 6;
    private int passwordMaxLen = 64;

    private transient String providerId = "";
    private transient List<Key> keys;

    public KeyStorage() {
    }

    /**
     * Файлове сховище ключів
     *
     * @param fileName   ім'я файлу
     * @param providerId ідентифікатор провайдера (наприклад, "PKCS12")
     */
    public KeyStorage(String fileName, String providerId) {
        this.id = fileName;
        this.providerId = providerId;
        this.manufacturer = "SPECINFOSYSTEMS";
        this.description = "FILE";
        this.model = "FILE";
        this.label = fileName;
        this.serial = fileName.substring(Math.max(fileName.lastIndexOf('/'), fileName.lastIndexOf('\\')) + 1);
    }

    public String id() { return Util.str(id); }
    public String manufacturer() { return Util.str(manufacturer); }
    public String model() { return Util.str(model); }
    public String description() { return Util.str(description); }
    public String serial() { return Util.str(serial); }
    public String label() { return Util.str(label); }
    public boolean passwordCountLow() { return passwordCountLow; }
    public boolean passwordFinalTry() { return passwordFinalTry; }
    public boolean passwordLocked() { return passwordLocked; }
    public boolean passwordToBeChanged() { return passwordToBeChanged; }
    public int passwordAttemptsLeft() { return passwordAttemptsLeft; }
    public int passwordMinLen() { return passwordMinLen; }
    public int passwordMaxLen() { return passwordMaxLen; }

    /**
     * @return ідентифікатор провайдера сховища
     */
    public String providerId() { return Util.str(providerId); }

    void setProviderId(String providerId) { this.providerId = providerId; }

    /**
     * @return ключі відкритого сховища (заповнюються під час відкриття) або null
     */
    public List<Key> keys() { return keys; }

    void setKeys(List<Key> keys) { this.keys = keys; }
}
