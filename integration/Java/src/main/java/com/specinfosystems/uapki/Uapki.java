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

import com.google.gson.JsonElement;
import com.google.gson.stream.JsonWriter;
import com.sun.jna.Pointer;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.lang.ref.Cleaner;
import java.lang.ref.Reference;
import java.lang.reflect.Type;
import java.net.ProxySelector;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.time.format.DateTimeParseException;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantReadWriteLock;

/**
 * Бібліотека UAPKI.
 * <p>
 * Кожен екземпляр - окрема сесія бібліотеки зі своїм станом (ініціалізація, відкрите сховище ключів, вибраний ключ);
 * сесії можна використовувати паралельно з різних потоків. Режими:
 * <ul>
 * <li>{@link #global()} - глобальний екземпляр бібліотеки (функція process), як у версіях 2.x; {@link #close()} нічого не робить;</li>
 * <li>{@link #Uapki()} - сесія (uapki_session_create);</li>
 * <li>{@link #createSharedMemory()} - спільна пам'ять (кеші сертифікатів і СВС для кількох сесій), дозволені лише методи роботи з кешами;</li>
 * <li>{@link #Uapki(Uapki)} - сесія, яка використовує спільну пам'ять.</li>
 * </ul>
 * Сесію і спільну пам'ять потрібно звільнити викликом {@link #close()} (try-with-resources); якщо цього не зробити,
 * їх звільнить {@link Cleaner} після збирання сміття. Виклик close() з іншого потоку чекає завершення поточних викликів;
 * після close() виклики завершуються {@link UapkiException}.
 * <p>
 * Стан екземпляра ({@link #getUapkiInfo()}, {@link #getOpenedKeyStorage()}, {@link #getSelectedKey()}) не синхронізований:
 * методи, які його змінюють (init, openKeyStorage, selectKey, ...), не слід викликати для одного екземпляра одночасно з різних потоків.
 * <p>
 * Сесії потребують нативної бібліотеки uapki версії 3.0 або новішої.
 */
public final class Uapki implements AutoCloseable {
    private enum Mode { GLOBAL, SESSION, SHARED_MEMORY }

    private static final String MSG_SESSION_CLOSED = "Помилка. Сесію звільнено";
    private static final String MSG_MEMORY_CLOSED = "Помилка. Спільну пам'ять звільнено";
    private static final String MSG_NO_SESSIONS = "Помилка. Бібліотека uapki не підтримує сесії (потрібна версія 3.0 або новіша)";
    private static final String DEFAULT_CONFIG = "{}";

    private static final Cleaner CLEANER = Cleaner.create();
    private static final Uapki GLOBAL = new Uapki(Mode.GLOBAL, null);

    private final Mode mode;
    private final Pointer handle;                   //  session or shared memory
    private final Uapki sharedMemory;               //  the shared memory used by the session (keeps it reachable)
    private final Cleaner.Cleanable cleanable;
    private final ReentrantReadWriteLock lock = new ReentrantReadWriteLock();
    private boolean closed;                         //  guarded by lock

    private UapkiLibraryInfo uapkiInfo;
    private OpenedKeyStorageInfo openedKeyStorage;
    private SelectedKeyInfo selectedKey;

    /**
     * Створює сесію бібліотеки (uapki_session_create). Сесію потрібно звільнити викликом {@link #close()}
     *
     * @throws UapkiException якщо бібліотека не підтримує сесії або сесію не вдалося створити
     */
    public Uapki() {
        this(Mode.SESSION, null);
    }

    /**
     * Створює сесію, яка використовує спільну пам'ять (кеші сертифікатів і СВС)
     *
     * @param sharedMemory спільна пам'ять ({@link #createSharedMemory()})
     * @throws IllegalArgumentException якщо sharedMemory не є спільною пам'яттю
     */
    public Uapki(Uapki sharedMemory) {
        this(Mode.SESSION, checkSharedMemory(sharedMemory));
    }

    private Uapki(Mode mode, Uapki sharedMemory) {
        this.mode = mode;
        this.sharedMemory = sharedMemory;
        if (mode == Mode.GLOBAL) {
            handle = null;
            cleanable = null;
        } else {
            boolean memory = (mode == Mode.SHARED_MEMORY);
            handle = createHandle(memory);
            cleanable = CLEANER.register(this, new Release(handle, memory));
        }
    }

    private static Uapki checkSharedMemory(Uapki sharedMemory) {
        Objects.requireNonNull(sharedMemory, "sharedMemory");
        if (sharedMemory.mode != Mode.SHARED_MEMORY)
            throw new IllegalArgumentException("Очікується екземпляр спільної пам'яті (Uapki.createSharedMemory)");
        return sharedMemory;
    }

    /**
     * @return глобальний екземпляр бібліотеки (функція process), як у версіях 2.x; його не можна звільнити
     */
    public static Uapki global() {
        return GLOBAL;
    }

    /**
     * Створює спільну пам'ять (uapki_session_shared_memory_create): кеші сертифікатів і СВС для кількох сесій.
     * Дозволені лише методи роботи з кешами; спільну пам'ять потрібно звільнити викликом {@link #close()}
     *
     * @return спільна пам'ять
     * @throws UapkiException якщо бібліотека не підтримує сесії
     */
    public static Uapki createSharedMemory() {
        return new Uapki(Mode.SHARED_MEMORY, null);
    }

    public boolean isGlobal() {
        return mode == Mode.GLOBAL;
    }

    public boolean isSharedMemory() {
        return mode == Mode.SHARED_MEMORY;
    }

    /**
     * @return стан ініціалізованої бібліотеки або null, якщо init не викликано
     */
    public UapkiLibraryInfo getUapkiInfo() {
        return uapkiInfo;
    }

    /**
     * @return відкрите сховище ключів або null
     */
    public OpenedKeyStorageInfo getOpenedKeyStorage() {
        return openedKeyStorage;
    }

    /**
     * @return вибраний ключ або null
     */
    public SelectedKeyInfo getSelectedKey() {
        return selectedKey;
    }

    // ---------------------------------------------------------------------------------------------------------------
    //  Native calls
    // ---------------------------------------------------------------------------------------------------------------

    private static UapkiNative lib() {
        return UapkiNative.Holder.get();
    }

    private static Pointer createHandle(boolean memory) {
        UapkiNative lib = lib();        //  an error loading the library itself is not caught
        Pointer h;
        try {
            h = memory ? lib.uapki_session_shared_memory_create() : lib.uapki_session_create();
        } catch (UnsatisfiedLinkError e) {
            throw new UapkiException(MSG_NO_SESSIONS, e);
        }
        if (h == null)
            throw new UapkiException("Помилка. Не вдалося створити сесію бібліотеки uapki");
        return h;
    }

    //  The release action must not reference the Uapki object
    private static final class Release implements Runnable {
        private final Pointer handle;
        private final boolean memory;

        Release(Pointer handle, boolean memory) {
            this.handle = handle;
            this.memory = memory;
        }

        @Override
        public void run() {
            if (memory)
                lib().uapki_session_shared_memory_free(handle);
            else
                lib().uapki_session_free(handle);
        }
    }

    /**
     * Звільняє сесію або спільну пам'ять; для глобального екземпляра нічого не робить. Якщо з іншого потоку
     * виконується виклик бібліотеки, close() чекає його завершення
     */
    @Override
    public void close() {
        if (mode == Mode.GLOBAL)
            return;

        lock.writeLock().lock();
        try {
            if (!closed) {
                closed = true;
                cleanable.clean();
            }
        } finally {
            lock.writeLock().unlock();
        }

        uapkiInfo = null;
        openedKeyStorage = null;
        selectedKey = null;
    }

    /**
     * Виконує JSON-запит до бібліотеки (як є) і повертає JSON-відповідь
     *
     * @param request JSON-запит: {"method":"...","parameters":{...}}
     * @return JSON-відповідь
     * @throws UapkiException якщо сесію або спільну пам'ять звільнено
     */
    public String process(String request) {
        byte[] req = toUtf8Z(request == null ? "" : request);
        Pointer p = (mode == Mode.GLOBAL) ? lib().process(req) : processWithHandles(req);
        String result = "{\"errorCode\":-1}";

        if (p != null) {
            try {
                result = p.getString(0, StandardCharsets.UTF_8.name());
            } finally {
                lib().json_free(p);
            }
        }
        return result;
    }

    //  The handles are locked for the time of the call: close() from another thread waits until the call is done
    private Pointer processWithHandles(byte[] req) {
        Lock own = lock.readLock();
        own.lock();
        try {
            if (closed)
                throw new UapkiException(mode == Mode.SHARED_MEMORY ? MSG_MEMORY_CLOSED : MSG_SESSION_CLOSED);

            if (mode == Mode.SHARED_MEMORY)
                return lib().uapki_session_shared_memory_process(handle, req);

            if (sharedMemory == null)
                return lib().uapki_session_process(handle, null, req);

            Lock memory = sharedMemory.lock.readLock();
            memory.lock();
            try {
                if (sharedMemory.closed)
                    throw new UapkiException(MSG_MEMORY_CLOSED);
                return lib().uapki_session_process(handle, sharedMemory.handle, req);
            } finally {
                memory.unlock();
            }
        } finally {
            own.unlock();
            Reference.reachabilityFence(this);
        }
    }

    private static byte[] toUtf8Z(String s) {
        byte[] b = s.getBytes(StandardCharsets.UTF_8);
        byte[] z = new byte[b.length + 1];
        System.arraycopy(b, 0, z, 0, b.length);
        return z;
    }

    // ---------------------------------------------------------------------------------------------------------------
    //  Requests and responses
    // ---------------------------------------------------------------------------------------------------------------

    private static String request(String method) {
        return Json.request(method);
    }

    private static String request(String method, Json.ParamsWriter writeParameters) {
        return Json.request(method, writeParameters);
    }

    private static String requestObject(String method, Object parameters) {
        return Json.requestObject(method, parameters);
    }

    private <T> Json.Response<T> response(String request, Type resultType) {
        return Json.parseResponse(process(request), resultType);
    }

    //  Checks the error code, returns the result (can be null)
    private <T> T call(String request, Type resultType) {
        Json.Response<T> ret = response(request, resultType);
        if (ret.errorCode != 0)
            throw new UapkiException(ret.errorCode);
        return ret.result;
    }

    //  Checks the error code and that the result is present
    private <T> T callResult(String request, Type resultType) {
        T ret = call(request, resultType);
        if (ret == null)
            throw new UapkiException(0x2001);
        return ret;
    }

    private void callNoResult(String request) {
        call(request, JsonElement.class);
    }

    private static void writeBase64(JsonWriter w, String name, byte[] bytes) throws IOException {
        w.name(name).value(Json.base64(bytes));
    }

    //  Result containers
    private record CmProviders(List<CmProvider> providers) { }
    private record VersionInfo(String name, String version) { }
    private record KeyStoragesList(List<KeyStorage> storages) { }
    private record KeysList(List<Key> keys) { }
    private record KeyIdResult(String id) { }
    private record CertsList(List<String> certIds, List<CertificateShortInfo> certInfos) { }
    private record BytesOnly(byte[] bytes) { }
    private record AddedCerts(List<AddedCert> added) { }
    private record CrlsList(List<String> crlIds, int count, int offset, int pageSize, List<CrlInfo> crlInfos) { }
    private record Signature(String id, byte[] bytes) { }
    private record SignaturesList(List<Signature> signatures) { }

    //  Request parameters
    private record OpenKeyStorageParams(String provider, String storage, String password, String mode, String username,
                                        OpenKeyStorageExtParams openParams) { }
    private record OpenKeyStorageRequest(String method, OpenKeyStorageParams parameters) { }
    private record ListCertsParams(Boolean storage, Boolean showCertInfos, Integer offset, Integer pageSize,
                                   List<String> subjectKeyIdentifiers) { }
    private record CertRemoveParams(String certId, Boolean storage, Boolean permanent) { }
    private record CertsAddParams(List<byte[]> certificates, byte[] bundle, Boolean storage, Boolean permanent) { }
    //  checkTrustedRoot: null (not sent) or true
    private record CertVerifyParams(byte[] bytes, String certId, String validationType, String validateTime, Boolean checkTrustedRoot) { }
    private record DigestParams(String hashAlgo, String signAlgo, byte[] bytes, String file) { }
    private record ContentToEncrypt(byte[] bytes, String encryptionAlgo) { }
    private record RecipientInfo(String certId, String kdfAlgo) { }
    private record EncryptParams(ContentToEncrypt content, List<RecipientInfo> recipientInfos) { }
    private record SignFormat(String signatureFormat, boolean detachedData, boolean includeCert, boolean includeTime,
                              String signAlgo) { }
    //  ptr/size - data in the memory of this process: the address (hex, big-endian) and the size
    private record DataTbs(String id, byte[] bytes, String file, Boolean isDigest, String ptr, Long size) { }
    //  checkTrustedRoot: null (not sent) or true
    private record SignOptions(boolean ignoreCertStatus, Boolean checkTrustedRoot) { }
    private record SignParameters(SignFormat signParams, List<DataTbs> dataTbs, SignOptions options) { }
    private record SignedData(byte[] bytes, byte[] content, String file, String ptr, Long size) { }
    private record VerifyParams(SignedData signature, ValidationOptions options, Boolean returnContent) { }

    // ---------------------------------------------------------------------------------------------------------------
    //  INIT, DEINIT, VERSION, PROVIDERS
    // ---------------------------------------------------------------------------------------------------------------

    private void checkInit() {
        if (uapkiInfo == null)
            throw new UapkiException("Помилка. Криптографічну бібліотеку не ініціалізовано");
    }

    /**
     * Ініціалізує бібліотеку (метод INIT); якщо бібліотеку вже ініціалізовано, нічого не робить і повертає "{}".
     * Каталоги кешів сертифікатів і СВС створюються, якщо їх немає
     *
     * @param parameters параметри INIT
     * @return JSON-відповідь INIT
     */
    public String init(Config parameters) {
        if (uapkiInfo != null)
            return "{}";

        openedKeyStorage = null;
        selectedKey = null;

        try {
            if (parameters.getCertCache() != null && parameters.getCertCache().getPath() != null)
                Files.createDirectories(Path.of(parameters.getCertCache().getPath()));
            if (parameters.getCrlCache() != null && parameters.getCrlCache().getPath() != null)
                Files.createDirectories(Path.of(parameters.getCrlCache().getPath()));
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }

        String res = process(requestObject("INIT", parameters));
        uapkiInfo = createLibraryInfo(res);
        return res;
    }

    /**
     * Ініціалізує бібліотеку з конфігурацією у JSON (параметри методу INIT)
     *
     * @param config JSON-конфігурація; null або "" - конфігурація за замовчуванням "{}"
     * @return JSON-відповідь INIT
     */
    public String init(String config) {
        if (uapkiInfo != null)
            return "{}";

        openedKeyStorage = null;
        selectedKey = null;

        if (config == null || config.isEmpty())
            config = DEFAULT_CONFIG;

        return init(Json.fromJson(config, Config.class));
    }

    /**
     * Ініціалізує бібліотеку з конфігурацією за замовчуванням
     *
     * @return JSON-відповідь INIT
     */
    public String init() {
        return init((String) null);
    }

    private UapkiLibraryInfo createLibraryInfo(String response) {
        Json.Response<InitResponse> ret = Json.parseResponse(response, InitResponse.class);
        if (ret.errorCode != 0)
            throw new UapkiException(ret.errorCode);
        if (ret.result == null)
            throw new UapkiException(0x2001);

        String version = getVersion();
        //  The shared memory does not load providers (PROVIDERS is not allowed there)
        List<CmProvider> providers = isSharedMemory() ? new ArrayList<>() : getProviders();
        return new UapkiLibraryInfo(version, ret.result.certCache().countCerts(), ret.result.certCache().countTrustedCerts(),
                ret.result.crlCache().countCrls(), providers);
    }

    /**
     * Деініціалізує бібліотеку (метод DEINIT); відкрите сховище ключів закривається
     */
    public void deinit() {
        checkInit();

        if (openedKeyStorage != null)
            closeKeyStorage();

        callNoResult(request("DEINIT"));
        uapkiInfo = null;
    }

    /**
     * @return версія бібліотеки (метод VERSION)
     */
    public String getVersion() {
        VersionInfo ret = callResult(request("VERSION"), VersionInfo.class);
        return ret.version();
    }

    private List<CmProvider> getProviders() {
        CmProviders ret = call(request("PROVIDERS"), CmProviders.class);
        return (ret != null && ret.providers() != null) ? ret.providers() : new ArrayList<>();
    }

    // ---------------------------------------------------------------------------------------------------------------
    //  Key storages
    // ---------------------------------------------------------------------------------------------------------------

    private void checkStorage() {
        checkStorage(KeyStorageOpenMode.RO);
    }

    private void checkStorage(KeyStorageOpenMode requiredMode) {
        checkInit();

        if (openedKeyStorage == null)
            throw new UapkiException("Помилка. Сховище ключів не відкрито");

        if (requiredMode == KeyStorageOpenMode.RW && openedKeyStorage.mode() == KeyStorageOpenMode.RO)
            throw new UapkiException("Помилка. Сховище ключів відкрито тільки для читання");
    }

    /**
     * @return сховища ключів усіх провайдерів, які підтримують перелік сховищ
     */
    public List<KeyStorage> getKeyStorages() {
        return getKeyStorages(null);
    }

    /**
     * @param providers провайдери; null - усі провайдери ініціалізованої бібліотеки
     * @return сховища ключів провайдерів, які підтримують перелік сховищ
     */
    public List<KeyStorage> getKeyStorages(List<CmProvider> providers) {
        checkInit();

        List<KeyStorage> keyStorages = new ArrayList<>();
        if (providers == null)
            providers = uapkiInfo.providers();

        for (CmProvider provider : providers) {
            if (!provider.supportListStorages())
                continue;

            KeyStoragesList ret = callResult(request("STORAGES", p -> p.name("provider").value(provider.id())), KeyStoragesList.class);
            if (ret.storages() != null) {
                for (KeyStorage storage : ret.storages()) {
                    if (storage == null)
                        continue;
                    storage.setProviderId(provider.id());
                    keyStorages.add(storage);
                }
            }
        }

        return keyStorages;
    }

    private static String openMode(KeyStorageOpenMode mode, String providerId, String storageId) {
        if (mode == KeyStorageOpenMode.CREATE)
            return "CREATE";
        String ext = Util.extension(storageId);
        if (mode == KeyStorageOpenMode.RO || ("PKCS12".equals(providerId) && !ext.equals(".p12") && !ext.equals(".pfx")))
            return "RO";
        return "RW";
    }

    /**
     * Відкриває сховище ключів (метод OPEN), завантажує перелік ключів з сертифікатами
     *
     * @param storage сховище ({@link #getKeyStorages()} або {@link KeyStorage#KeyStorage(String, String)})
     * @param passwd  пароль
     * @param mode    режим відкриття
     */
    public void openKeyStorage(KeyStorage storage, String passwd, KeyStorageOpenMode mode) {
        openKeyStorage(storage, passwd, mode, null, null);
    }

    /**
     * Відкриває сховище ключів (метод OPEN), завантажує перелік ключів з сертифікатами
     *
     * @param storage     сховище
     * @param passwd      пароль
     * @param mode        режим відкриття
     * @param loginParams параметри входу (передаються JSON-рядком у параметрі username) або null
     * @param openParams  додаткові параметри відкриття або null
     */
    public void openKeyStorage(KeyStorage storage, String passwd, KeyStorageOpenMode mode,
                               OpenKeyStorageLoginParams loginParams, OpenKeyStorageExtParams openParams) {
        if (openedKeyStorage != null)
            closeKeyStorage();

        OpenKeyStorageParams parameters = new OpenKeyStorageParams(storage.providerId(), storage.id(), passwd,
                openMode(mode, storage.providerId(), storage.id()),
                loginParams != null ? Json.GSON.toJson(loginParams) : null,
                openParams);

        KeyStorageInfo ret = callResult(requestObject("OPEN", parameters), KeyStorageInfo.class);

        openedKeyStorage = new OpenedKeyStorageInfo(storage, ret, mode);
        updateKeysInOpenedStorage(true);
    }

    /**
     * Відкриває файлове сховище ключів PKCS#12 (метод OPEN), завантажує перелік ключів з сертифікатами.
     * Файли з розширенням, відмінним від .p12 і .pfx (наприклад, Key-6.dat, .jks), відкриваються лише для читання
     *
     * @param fileName ім'я файлу
     * @param passwd   пароль
     * @param mode     режим відкриття
     */
    public void openKeyStorage(String fileName, String passwd, KeyStorageOpenMode mode) {
        if (openedKeyStorage != null)
            closeKeyStorage();

        String openMode = openMode(mode, "PKCS12", fileName);
        OpenKeyStorageParams parameters = new OpenKeyStorageParams("PKCS12", fileName, passwd, openMode, null, null);

        KeyStorageInfo ret = callResult(requestObject("OPEN", parameters), KeyStorageInfo.class);

        openedKeyStorage = new OpenedKeyStorageInfo(new KeyStorage(fileName, "PKCS12"), ret,
                (openMode.equals("RW") || openMode.equals("CREATE")) ? KeyStorageOpenMode.RW : KeyStorageOpenMode.RO);
        updateKeysInOpenedStorage(true);
    }

    /**
     * Відкриває сховище ключів JSON-запитом OPEN (як є); у разі успіху оновлює стан відкритого сховища
     *
     * @param openCmd JSON-запит OPEN
     * @return JSON-відповідь
     */
    public String openKeyStorageCmd(String openCmd) {
        if (openedKeyStorage != null)
            closeKeyStorage();

        OpenKeyStorageRequest req = Json.fromJson(openCmd, OpenKeyStorageRequest.class);
        String res = process(openCmd);
        Json.Response<KeyStorageInfo> ret = Json.parseResponse(res, KeyStorageInfo.class);
        if (ret.errorCode == 0) {
            if (ret.result == null)
                throw new UapkiException(0x2001);

            OpenKeyStorageParams p = req.parameters();
            if (p == null || p.storage() == null || p.provider() == null)
                throw new UapkiException(0x2001);

            openedKeyStorage = new OpenedKeyStorageInfo(new KeyStorage(p.storage(), p.provider()), ret.result,
                    ("RW".equals(p.mode()) || "CREATE".equals(p.mode())) ? KeyStorageOpenMode.RW : KeyStorageOpenMode.RO);
            updateKeysInOpenedStorage(true);
        }

        return res;
    }

    /**
     * Закриває відкрите сховище ключів (метод CLOSE)
     */
    public void closeKeyStorage() {
        checkStorage();

        callNoResult(request("CLOSE"));

        openedKeyStorage = null;
        selectedKey = null;
    }

    /**
     * Змінює пароль відкритого (для запису) сховища ключів (метод CHANGE_PASSWORD)
     */
    public void changePassword(String newPassword) {
        checkStorage(KeyStorageOpenMode.RW);
        callNoResult(request("CHANGE_PASSWORD", p -> p.name("newPassword").value(newPassword)));
    }

    // ---------------------------------------------------------------------------------------------------------------
    //  Keys
    // ---------------------------------------------------------------------------------------------------------------

    /**
     * Оновлює перелік ключів відкритого сховища (метод KEYS) без сертифікатів
     */
    public void updateKeysInOpenedStorage() {
        updateKeysInOpenedStorage(false);
    }

    /**
     * Оновлює перелік ключів відкритого сховища (метод KEYS)
     *
     * @param withCerts завантажити також сертифікати ключів з кешу сертифікатів
     */
    public void updateKeysInOpenedStorage(boolean withCerts) {
        checkInit();
        checkStorage();

        KeysList ret = call(request("KEYS"), KeysList.class);
        if (ret == null || ret.keys() == null) {
            openedKeyStorage.storage().setKeys(new ArrayList<>());
            return;
        }

        List<Key> keys = new ArrayList<>(ret.keys());
        if (withCerts) {
            for (Key key : keys) {
                List<String> ids = new ArrayList<>();
                ids.add(key.id());
                if (key.keyId2() != null)
                    ids.add(key.keyId2());
                key.setCerts(getCertsShortInfoList(false, 0, null, ids));
            }
        }

        openedKeyStorage.storage().setKeys(keys);
    }

    private void setSelectedKey(Key key) {
        selectedKey = new SelectedKeyInfo(key, (key != null && key.certId() != null) ? getCertInfo(key.certId()) : null);
    }

    /**
     * Вибирає ключ за ідентифікатором сертифіката (метод SELECT_KEY)
     */
    public void selectKeyByCert(String certId) {
        checkInit();
        checkStorage();
        setSelectedKey(call(request("SELECT_KEY", p -> p.name("certId").value(certId)), Key.class));
    }

    /**
     * Вибирає ключ за ідентифікатором (метод SELECT_KEY)
     */
    public void selectKey(String keyId) {
        checkInit();
        checkStorage();
        setSelectedKey(call(request("SELECT_KEY", p -> p.name("id").value(keyId)), Key.class));
    }

    /**
     * Вибирає ключ (метод SELECT_KEY)
     */
    public void selectKey(Key key) {
        selectKey(key.id());
    }

    /**
     * Вибирає ключ JSON-запитом SELECT_KEY (як є); у разі успіху оновлює стан вибраного ключа
     *
     * @param selectCmd JSON-запит SELECT_KEY
     * @return JSON-відповідь
     */
    public String selectKeyCmd(String selectCmd) {
        checkInit();
        checkStorage();

        String res = process(selectCmd);
        Json.Response<Key> ret = Json.parseResponse(res, Key.class);
        if (ret.errorCode == 0)
            setSelectedKey(ret.result);
        return res;
    }

    /**
     * Видаляє ключ зі сховища, відкритого для запису (метод DELETE_KEY)
     */
    public void deleteKey(Key key) {
        checkInit();
        checkStorage(KeyStorageOpenMode.RW);

        callNoResult(request("DELETE_KEY", p -> p.name("id").value(key.id())));

        if (selectedKey != null && selectedKey.key() != null && selectedKey.key().id().equals(key.id()))
            selectedKey = null;
    }

    /**
     * Генерує ключ у сховищі, відкритому для запису (метод CREATE_KEY)
     *
     * @param label       мітка ключа
     * @param application застосування
     * @param mechanism   OID механізму (алгоритму ключа)
     * @param parameter   OID параметра ключа
     * @param isKep       ключ узгодження ключів
     * @return ідентифікатор ключа
     */
    public String generateKey(String label, String application, String mechanism, String parameter, boolean isKep) {
        checkStorage(KeyStorageOpenMode.RW);

        KeyIdResult ret = call(request("CREATE_KEY", p -> {
            p.name("mechanismId").value(mechanism);
            p.name("parameterId").value(parameter);
            p.name("label").value(label);
            p.name("application").value(application);
            p.name("flags").beginObject();
            p.name("keyAgreement").value(isKep);
            p.endObject();
        }), KeyIdResult.class);

        if (ret == null || ret.id() == null)
            throw new UapkiException(0x2001);
        return ret.id();
    }

    // ---------------------------------------------------------------------------------------------------------------
    //  Certificates
    // ---------------------------------------------------------------------------------------------------------------

    /**
     * @param certId ідентифікатор сертифіката
     * @return сертифікат з кешу (метод CERT_INFO)
     */
    public Certificate getCertInfo(String certId) {
        checkInit();

        Json.Response<Certificate> ret = response(request("CERT_INFO", p -> p.name("certId").value(certId)), Certificate.class);
        if (ret.errorCode != 0)
            throw new UapkiException(ret.errorCode);
        if (ret.result == null)
            throw new UapkiException(0x1005);

        ret.result.setId(certId);
        return ret.result;
    }

    /**
     * @return коротка інформація про сертифікати кешу (метод LIST_CERTS)
     */
    public List<CertificateShortInfo> getCertsShortInfoList() {
        return getCertsShortInfoList(false, 0, null, null);
    }

    /**
     * @param storage сертифікати відкритого сховища ключів (інакше - кешу сертифікатів)
     * @return коротка інформація про сертифікати (метод LIST_CERTS)
     */
    public List<CertificateShortInfo> getCertsShortInfoList(boolean storage) {
        return getCertsShortInfoList(storage, 0, null, null);
    }

    /**
     * Коротка інформація про сертифікати (метод LIST_CERTS). Як і в .NET, помилка бібліотеки дає порожній список
     *
     * @param storage  сертифікати відкритого сховища ключів (інакше - кешу сертифікатів)
     * @param offset   зсув
     * @param pageSize розмір сторінки або null
     * @param keyIds   ідентифікатори ключів (subjectKeyIdentifier) для відбору або null
     */
    public List<CertificateShortInfo> getCertsShortInfoList(boolean storage, int offset, Integer pageSize, List<String> keyIds) {
        checkInit();

        ListCertsParams parameters = new ListCertsParams(storage, true, offset, pageSize, keyIds);
        Json.Response<CertsList> ret = response(requestObject("LIST_CERTS", parameters), CertsList.class);
        if (ret.result == null || ret.result.certInfos() == null)
            return new ArrayList<>();
        return ret.result.certInfos();
    }

    /**
     * @return ідентифікатори сертифікатів кешу (метод LIST_CERTS)
     */
    public List<String> getCerts() {
        return getCerts(false, null);
    }

    /**
     * @param storage сертифікати відкритого сховища ключів (інакше - кешу сертифікатів)
     * @return ідентифікатори сертифікатів (метод LIST_CERTS)
     */
    public List<String> getCerts(boolean storage) {
        return getCerts(storage, null);
    }

    /**
     * @param storage сертифікати відкритого сховища ключів (інакше - кешу сертифікатів)
     * @param keyIds  ідентифікатори ключів (subjectKeyIdentifier) для відбору або null
     * @return ідентифікатори сертифікатів (метод LIST_CERTS)
     */
    public List<String> getCerts(boolean storage, List<String> keyIds) {
        checkInit();

        ListCertsParams parameters = new ListCertsParams(storage, false, null, null, keyIds);
        CertsList ret = call(requestObject("LIST_CERTS", parameters), CertsList.class);
        if (ret == null || ret.certIds() == null)
            return new ArrayList<>();
        return ret.certIds();
    }

    /**
     * Видаляє сертифікат з кешу (назавжди) (метод REMOVE_CERT)
     */
    public void removeCert(String certId) {
        removeCert(certId, false, true);
    }

    /**
     * Видаляє сертифікат (метод REMOVE_CERT)
     *
     * @param certId    ідентифікатор сертифіката
     * @param storage   видалити з відкритого для запису сховища ключів (інакше - з кешу)
     * @param permanent видалити також файл з кешу
     */
    public void removeCert(String certId, boolean storage, boolean permanent) {
        checkInit();

        if (storage)
            checkStorage(KeyStorageOpenMode.RW);

        callNoResult(requestObject("REMOVE_CERT", new CertRemoveParams(certId, storage, permanent)));
    }

    /**
     * Видаляє сертифікат з кешу (назавжди) (метод REMOVE_CERT)
     */
    public void removeCert(Certificate cert) {
        removeCert(cert.id(), false, true);
    }

    /**
     * Видаляє сертифікат (метод REMOVE_CERT)
     */
    public void removeCert(Certificate cert, boolean storage, boolean permanent) {
        removeCert(cert.id(), storage, permanent);
    }

    /**
     * @param certId ідентифікатор сертифіката
     * @return сертифікат з кешу (метод GET_CERT) або null
     */
    public byte[] getCert(String certId) {
        checkInit();

        BytesOnly ret = call(request("GET_CERT", p -> p.name("certId").value(certId)), BytesOnly.class);
        return ret == null ? null : ret.bytes();
    }

    /**
     * Додає сертифікати до кешу (назавжди) (метод ADD_CERT)
     */
    public List<AddedCert> importCerts(List<byte[]> certs) {
        return importCerts(certs, false, true);
    }

    /**
     * Додає сертифікати (метод ADD_CERT)
     *
     * @param certs     сертифікати
     * @param storage   додати до відкритого для запису сховища ключів (інакше - до кешу)
     * @param permanent зберегти у файлах кешу
     * @return додані сертифікати
     */
    public List<AddedCert> importCerts(List<byte[]> certs, boolean storage, boolean permanent) {
        if (storage)
            checkStorage(KeyStorageOpenMode.RW);
        else
            checkInit();

        AddedCerts ret = call(requestObject("ADD_CERT", new CertsAddParams(certs, null, storage, permanent)), AddedCerts.class);
        return (ret == null || ret.added() == null) ? new ArrayList<>() : ret.added();
    }

    /**
     * Додає сертифікат до кешу (назавжди) (метод ADD_CERT)
     *
     * @return доданий сертифікат або null
     */
    public AddedCert importCert(byte[] cert) {
        return importCert(cert, false, true);
    }

    /**
     * Додає сертифікат (метод ADD_CERT)
     *
     * @return доданий сертифікат або null
     */
    public AddedCert importCert(byte[] cert, boolean storage, boolean permanent) {
        List<AddedCert> addedCerts = importCerts(List.of(cert), storage, permanent);
        return addedCerts.isEmpty() ? null : addedCerts.get(0);
    }

    /**
     * Додає сертифікати з PKCS#7-пакета до кешу (назавжди) (метод ADD_CERT)
     *
     * @return кількість нових сертифікатів
     */
    public int importCertBundle(byte[] bundle) {
        return importCertBundle(bundle, false, true);
    }

    /**
     * Додає сертифікати з PKCS#7-пакета (метод ADD_CERT)
     *
     * @return кількість нових сертифікатів
     */
    public int importCertBundle(byte[] bundle, boolean storage, boolean permanent) {
        if (storage)
            checkStorage(KeyStorageOpenMode.RW);
        else
            checkInit();

        AddedCerts ret = call(requestObject("ADD_CERT", new CertsAddParams(null, bundle, storage, permanent)), AddedCerts.class);
        if (ret == null || ret.added() == null)
            return 0;
        return (int) ret.added().stream().filter(AddedCert::isUnique).count();
    }

    private static String validationType(boolean useOcsp, boolean useCrl, Instant validateTime) {
        if (validateTime != null || useCrl)
            return "CRL";
        if (useOcsp)
            return "OCSP";
        return null;
    }

    private static String formatUtcTime(Instant time) {
        return time == null ? null : DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss").withZone(ZoneOffset.UTC).format(time);
    }

    /**
     * Перевіряє сертифікат без перевірки статусу (метод VERIFY_CERT)
     */
    public CertValidation verifyCert(byte[] cert) {
        return verifyCert(cert, false, false, null);
    }

    /**
     * Перевіряє сертифікат (метод VERIFY_CERT)
     *
     * @param cert         сертифікат
     * @param useOcsp      перевірити статус за OCSP
     * @param useCrl       перевірити статус за СВС
     * @param validateTime час перевірки (перевірка за СВС) або null
     */
    public CertValidation verifyCert(byte[] cert, boolean useOcsp, boolean useCrl, Instant validateTime) {
        return verifyCert(cert, useOcsp, useCrl, validateTime, false);
    }

    /**
     * Перевіряє сертифікат (метод VERIFY_CERT)
     *
     * @param cert             сертифікат
     * @param useOcsp          перевірити статус за OCSP
     * @param useCrl           перевірити статус за СВС
     * @param validateTime     час перевірки (перевірка за СВС) або null
     * @param checkTrustedRoot ланцюжок сертифіката має закінчуватися довіреним кореневим сертифікатом
     *                         (інакше помилка CERT_NOT_TRUSTED)
     */
    public CertValidation verifyCert(byte[] cert, boolean useOcsp, boolean useCrl, Instant validateTime, boolean checkTrustedRoot) {
        CertVerifyParams parameters = new CertVerifyParams(cert, null, validationType(useOcsp, useCrl, validateTime), formatUtcTime(validateTime),
                checkTrustedRoot ? Boolean.TRUE : null);
        return callResult(requestObject("VERIFY_CERT", parameters), CertValidation.class);
    }

    /**
     * Перевіряє сертифікат з кешу без перевірки статусу (метод VERIFY_CERT)
     */
    public CertValidation verifyCert(String certId) {
        return verifyCert(certId, false, false, null);
    }

    /**
     * Перевіряє сертифікат з кешу (метод VERIFY_CERT)
     *
     * @param certId       ідентифікатор сертифіката
     * @param useOcsp      перевірити статус за OCSP
     * @param useCrl       перевірити статус за СВС
     * @param validateTime час перевірки (перевірка за СВС) або null
     */
    public CertValidation verifyCert(String certId, boolean useOcsp, boolean useCrl, Instant validateTime) {
        return verifyCert(certId, useOcsp, useCrl, validateTime, false);
    }

    /**
     * Перевіряє сертифікат з кешу (метод VERIFY_CERT)
     *
     * @param certId           ідентифікатор сертифіката
     * @param useOcsp          перевірити статус за OCSP
     * @param useCrl           перевірити статус за СВС
     * @param validateTime     час перевірки (перевірка за СВС) або null
     * @param checkTrustedRoot ланцюжок сертифіката має закінчуватися довіреним кореневим сертифікатом
     *                         (інакше помилка CERT_NOT_TRUSTED)
     */
    public CertValidation verifyCert(String certId, boolean useOcsp, boolean useCrl, Instant validateTime, boolean checkTrustedRoot) {
        CertVerifyParams parameters = new CertVerifyParams(null, certId, validationType(useOcsp, useCrl, validateTime), formatUtcTime(validateTime),
                checkTrustedRoot ? Boolean.TRUE : null);
        return callResult(requestObject("VERIFY_CERT", parameters), CertValidation.class);
    }

    /**
     * Статус сертифіката за OCSP (метод CERT_STATUS_BY_OCSP)
     *
     * @param url          адреса OCSP-сервера
     * @param issuerCertId ідентифікатор сертифіката видавця
     * @param serialNumber серійний номер сертифіката (hex)
     */
    public ValidateByOcspInfo getCertByOcsp(String url, String issuerCertId, String serialNumber) {
        return callResult(request("CERT_STATUS_BY_OCSP", p -> {
            p.name("url").value(url);
            p.name("issuerCertId").value(issuerCertId);
            p.name("serialNumber").value(serialNumber);
        }), ValidateByOcspInfo.class);
    }

    // ---------------------------------------------------------------------------------------------------------------
    //  CRLs
    // ---------------------------------------------------------------------------------------------------------------

    /**
     * @return інформація про СВС з кешу з переліком відкликаних сертифікатів (метод CRL_INFO)
     */
    public CrlInfo getCrlInfo(String crlId) {
        return getCrlInfo(crlId, true);
    }

    /**
     * @param crlId            ідентифікатор СВС
     * @param showRevokedCerts повернути перелік відкликаних сертифікатів
     * @return інформація про СВС з кешу (метод CRL_INFO)
     */
    public CrlInfo getCrlInfo(String crlId, boolean showRevokedCerts) {
        checkInit();

        return callResult(request("CRL_INFO", p -> {
            p.name("crlId").value(crlId);
            p.name("showRevokedCerts").value(showRevokedCerts);
        }), CrlInfo.class);
    }

    /**
     * @param bytes СВС
     * @return інформація про СВС (метод CRL_INFO)
     */
    public CrlInfo getCrlInfo(byte[] bytes) {
        return callResult(request("CRL_INFO", p -> writeBase64(p, "bytes", bytes)), CrlInfo.class);
    }

    /**
     * Додає СВС до кешу (назавжди) (метод ADD_CRL)
     */
    public void importCrl(byte[] crl) {
        importCrl(crl, true);
    }

    /**
     * Додає СВС до кешу (метод ADD_CRL)
     *
     * @param permanent зберегти у файлі кешу
     */
    public void importCrl(byte[] crl, boolean permanent) {
        checkInit();

        callNoResult(request("ADD_CRL", p -> {
            writeBase64(p, "bytes", crl);
            p.name("permanent").value(permanent);
        }));
    }

    /**
     * Видаляє СВС з кешу (назавжди) (метод REMOVE_CRL)
     */
    public void removeCrl(String crlId) {
        removeCrl(crlId, true);
    }

    /**
     * Видаляє СВС з кешу (метод REMOVE_CRL)
     *
     * @param permanent видалити також файл з кешу
     */
    public void removeCrl(String crlId, boolean permanent) {
        checkInit();

        callNoResult(request("REMOVE_CRL", p -> {
            p.name("crlId").value(crlId);
            p.name("permanent").value(permanent);
        }));
    }

    /**
     * @return інформація про всі СВС кешу (метод LIST_CRLS)
     */
    public List<CrlInfo> getAllCrls() {
        return getAllCrls(true, 0, null);
    }

    /**
     * @param showCrlInfos повернути інформацію про СВС
     * @param offset       зсув
     * @param pageSize     розмір сторінки або null
     * @return інформація про СВС кешу (метод LIST_CRLS)
     */
    public List<CrlInfo> getAllCrls(boolean showCrlInfos, int offset, Integer pageSize) {
        checkInit();

        CrlsList ret = call(request("LIST_CRLS", p -> {
            p.name("showCrlInfos").value(showCrlInfos);
            p.name("offset").value(offset);
            p.name("pageSize").value(pageSize);
        }), CrlsList.class);

        if (ret != null && ret.crlInfos() != null)
            return ret.crlInfos();
        return new ArrayList<>();
    }

    // ---------------------------------------------------------------------------------------------------------------
    //  CSR
    // ---------------------------------------------------------------------------------------------------------------

    /**
     * @return запит на сертифікат для вибраного ключа (метод GET_CSR)
     */
    public byte[] getCsr() {
        return getCsr(null);
    }

    /**
     * @param signAlgo алгоритм підпису запиту або null
     * @return запит на сертифікат для вибраного ключа (метод GET_CSR)
     */
    public byte[] getCsr(SignAlgo signAlgo) {
        BytesOnly ret = call(request("GET_CSR", p -> {
            if (signAlgo != null)
                p.name("signAlgo").value(signAlgo.oid());
        }), BytesOnly.class);

        if (ret == null || ret.bytes() == null)
            throw new UapkiException(0x2001);
        return ret.bytes();
    }

    /**
     * @param csr запит на сертифікат
     * @return результат перевірки запиту (метод VERIFY_CSR)
     */
    public VerifyCsrInfo verifyCsr(byte[] csr) {
        return callResult(request("VERIFY_CSR", p -> writeBase64(p, "bytes", csr)), VerifyCsrInfo.class);
    }

    // ---------------------------------------------------------------------------------------------------------------
    //  Digest, random
    // ---------------------------------------------------------------------------------------------------------------

    /**
     * @return геш даних (метод DIGEST)
     */
    public byte[] getDigest(byte[] bytes, HashAlgo hashAlgo) {
        return getDigest(bytes, hashAlgo, null);
    }

    /**
     * @param bytes    дані
     * @param hashAlgo алгоритм гешування або null
     * @param signAlgo алгоритм підпису (визначає алгоритм гешування) або null
     * @return геш даних (метод DIGEST)
     */
    public byte[] getDigest(byte[] bytes, HashAlgo hashAlgo, SignAlgo signAlgo) {
        return digest(new DigestParams(hashAlgo != null ? hashAlgo.oid() : null, signAlgo != null ? signAlgo.oid() : null, bytes, null));
    }

    /**
     * @return геш файлу (метод DIGEST)
     */
    public byte[] getFileDigest(String file, HashAlgo hashAlgo) {
        return getFileDigest(file, hashAlgo, null);
    }

    /**
     * @param file     ім'я файлу
     * @param hashAlgo алгоритм гешування або null
     * @param signAlgo алгоритм підпису (визначає алгоритм гешування) або null
     * @return геш файлу (метод DIGEST)
     */
    public byte[] getFileDigest(String file, HashAlgo hashAlgo, SignAlgo signAlgo) {
        return digest(new DigestParams(hashAlgo != null ? hashAlgo.oid() : null, signAlgo != null ? signAlgo.oid() : null, null, file));
    }

    private byte[] digest(DigestParams parameters) {
        BytesOnly ret = call(requestObject("DIGEST", parameters), BytesOnly.class);
        if (ret == null || ret.bytes() == null)
            throw new UapkiException(0x2001);
        return ret.bytes();
    }

    /**
     * @param length кількість байтів
     * @return випадкові байти (метод RANDOM_BYTES)
     */
    public byte[] getRandomBytes(int length) {
        checkInit();

        BytesOnly ret = call(request("RANDOM_BYTES", p -> p.name("length").value(length)), BytesOnly.class);
        if (ret == null || ret.bytes() == null)
            throw new UapkiException(0x2001);
        return ret.bytes();
    }

    // ---------------------------------------------------------------------------------------------------------------
    //  Encrypt, decrypt
    // ---------------------------------------------------------------------------------------------------------------

    /**
     * Зашифровує дані для отримувачів (метод ENCRYPT) алгоритмом Калина-256 з KDF Купина-256
     *
     * @param plain           дані
     * @param recipientsCerts ідентифікатори сертифікатів отримувачів
     */
    public byte[] encrypt(byte[] plain, List<String> recipientsCerts) {
        return encrypt(plain, recipientsCerts, "1.2.804.2.1.1.1.1.1.3.3.2", "1.2.804.2.1.1.1.1.3.7");
    }

    /**
     * Зашифровує дані для отримувачів (метод ENCRYPT).
     * ГОСТ 28147 з KDF ГОСТ 34.311: encryptionAlgo = "1.2.804.2.1.1.1.1.1.1.3", kdfAlgo = "1.2.804.2.1.1.1.1.3.4";
     * Калина-256 з KDF Купина-256: encryptionAlgo = "1.2.804.2.1.1.1.1.1.3.3.2", kdfAlgo = "1.2.804.2.1.1.1.1.3.7"
     *
     * @param plain           дані
     * @param recipientsCerts ідентифікатори сертифікатів отримувачів
     * @param encryptionAlgo  OID алгоритму шифрування
     * @param kdfAlgo         OID алгоритму KDF
     */
    public byte[] encrypt(byte[] plain, List<String> recipientsCerts, String encryptionAlgo, String kdfAlgo) {
        checkInit();

        List<RecipientInfo> recipientInfos = new ArrayList<>();
        for (String recipient : recipientsCerts)
            recipientInfos.add(new RecipientInfo(recipient, kdfAlgo));

        EncryptParams parameters = new EncryptParams(new ContentToEncrypt(plain, encryptionAlgo), recipientInfos);
        BytesOnly ret = call(requestObject("ENCRYPT", parameters), BytesOnly.class);
        if (ret == null || ret.bytes() == null)
            throw new UapkiException(0x2001);
        return ret.bytes();
    }

    /**
     * Розшифровує дані вибраним ключем (метод DECRYPT)
     */
    public DecryptedData decrypt(byte[] bytes) {
        checkStorage();
        return callResult(request("DECRYPT", p -> writeBase64(p, "bytes", bytes)), DecryptedData.class);
    }

    // ---------------------------------------------------------------------------------------------------------------
    //  MODIFY_CMS
    // ---------------------------------------------------------------------------------------------------------------

    /**
     * Модифікація PKCS#7-підпису без зміни значень підписів (метод MODIFY_CMS): додавання
     *
     * @param cmsBytes PKCS#7-підпис
     * @param add      що додати або null
     */
    public ModifyCmsResult modifyCms(byte[] cmsBytes, AddSignature add) {
        return modifyCms(cmsBytes, add, null, null);
    }

    /**
     * Модифікація PKCS#7-підпису без зміни значень підписів (метод MODIFY_CMS): спочатку виконується
     * видалення (remove), потім додавання (add). Якщо щось додано або видалено, новий PKCS#7-підпис
     * повертається в {@link ModifyCmsResult#bytes()}
     *
     * @param cmsBytes PKCS#7-підпис
     * @param add      що додати або null
     * @param remove   що видалити або null
     * @param options  що повернути або null
     */
    public ModifyCmsResult modifyCms(byte[] cmsBytes, AddSignature add, ModifyCmsRemove remove, ModifyCmsOptions options) {
        ModifyCmsParameters parameters = new ModifyCmsParameters()
                .setBytes(cmsBytes)
                .setAdd(add)
                .setRemove(remove)
                .setOptions(options);
        return callResult(requestObject("MODIFY_CMS", parameters), ModifyCmsResult.class);
    }

    /**
     * Додати до PKCS#7-підпису підпис і/або сертифікати, а також отримати контент, сертифікати, СВС (метод MODIFY_CMS)
     *
     * @param cmsBytes                PKCS#7-підпис
     * @param addSignatureBytes       PKCS#7-підпис, перший підпис якого додається, або null
     * @param addCertificates         сертифікати, які додаються, або null
     * @param returnContent           повернути контент
     * @param returnCerts             повернути сертифікати
     * @param returnCrls              повернути СВС
     * @param returnEncodedSignerInfo повернути DER-кодовані структури SignerInfo
     */
    public ModifyCmsResult modifyCms(byte[] cmsBytes, byte[] addSignatureBytes, List<byte[]> addCertificates,
                                     boolean returnContent, boolean returnCerts, boolean returnCrls, boolean returnEncodedSignerInfo) {
        AddSignature add = (addSignatureBytes != null || (addCertificates != null && !addCertificates.isEmpty()))
                ? new AddSignature().setBytes(addSignatureBytes).setCertificates(addCertificates)
                : null;
        ModifyCmsOptions options = new ModifyCmsOptions()
                .setReturnContent(returnContent)
                .setReturnCerts(returnCerts)
                .setReturnCrls(returnCrls)
                .setReturnEncodedSignerInfo(returnEncodedSignerInfo);
        return modifyCms(cmsBytes, add, null, options);
    }

    // ---------------------------------------------------------------------------------------------------------------
    //  Sign
    // ---------------------------------------------------------------------------------------------------------------

    /**
     * Підписує дані вибраним ключем (метод SIGN) з сертифікатом у підписі
     *
     * @param datas        дані
     * @param algo         алгоритм підпису
     * @param signFormat   формат підпису
     * @param detachedData підпис без інкапсуляції даних
     * @return підписи
     */
    public List<byte[]> sign(List<byte[]> datas, SignAlgo algo, SignatureFormat signFormat, boolean detachedData) {
        return sign(datas, algo, signFormat, detachedData, true, false, false);
    }

    /**
     * Підписує дані вибраним ключем (метод SIGN)
     *
     * @param datas            дані
     * @param algo             алгоритм підпису
     * @param signFormat       формат підпису
     * @param detachedData     підпис без інкапсуляції даних
     * @param includeCert      включити сертифікат підписувача
     * @param ignoreCertStatus не перевіряти статус сертифіката підписувача
     * @return підписи
     */
    public List<byte[]> sign(List<byte[]> datas, SignAlgo algo, SignatureFormat signFormat, boolean detachedData,
                             boolean includeCert, boolean ignoreCertStatus) {
        return sign(datas, algo, signFormat, detachedData, includeCert, ignoreCertStatus, false);
    }

    /**
     * Підписує дані або геші вибраним ключем (метод SIGN)
     *
     * @param datas            дані (або геші, якщо isDigest)
     * @param algo             алгоритм підпису
     * @param signFormat       формат підпису
     * @param detachedData     підпис без інкапсуляції даних
     * @param includeCert      включити сертифікат підписувача
     * @param ignoreCertStatus не перевіряти статус сертифіката підписувача
     * @param isDigest         у datas знаходяться геші
     * @return підписи
     */
    public List<byte[]> sign(List<byte[]> datas, SignAlgo algo, SignatureFormat signFormat, boolean detachedData,
                             boolean includeCert, boolean ignoreCertStatus, boolean isDigest) {
        return sign(datas, algo, signFormat, detachedData, includeCert, ignoreCertStatus, isDigest, false);
    }

    /**
     * Підписує дані або геші вибраним ключем (метод SIGN)
     *
     * @param datas            дані (або геші, якщо isDigest)
     * @param algo             алгоритм підпису
     * @param signFormat       формат підпису
     * @param detachedData     підпис без інкапсуляції даних
     * @param includeCert      включити сертифікат підписувача
     * @param ignoreCertStatus не перевіряти статус сертифіката підписувача
     * @param isDigest         у datas знаходяться геші
     * @param checkTrustedRoot під час перевірки статусу ланцюжок сертифіката підписувача має закінчуватися
     *                         довіреним кореневим сертифікатом (інакше помилка CERT_NOT_TRUSTED)
     * @return підписи
     */
    public List<byte[]> sign(List<byte[]> datas, SignAlgo algo, SignatureFormat signFormat, boolean detachedData,
                             boolean includeCert, boolean ignoreCertStatus, boolean isDigest, boolean checkTrustedRoot) {
        List<DataTbs> dataTbs = new ArrayList<>();
        for (int i = 0; i < datas.size(); i++)
            dataTbs.add(new DataTbs(Integer.toString(i), datas.get(i), null, isDigest, null, null));

        SignaturesList ret = callSign(dataTbs, algo, signFormat, detachedData, includeCert, ignoreCertStatus, checkTrustedRoot);

        List<byte[]> signatures = new ArrayList<>();
        for (Signature signature : ret.signatures())
            signatures.add(signature.bytes());
        return signatures;
    }

    private SignaturesList callSign(List<DataTbs> dataTbs, SignAlgo algo, SignatureFormat signFormat, boolean detachedData,
                                    boolean includeCert, boolean ignoreCertStatus, boolean checkTrustedRoot) {
        SignParameters parameters = new SignParameters(
                new SignFormat(signFormat.value(), detachedData, includeCert, true, algo.oid()),
                dataTbs,
                new SignOptions(ignoreCertStatus, checkTrustedRoot ? Boolean.TRUE : null));

        SignaturesList ret = call(requestObject("SIGN", parameters), SignaturesList.class);
        if (ret == null || ret.signatures() == null)
            throw new UapkiException(0x2001);
        return ret;
    }

    /**
     * Підписує файли вибраним ключем без інкапсуляції даних, з сертифікатом у підписі (метод SIGN)
     *
     * @see #signDetached(List, SignAlgo, SignatureFormat, boolean, boolean)
     */
    public List<byte[]> signFilesDetached(String[] files, SignAlgo algo, SignatureFormat signFormat) {
        return signFilesDetached(files, algo, signFormat, true, false);
    }

    /**
     * Підписує файли вибраним ключем без інкапсуляції даних (метод SIGN)
     *
     * @see #signDetached(List, SignAlgo, SignatureFormat, boolean, boolean)
     */
    public List<byte[]> signFilesDetached(String[] files, SignAlgo algo, SignatureFormat signFormat,
                                          boolean includeCert, boolean ignoreCertStatus) {
        return signFilesDetached(files, algo, signFormat, includeCert, ignoreCertStatus, false);
    }

    /**
     * Підписує файли вибраним ключем без інкапсуляції даних (метод SIGN)
     *
     * @see #signDetached(List, SignAlgo, SignatureFormat, boolean, boolean, boolean)
     */
    public List<byte[]> signFilesDetached(String[] files, SignAlgo algo, SignatureFormat signFormat,
                                          boolean includeCert, boolean ignoreCertStatus, boolean checkTrustedRoot) {
        List<SignSource> sources = new ArrayList<>();
        for (String file : files)
            sources.add(SignSource.ofFile(file));
        return signDetached(sources, algo, signFormat, includeCert, ignoreCertStatus, checkTrustedRoot);
    }

    /**
     * Підписує файли або дані в пам'яті вибраним ключем без інкапсуляції даних, одним викликом SIGN.
     * Файли бібліотека читає блоками, дані в пам'яті гешує на місці; нічого не записується на диск.
     * Підпис з інкапсуляцією даних викликач складає сам, якщо потрібен: дані не входять у підписані
     * атрибути, тож вкладання їх у підпис значення підпису не змінює
     *
     * @param sources          файли або дані в пам'яті ({@link SignSource})
     * @param algo             алгоритм підпису
     * @param signFormat       формат підпису
     * @param includeCert      включити сертифікат підписувача
     * @param ignoreCertStatus не перевіряти статус сертифіката підписувача
     * @return підписи в порядку sources
     */
    public List<byte[]> signDetached(List<SignSource> sources, SignAlgo algo, SignatureFormat signFormat,
                                     boolean includeCert, boolean ignoreCertStatus) {
        return signDetached(sources, algo, signFormat, includeCert, ignoreCertStatus, false);
    }

    /**
     * Підписує файли або дані в пам'яті вибраним ключем без інкапсуляції даних, одним викликом SIGN
     *
     * @param sources          файли або дані в пам'яті ({@link SignSource})
     * @param algo             алгоритм підпису
     * @param signFormat       формат підпису
     * @param includeCert      включити сертифікат підписувача
     * @param ignoreCertStatus не перевіряти статус сертифіката підписувача
     * @param checkTrustedRoot під час перевірки статусу ланцюжок сертифіката підписувача має закінчуватися
     *                         довіреним кореневим сертифікатом (інакше помилка CERT_NOT_TRUSTED)
     * @return підписи в порядку sources
     * @see #signDetached(List, SignAlgo, SignatureFormat, boolean, boolean)
     */
    public List<byte[]> signDetached(List<SignSource> sources, SignAlgo algo, SignatureFormat signFormat,
                                     boolean includeCert, boolean ignoreCertStatus, boolean checkTrustedRoot) {
        List<DataTbs> dataTbs = new ArrayList<>();
        for (int i = 0; i < sources.size(); i++) {
            SignSource source = sources.get(i);
            if (source.file() != null)
                dataTbs.add(new DataTbs(Integer.toString(i), null, source.file(), null, null, null));
            else
                dataTbs.add(new DataTbs(Integer.toString(i), null, null, null, SignSource.hexAddress(source.ptr()), source.size()));
        }

        SignaturesList ret = callSign(dataTbs, algo, signFormat, true, includeCert, ignoreCertStatus, checkTrustedRoot);

        byte[][] signatures = new byte[sources.size()][];
        for (Signature signature : ret.signatures())
            signatures[Integer.parseInt(signature.id())] = signature.bytes();
        for (byte[] signature : signatures) {
            if (signature == null)
                throw new UapkiException(0x2001);
        }
        return List.of(signatures);
    }

    // ---------------------------------------------------------------------------------------------------------------
    //  Verify
    // ---------------------------------------------------------------------------------------------------------------

    /**
     * Перевіряє підпис (метод VERIFY, повна перевірка)
     *
     * @param signature PKCS#7-підпис
     * @param content   дані (для підпису без інкапсуляції даних) або null
     */
    public ValidationResult verify(byte[] signature, byte[] content) {
        return verify(signature, content, "FULL");
    }

    /**
     * Перевіряє підпис (метод VERIFY). Якщо в результаті є інформація про підписи, вона повертається навіть
     * за ненульового коду помилки
     *
     * @param signature      PKCS#7-підпис
     * @param content        дані (для підпису без інкапсуляції даних) або null
     * @param validationType тип перевірки ("FULL", "CHAIN", "STRUCT")
     */
    public ValidationResult verify(byte[] signature, byte[] content, String validationType) {
        VerifyParams parameters = new VerifyParams(new SignedData(signature, content, null, null, null), new ValidationOptions(validationType), null);
        return verifyResult(response(requestObject("VERIFY", parameters), ValidationResult.class));
    }

    /**
     * Перевіряє підпис без інкапсуляції даних за даними в пам'яті процесу (метод VERIFY, повна перевірка)
     *
     * @see #verifyDetached(byte[], Pointer, long, String)
     */
    public ValidationResult verifyDetached(byte[] signature, Pointer content, long size) {
        return verifyDetached(signature, content, size, "FULL");
    }

    /**
     * Перевіряє підпис без інкапсуляції даних за даними в пам'яті процесу (метод VERIFY). Бібліотека гешує
     * дані на місці: без копій і Base64, один виклик, дані у відповіді не повертаються.
     * Для підпису з інкапсуляцією даних викликач може передати підпис без даних, а дані - вказівником
     * (наприклад, у відображений у пам'ять файл підпису)
     *
     * @param signature      PKCS#7-підпис без інкапсуляції даних
     * @param content        адреса даних, наприклад з {@code MemorySegment.address()}; пам'ять має бути
     *                       доступна до кінця виклику
     * @param size           розмір даних
     * @param validationType тип перевірки ("FULL", "CHAIN", "STRUCT")
     */
    public ValidationResult verifyDetached(byte[] signature, Pointer content, long size, String validationType) {
        SignedData signed = new SignedData(signature, null, null, SignSource.hexAddress(content), size);
        return verifyResult(response(requestObject("VERIFY", new VerifyParams(signed, new ValidationOptions(validationType), false)),
                ValidationResult.class));
    }

    /**
     * Перевіряє підпис без інкапсуляції даних за даними від position до limit прямого буфера
     * (метод VERIFY, повна перевірка)
     *
     * @see #verifyDetached(byte[], ByteBuffer, String)
     */
    public ValidationResult verifyDetached(byte[] signature, ByteBuffer content) {
        return verifyDetached(signature, content, "FULL");
    }

    /**
     * Перевіряє підпис без інкапсуляції даних за даними від position до limit прямого буфера, наприклад
     * {@code FileChannel.map(...)} (метод VERIFY). Бібліотека гешує дані на місці
     *
     * @param signature      PKCS#7-підпис без інкапсуляції даних
     * @param content        прямий буфер із даними
     * @param validationType тип перевірки ("FULL", "CHAIN", "STRUCT")
     */
    public ValidationResult verifyDetached(byte[] signature, ByteBuffer content, String validationType) {
        try {
            return verifyDetached(signature, SignSource.address(content), content.remaining(), validationType);
        } finally {
            Reference.reachabilityFence(content);
        }
    }

    /**
     * Перевіряє підпис без інкапсуляції даних за файлом даних (метод VERIFY, повна перевірка)
     *
     * @see #verifyDetached(byte[], String, String)
     */
    public ValidationResult verifyDetached(byte[] signature, String contentFile) {
        return verifyDetached(signature, contentFile, "FULL");
    }

    /**
     * Перевіряє підпис без інкапсуляції даних за файлом даних (метод VERIFY). Бібліотека читає файл блоками;
     * один виклик, нічого не записується на диск
     *
     * @param signature      PKCS#7-підпис без інкапсуляції даних
     * @param contentFile    файл даних
     * @param validationType тип перевірки ("FULL", "CHAIN", "STRUCT")
     */
    public ValidationResult verifyDetached(byte[] signature, String contentFile, String validationType) {
        SignedData signed = new SignedData(signature, null, contentFile, null, null);
        return verifyResult(response(requestObject("VERIFY", new VerifyParams(signed, new ValidationOptions(validationType), false)),
                ValidationResult.class));
    }

    private static ValidationResult verifyResult(Json.Response<ValidationResult> ret) {
        if (ret.result != null && ret.result.signatureInfos() != null)
            return ret.result;
        if (ret.errorCode != 0)
            throw new UapkiException(ret.errorCode);
        return ret.result;
    }

    // ---------------------------------------------------------------------------------------------------------------
    //  CMP
    // ---------------------------------------------------------------------------------------------------------------

    /**
     * Отримує сертифікати з CMP-серверів ЦСК за ідентифікаторами ключів (власний протокол, тип 13). Запити на всі
     * адреси надсилаються паралельно; повертається перша успішна відповідь
     *
     * @param urls   адреси CMP-серверів
     * @param keyIds від 1 до 4 ідентифікаторів ключів (hex, 40 або 64 символи)
     * @return сертифікати у форматі PKCS#7 або null, якщо жоден сервер не відповів (загальний час очікування 11 с)
     */
    public static byte[] cmp(List<String> urls, List<String> keyIds) {
        return cmp(urls, keyIds, null);
    }

    /**
     * Отримує сертифікати з CMP-серверів ЦСК за ідентифікаторами ключів (власний протокол, тип 13)
     *
     * @param urls   адреси CMP-серверів
     * @param keyIds від 1 до 4 ідентифікаторів ключів (hex, 40 або 64 символи)
     * @param proxy  вибір проксі-сервера або null (системні налаштування за замовчуванням)
     * @return сертифікати у форматі PKCS#7 або null, якщо жоден сервер не відповів
     */
    public static byte[] cmp(List<String> urls, List<String> keyIds, ProxySelector proxy) {
        return cmpAsync(urls, keyIds, proxy).join();
    }

    /**
     * Асинхронний варіант {@link #cmp(List, List, ProxySelector)}; скасування результату скасовує запити
     */
    public static CompletableFuture<byte[]> cmpAsync(List<String> urls, List<String> keyIds, ProxySelector proxy) {
        return Cmp.cmpAsync(urls, keyIds, proxy);
    }

    // ---------------------------------------------------------------------------------------------------------------
    //  Utilities
    // ---------------------------------------------------------------------------------------------------------------

    /**
     * Перетворює час UTC у форматі бібліотеки ("yyyy-MM-dd HH:mm:ss" або "yyyy-MM-dd HH:mm")
     *
     * @throws DateTimeParseException якщо формат неправильний
     */
    public static Instant convertUtcTimeToInstant(String time) {
        try {
            return LocalDateTime.parse(time, DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss")).toInstant(ZoneOffset.UTC);
        } catch (DateTimeParseException e) {
            return LocalDateTime.parse(time, DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm")).toInstant(ZoneOffset.UTC);
        }
    }
}
