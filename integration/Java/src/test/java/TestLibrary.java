/*
 * Copyright (c) 2021, The UAPKI Project Authors.
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

import com.sit.uapki.cert.*;
import com.sit.uapki.common.*;
import com.sit.uapki.crl.*;
import com.sit.uapki.key.*;
import com.sit.uapki.method.*;
import com.google.gson.*;
import java.util.ArrayList;
import java.util.LinkedList;
import java.util.List;
import com.sit.uapki.*;
import org.junit.*;
import org.junit.runners.MethodSorters;

@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class TestLibrary {
    static final String WORK_DIR = "./../../library/test/data/";
    static final String INIT_TSP_URL = "http://ca.iit.ua/services/tsp/dstu/";
    static final String INIT_TSP_POLICY = null;//l"1.2.804.2.1.1.1.2.3.1";

    static Library lib;
    static String testDir = WORK_DIR;
    static List<String> listProviders;


    @BeforeClass
    public static void setup() throws Exception  {
        lib = new Library(true);
        Assert.assertNotNull(lib);
        System.out.println("Library loaded. Name: " + lib.getName() + ", Version: " + lib.getVersion());
        System.out.println("Бібліотека завантажена (тест utf-8). Назва: " + lib.getName() + ", Версія: " + lib.getVersion());
        Assert.assertEquals(lib.getName(), "UAPKI");


        final String INIT_DIR_CERTS = testDir + "certs/";
        final String INIT_DIR_CRLS = testDir + "certs/crls/";

        final boolean ADD_PKCS12 = true;
        final String[] ADD_CM_PROVIDERS = new String[] {
            //"cm-example"
        };
        final boolean ADD_TRUSTED_CERTS = false;
        
        int expected_cnt_cmproviders = 0;
        
        Init.Parameters init_params = new Init.Parameters();
        Assert.assertNotNull(init_params);

        if (ADD_PKCS12) {
            final String p12_cfg = "{\"createPfx\":{\"bagCipher\":\"2.16.840.1.101.3.4.1.22\",\"bagKdf\":\"1.2.840.113549.2.10\","
                    + "\"iterations\":5555,\"macAlgo\":\"2.16.840.1.101.3.4.2.2\"}}";
            init_params.addCmProvider("cm-pkcs12", p12_cfg);
            expected_cnt_cmproviders++;
        }
        for (int i = 0; i < ADD_CM_PROVIDERS.length; i++) {
            init_params.addCmProvider(ADD_CM_PROVIDERS[i]);
            expected_cnt_cmproviders++;
        }

        final ArrayList<PkiData> list_trustedcerts = new ArrayList<>();
        if (INIT_DIR_CERTS != null) {
            if (ADD_TRUSTED_CERTS) {
                list_trustedcerts.add(new PkiData(TestData.B64_CERT_3DA_ROOT_DSTU));
                list_trustedcerts.add(new PkiData(TestData.B64_CERT_3DA_ROOT_ECDSA));
            }
            init_params.setCertCache(INIT_DIR_CERTS, list_trustedcerts);
        }
        if (INIT_DIR_CRLS != null) {
            init_params.setCrlCache(INIT_DIR_CRLS);
        }
        if (INIT_TSP_URL != null) {
            init_params.setTspParameters(INIT_TSP_URL, INIT_TSP_POLICY);
        }

        Init.Result init_result = lib.init(init_params);
        Assert.assertNotNull(init_result);
        Assert.assertNotNull(init_result.getCertCacheInfo());
        Assert.assertNotNull(init_result.getCrlCacheInfo());
        Assert.assertNotNull(init_result.getTspInfo());
        
        System.out.println("getCertCacheInfo().getCountCerts(): " + init_result.getCertCacheInfo().getCountCerts());
        System.out.println("getCertCacheInfo().getCountTrustedCerts(): " + init_result.getCertCacheInfo().getCountTrustedCerts());
        System.out.println("getCrlCacheInfo().getCountCrls(): " + init_result.getCrlCacheInfo().getCountCrls());
        System.out.println("getCountCmProviders(): " + init_result.getCountCmProviders());
        System.out.println("isOffline(): " + init_result.isOffline());
        System.out.println("getTspInfo().getUrl(): " + init_result.getTspInfo().getUrl());
        System.out.println("getTspInfo().getPolicy(): " + init_result.getTspInfo().getPolicy());
        System.out.println("");
        
        Assert.assertEquals(init_result.getCertCacheInfo().getCountTrustedCerts(), list_trustedcerts.size());
        Assert.assertEquals(init_result.getCountCmProviders(), expected_cnt_cmproviders);
        if (INIT_TSP_URL != null) {
            Assert.assertEquals(init_result.getTspInfo().getUrl(), INIT_TSP_URL);
            if (INIT_TSP_POLICY != null) {
                Assert.assertEquals(init_result.getTspInfo().getPolicy(), INIT_TSP_POLICY);
            }
        }
    }

    @AfterClass
    public static void tearDown()  throws Exception {
        lib.deinit();
    }

    @Test
    public void testProviders () throws Exception {
         final List<String> list_providernames = new LinkedList<>();
        final List<Providers.CmProviderInfo> list_providerinfos = lib.getProviders();
        for (Providers.CmProviderInfo provider : list_providerinfos) {
            System.out.println("Key provider info: id = " + provider.getId() + "; version = " + provider.getVersion()
                    + "; description = " + provider.getDescription() + "; manufacturer = " + provider.getManufacturer());
            list_providernames.add(provider.getId());

            // Якщо провайдер підтримує отримання переліку доступних сховищ ключів - отримуємо переік сховищ
            if (provider.isSupportListStorages() == true) {
                final ArrayList<Storages.StorageInfo> storages_info = lib.getStorages(provider.getId());

                // Для кожного сховища отримуємо перелік ключів
                for (Storages.StorageInfo storageInfo : storages_info) {
                    System.out.println("Key storage info: id = " + storageInfo.getId() + "; description = " + storageInfo.getDescription()
                            + "; label = " + storageInfo.getLabel() + "; serial = " + storageInfo.getSerial() );
                }
                System.out.println("");
            }
        }

        System.out.println("List provider names: " + list_providernames);
    }

    @Test
    public void testP12CreateKey () throws Exception {
        final boolean CREATE_DSTU = true;
        final boolean CREATE_ECDSA = true;
        final boolean CREATE_RSA = true;
        final boolean DELETE_KEY = true;
        
        // Створюємо нове сховище ключів (файл-контейнер формату PKCS#12)
        final String provider_id = "PKCS12";
        final String storage_id = testDir + "new-key.p12";
        final String password = "testpassword";
        String openParams = null;
        //openParams = "{\"createPfx\":{\"bagCipher\":\"2.16.840.1.101.3.4.1.22\",\"bagKdf\":\"1.2.840.113549.2.10\",\"iterations\":5555,\"macAlgo\":\"2.16.840.1.101.3.4.2.2\"}}";
        openParams = "{\"createPfx\":{\"bagCipher\":\"2.16.840.1.101.3.4.1.2\",\"bagKdf\":\"1.2.840.113549.2.9\",\"iterations\":777,\"macAlgo\":\"2.16.840.1.101.3.4.2.1\"}}";
        
        StorageInfo storage_info = lib.openStorage(provider_id, storage_id, password, Open.Mode.CREATE, openParams);
        System.out.println("\nNew storage created.");
        System.out.println(" Label: '" + storage_info.getLabel() + "'");
        System.out.println(" Serial: '" + storage_info.getSerial() + "'");
        System.out.println(" Manufacturer: '" + storage_info.getManufacturer() + "'");
        
        PkiOid mechanism_id;
        PkiOid parameter_id;
        KeyId new_keyid = null;

        if (CREATE_DSTU) {
            // Створюємо новий ключ для алгоритму ДСТУ4145 з ГОСТ 34.311 на ЕК М257. Згенерований ключ автоматично стає "обраним"
            mechanism_id = Oids.KeyAlgo.Dstu4145.DSTU4145_WITH_GOST3411;
            parameter_id = Oids.KeyParam.Dstu4145.M257_PB;
            new_keyid = lib.createKey(mechanism_id, parameter_id, "Test key ДСТУ4145");
            System.out.println("Key created. KeyId: '" + new_keyid + "'");

            // Отримуємо запит на формування сертифікату для згенерованого ключа
            PkiData csr = lib.getCsr();
            System.out.println("CSR created: '" + csr + "'");
        }
        
        if (CREATE_ECDSA) {
            mechanism_id = Oids.KeyAlgo.ECDSA;
            parameter_id = Oids.KeyParam.Ecdsa.NIST_P256;
            new_keyid = lib.createKey(mechanism_id, parameter_id, "Test Key ECDSA(P256)");
            System.out.println("Key created. KeyId: '" + new_keyid + "'");
            System.out.println("CSR created: '" + lib.getCsr() + "'");
        }
        
        if (CREATE_RSA) {
            new_keyid = lib.createKey(Oids.KeyAlgo.RSA, 1024, "Test Key RSA(1024)");
            System.out.println("Key created. KeyId: " + new_keyid);
            System.out.println("CSR created: '" + lib.getCsr() + "'");
        }
        
        // Отримуємо перелік ключів у сховищі
        ArrayList<KeyInfo> key_infos = lib.getKeys();
        System.out.println("\nList keys on storage:");
        for (KeyInfo key_info : key_infos) {
            System.out.println(" id: '" + key_info.getId() + "'");
            System.out.println(" mechanismId: '" + key_info.getMechanismId() + "'");
            System.out.println(" parameterId: '" + key_info.getParameterId() + "'");
            System.out.println(" label: '" + key_info.getLabel() + "'");
            System.out.println(" signAlgos: " + key_info.getSignAlgo());
        }
        
        if (DELETE_KEY) {
            lib.deleteKey(new_keyid);
            key_infos = lib.getKeys();
            System.out.println("\nList keys on storage:");
            for (KeyInfo key_info : key_infos) {
                System.out.println(" id: '" + key_info.getId() + "'");
                System.out.println(" mechanismId: '" + key_info.getMechanismId() + "'");
                System.out.println(" parameterId: '" + key_info.getParameterId() + "'");
                System.out.println(" label: '" + key_info.getLabel() + "'");
                System.out.println(" signAlgos: " + key_info.getSignAlgo());
            }
        }

        // Закриваємо сховище
        lib.closeStorage();
        System.out.println("New storage closed\n");
    }
    
    @Test
    public void testCertAPI () throws Exception {
        final boolean ADD_CERTS = true;
        final boolean ADD_BUNDLE_CERTS = false;
        final boolean CERT_INFO_BY_BYTES = false;
        final boolean CERT_INFO_BY_CERTID = true;
        final boolean GET_CERT = false;
        final boolean LIST_CERTS = false;
        final boolean REMOVE_CERT = false;

        CertId certid = null;
        
        if (ADD_CERTS) {
            ArrayList<PkiData> b64_certs = new ArrayList<>();
            b64_certs.add(new PkiData(TestData.B64_CERT_1));
            b64_certs.add(new PkiData(TestData.B64_CERT_2));
            final ArrayList<AddCert.AddedCertInfo> added_certs = lib.addCert(b64_certs, false);
            for (AddCert.AddedCertInfo addedcert_info : added_certs) {
                System.out.println(" getCertId: '" + addedcert_info.getCertId() + "'");
                System.out.println(" isUnique: " + addedcert_info.isUnique());
                certid = addedcert_info.getCertId();
            }
        }
        
        if (ADD_BUNDLE_CERTS) {
            String b64_bundle = TestData.B64_BUNDLE_P7B;
            final ArrayList<AddCert.AddedCertInfo> added_certs = lib.addCert(new PkiData(b64_bundle), false);
            for (AddCert.AddedCertInfo addedcert_info : added_certs) {
                System.out.println(" getCertId: '" + addedcert_info.getCertId() + "'");
                System.out.println(" isUnique: " + addedcert_info.isUnique());
                certid = addedcert_info.getCertId();
            }
        }

        if (CERT_INFO_BY_BYTES && (certid != null)) {
            PkiData cert_bytes = lib.getCert(certid);
            CertInfo.Result cert_info = lib.certInfo(cert_bytes);
            showCert(cert_info);
            System.out.println("");
        }

        if (CERT_INFO_BY_CERTID && (certid != null)) {
            CertInfo.Result cert_info = lib.certInfo(certid);
            showCert(cert_info);
            System.out.println("");
        }

        if (GET_CERT) {
            PkiData cert_bytes = lib.getCert(certid);
            System.out.println("\nGetCert, certid: '" + certid + "'");
            System.out.println(" b64_cert: '" + cert_bytes + "'");
        }
        
        if (LIST_CERTS) {
            ArrayList<CertId> list_certids = lib.listCerts();
            System.out.println("\nlistCerts, count: " + list_certids.size());
            for (CertId cert_id : list_certids) {
                System.out.print("'" + cert_id.toString() + "', ");
            }
            System.out.println("");
            
            ListCerts.Result listcerts_result = lib.listCerts(10, 5);
            System.out.println("\nlistCerts, count: " + listcerts_result.getCount());
            System.out.println(" getOffset: " + listcerts_result.getOffset());
            System.out.println(" getPageSize: " + listcerts_result.getPageSize());
            for (CertId cert_id : listcerts_result.getCertIds()) {
                System.out.print("'" + cert_id.toString() + "', ");
            }
            System.out.println("");
        }

        if (REMOVE_CERT) {
            ArrayList<CertId> list_certids = lib.listCerts();
            System.out.println("\nList certs, count (before): " + list_certids.size());

            lib.removeCert(certid);
            System.out.println("\nRemoved cert from CERT-cache, certid: '" + certid + "'");
            
            list_certids = lib.listCerts();
            System.out.println("\nList certs, count (after): " + list_certids.size());
        }
    }
    
    public void showCert (CertInfo.Result certInfo) throws Exception {
        System.out.println(" getSerialNumber(): '" + certInfo.getSerialNumber() + "'");
        System.out.println(" getIssuer().getCN(): '" + certInfo.getIssuer().getCN() + "'");
        System.out.println(" getIssuer().getO(): '" + certInfo.getIssuer().getO() + "'");
        System.out.println(" getValidity().getNotBefore(): '" + certInfo.getValidity().getNotBefore() + "'");
        System.out.println(" getValidity().getNotAfter(): '" + certInfo.getValidity().getNotAfter() + "'");
        System.out.println(" getSubject().getCN(): '" + certInfo.getSubject().getCN() + "'");
        System.out.println(" getSubject().getO(): '" + certInfo.getSubject().getO() + "'");
        System.out.println(" getSpki().getAlgorithm(): '" + certInfo.getSpki().getAlgorithm() + "'");
        System.out.println(" getSpki().getParameters(): '" + certInfo.getSpki().getParameters()+ "'");
        System.out.println(" getSpki().getPublicKey(): '" + certInfo.getSpki().getPublicKey()+ "'");
        System.out.println(" getSignatureInfo().getAlgorithm(): '" + certInfo.getSignatureInfo().getAlgorithm() + "'");
        System.out.println(" getSignatureInfo().getParameters(): '" + certInfo.getSignatureInfo().getParameters() + "'");
        System.out.println(" getSignatureInfo().getSignature(): '" + certInfo.getSignatureInfo().getSignature() + "'");
        System.out.println(" isSelfSigned(): " + certInfo.isSelfSigned());

        ArrayList<CertInfo.Extension> list_extns = certInfo.getExtensions();
        System.out.println(" Extensions, count: " + list_extns.size());
        for (CertInfo.Extension cert_extn : list_extns) {
            System.out.println("  extnId: '" + cert_extn.getExtnId()+ "', critical: " + cert_extn.isCritical());
            System.out.println("  extnValue: '" + cert_extn.getExtnValue() + "'");
        }
        System.out.println("========================================");
    }
    
    @Test
    public void testCertInfo () throws Exception {
        PkiData cert_bytes = new PkiData(TestData.B64_CERT_1);
        CertInfo.Result cert_info = lib.certInfo(cert_bytes);
        showCert(cert_info);
    }
    
    enum TestVerifyCert {
        FROM_CACHE,
        VALIDATY_BY_CRL,
        VALIDATY_BY_CRL_AND_TIME,
        VALIDATY_BY_ISSUERONLY,
        VALIDATY_BY_OCSP;
    };

    @Test
    public void testVerifyCert () throws Exception {

        TestVerifyCert test = TestVerifyCert.FROM_CACHE;
        test = TestVerifyCert.VALIDATY_BY_CRL;
        //test = TestVerifyCert.VALIDATY_BY_CRL_AND_TIME;
        //test = TestVerifyCert.VALIDATY_BY_ISSUERONLY;
        //test = TestVerifyCert.VALIDATY_BY_OCSP;
        VerifyCert.Result report = null;
        
        System.out.println("testVerifyCert, test: " + test);

        if (test == TestVerifyCert.FROM_CACHE) {
            ArrayList<PkiData> list_certs = new ArrayList<>();
            list_certs.add(new PkiData(TestData.B64_CERT_1));
            final ArrayList<AddCert.AddedCertInfo> added_certs = lib.addCert(list_certs, false);
            CertId certid = added_certs.get(0).getCertId();
            report = lib.verifyCert(certid, VerifyCert.ValidationType.ISSUER_AND_CRL);
            System.out.println("\nVerifyCert");
        }
        
        if (test == TestVerifyCert.VALIDATY_BY_ISSUERONLY) {
            PkiData cert_bytes = new PkiData(TestData.B64_CERT_1);
            report = lib.verifyCert(cert_bytes, VerifyCert.ValidationType.ISSUER_ONLY);
            System.out.println("\nVerifyCert");
        }
        
        if (test == TestVerifyCert.VALIDATY_BY_CRL) {
            PkiData cert_bytes = new PkiData(TestData.B64_CERT_1);
            report = lib.verifyCert(cert_bytes, VerifyCert.ValidationType.ISSUER_AND_CRL);
            System.out.println("\nVerifyCert");
        }
        
        if (test == TestVerifyCert.VALIDATY_BY_CRL_AND_TIME) {
            PkiData cert_bytes = new PkiData(TestData.B64_CERT_1);
            PkiTime validate_time;
            //validate_time = new PkiTime("2020-08-26 20:28:37");
            validate_time = new PkiTime("2020-08-26 20:32:18");
            //validate_time = new PkiTime("2020-08-31 15:59:59");
            //validate_time = new PkiTime("2020-08-31 16:01:09");
            report = lib.verifyCert(cert_bytes, validate_time);
            System.out.println("\nVerifyCert");
        }

        if (test == TestVerifyCert.VALIDATY_BY_OCSP) {
            PkiData cert_bytes = new PkiData(TestData.B64_CERT_1);
            report = lib.verifyCert(cert_bytes, VerifyCert.ValidationType.ISSUER_AND_OCSP);
            System.out.println("\nVerifyCert");
        }

        if (report != null) {
            System.out.println("Certificate Verification Report");
            System.out.println(" getValidateTime(): '" + report.getValidateTime() + "'");
            System.out.println(" getSubjectCertId(): '" + report.getSubjectCertId() + "'");
            System.out.println(" getValidity().getNotBefore(): '" + report.getValidity().getNotBefore() + "'");
            System.out.println(" getValidity().getNotAfter(): '" + report.getValidity().getNotAfter() + "'");
            System.out.println(" isExpired(): " + report.isExpired());
            System.out.println(" isSelfSigned(): " + report.isSelfSigned());
            System.out.println(" getStatusSignature(): '" + report.getStatusSignature() + "'");
            System.out.println(" getIssuerCertId()): '" + report.getIssuerCertId() + "'");
            if (report.getValidateByCrl() != null) {
                ValidateRevocation.ValidateByCrl validate_by_crl = report.getValidateByCrl();
                System.out.println(" getStatus(): '" + validate_by_crl.getStatus() + "'");
                System.out.println(" getRevocationReason(): '" + validate_by_crl.getRevocationReason() + "'");
                System.out.println(" getRevocationTime(): '" + validate_by_crl.getRevocationTime() + "'");
                System.out.println(" getFull().getUrl(): '" + validate_by_crl.getFull().getUrl() + "'");
                System.out.println(" getFull().getCrlId(): '" + validate_by_crl.getFull().getCrlId() + "'");
                System.out.println(" getFull().getStatusSignature(): '" + validate_by_crl.getFull().getStatusSignature()+ "'");
                System.out.println(" getDelta().getUrl(): '" + validate_by_crl.getDelta().getUrl() + "'");
                System.out.println(" getDelta().getCrlId(): '" + validate_by_crl.getDelta().getCrlId() + "'");
                System.out.println(" getDelta().getStatusSignature(): '" + validate_by_crl.getDelta().getStatusSignature()+ "'");
            }
            if (report.getValidateByOcsp() != null) {
                ValidateRevocation.ValidateByOcsp validate_by_ocsp = report.getValidateByOcsp();
                System.out.println(" getStatus(): '" + validate_by_ocsp.getStatus() + "'");
                System.out.println(" getRevocationReason(): '" + validate_by_ocsp.getRevocationReason() + "'");
                System.out.println(" getRevocationTime(): '" + validate_by_ocsp.getRevocationTime() + "'");
                System.out.println(" getResponseStatus(): '" + validate_by_ocsp.getResponseStatus() + "'");
                System.out.println(" getResponderId(): '" + validate_by_ocsp.getResponderId() + "'");
                System.out.println(" getStatusSignature(): '" + validate_by_ocsp.getStatusSignature() + "'");
                System.out.println(" getProducedAt(): '" + validate_by_ocsp.getProducedAt() + "'");
                System.out.println(" getThisUpdate(): '" + validate_by_ocsp.getThisUpdate() + "'");
                System.out.println(" getNextUpdate(): '" + validate_by_ocsp.getNextUpdate() + "'");
            }
            System.out.println(" getReportTime(): '" + report.getReportTime() + "'");
        }
    }
    
    @Test
    public void testCrlAPI () throws Exception {
        
        final boolean ADD_CRL = true;
        final boolean CRL_INFO_BY_BYTES = true;
        final boolean CRL_INFO_BY_CRLID = false;
        
        CrlId crlid = null;
        
        if (ADD_CRL) {
            String b64_crl = TestData.B64_CRL_FULL_25_REVOKEDCERTS;
            AddCrl.Result added_crl = lib.addCrl(new PkiData(b64_crl), false);
            System.out.println(" getCrlId: '" + added_crl.getCrlId().toString() + "'");
            System.out.println(" isUnique: " + added_crl.isUnique());
            crlid = added_crl.getCrlId();

            b64_crl = TestData.B64_CRL_DELTA_0_REVOKEDCERTS;
            added_crl = lib.addCrl(new PkiData(b64_crl), false);
            System.out.println(" getCrlId: '" + added_crl.getCrlId().toString() + "'");
            System.out.println(" isUnique: " + added_crl.isUnique());
        }

        if (CRL_INFO_BY_BYTES && (crlid != null)) {//TODO
            PkiData crl = new PkiData(TestData.B64_CRL_FULL_25_REVOKEDCERTS);
            CrlInfo.Result crl_info = lib.crlInfo(crl);
            System.out.println("\nCrlInfo:");
            System.out.println(" getIssuer.getCN: '" + crl_info.getIssuer().getCN() + "'");
            System.out.println(" getIssuer.getO: '" + crl_info.getIssuer().getO() + "'");
            System.out.println(" getThisUpdate: '" + crl_info.getThisUpdate() + "'");
            System.out.println(" getNextUpdate: '" + crl_info.getNextUpdate() + "'");
            System.out.println(" getCountRevokedCerts: " + crl_info.getCountRevokedCerts());
            System.out.println(" getAuthorityKeyId: '" + crl_info.getAuthorityKeyId() + "'");
            System.out.println(" getCrlNumber: '" + crl_info.getCrlNumber() + "'");
            System.out.println(" GetDeltaCrlIndicator: '" + crl_info.getDeltaCrlIndicator()+ "' (optional)");
            System.out.println(" isDeltaCrl: " + crl_info.isDeltaCrl());
            if (crl_info.getRevokedCerts() != null) {
                for (CrlInfo.RevokedCert revoked_cert: crl_info.getRevokedCerts()) {
                    System.out.println("getUserCertificate: '" + revoked_cert.getUserCertificate() + "'");
                    System.out.println("getRevocationDate: '" + revoked_cert.getRevocationDate() + "'");
                    System.out.println("getCrlReason: '" + revoked_cert.getCrlReason() + "' (optional)");
                    System.out.println("getInvalidityDate: '" + revoked_cert.getInvalidityDate() + "' (optional)");
                    System.out.println("========================================");
                }
            }
            System.out.println("");

            crl = new PkiData(TestData.B64_CRL_DELTA_0_REVOKEDCERTS);
            crl_info = lib.crlInfo(crl);
            System.out.println("\nCrlInfo:");
            System.out.println(" getIssuer.getCN: '" + crl_info.getIssuer().getCN() + "'");
            System.out.println(" getIssuer.getO: '" + crl_info.getIssuer().getO() + "'");
            System.out.println(" getThisUpdate: '" + crl_info.getThisUpdate() + "'");
            System.out.println(" getNextUpdate: '" + crl_info.getNextUpdate() + "'");
            System.out.println(" getCountRevokedCerts: " + crl_info.getCountRevokedCerts());
            System.out.println(" getAuthorityKeyId: '" + crl_info.getAuthorityKeyId() + "'");
            System.out.println(" getCrlNumber: '" + crl_info.getCrlNumber() + "'");
            System.out.println(" GetDeltaCrlIndicator: '" + crl_info.getDeltaCrlIndicator() + "' (optional)");
            System.out.println(" isDeltaCrl: " + crl_info.isDeltaCrl());
            if (crl_info.getRevokedCerts() != null) {
                for (CrlInfo.RevokedCert revoked_cert: crl_info.getRevokedCerts()) {
                    System.out.println("getUserCertificate: '" + revoked_cert.getUserCertificate() + "'");
                    System.out.println("getRevocationDate: '" + revoked_cert.getRevocationDate() + "'");
                    System.out.println("getCrlReason: '" + revoked_cert.getCrlReason() + "' (optional)");
                    System.out.println("getInvalidityDate: '" + revoked_cert.getInvalidityDate() + "' (optional)");
                    System.out.println("========================================");
                }
            }
            System.out.println("");
        }

        if (CRL_INFO_BY_CRLID && (crlid != null)) {//TODO
            CrlInfo.Result crl_info = lib.crlInfo(crlid);
            System.out.println(" crlInfo.getCrlNumber: '" + crl_info.getCrlNumber()+ "'");
        }

        //TODO

    }
    
    public void showReportVerify (Verify.Result report) throws Exception {
        Gson gson = new Gson();
        System.out.println("showReportVerify");
        System.out.println(" getContent().getType(): '" + report.getContent().getType() + "'");
        System.out.println(" getContent().getBytes(): '" + report.getContent().getBytes() + "' (optional)");
        System.out.println(" getCertIds(): " + report.getCertIds());
        Verify.SignatureInfo sign_info = report.getSignatureInfo();
        if (sign_info != null) {
            System.out.println("SignatureInfo:");
            System.out.println("  getSignerCertId(): " + sign_info.getSignerCertId());
            System.out.println("  getStatus(): '" + sign_info.getStatus() + "'");
            System.out.println("  getStatusSignature(): '" + sign_info.getStatusSignature() + "'");
            System.out.println("  getStatusMessageDigest(): '" + sign_info.getStatusMessageDigest() + "'");
            System.out.println("  getStatusEssCert(): '" + sign_info.getStatusEssCert() + "' (optional)");
            System.out.println("  getSigningTime(): '" + sign_info.getSigningTime() + "' (optional)");
            if (sign_info.getContentTS() != null) {
                Verify.TimestampInfo ts_info = sign_info.getContentTS();
                System.out.println("  getContentTS():");
                System.out.println("   getGenTime(): '" + ts_info.getGenTime() + "'");
                System.out.println("   getPolicy(): '" + ts_info.getPolicy()+ "'");
                System.out.println("   getStatusDigest(): '" + ts_info.getStatusDigest()+ "'");
                System.out.println("   getHashAlgo(): '" + ts_info.getHashAlgo()+ "' (optional/ifvalid)");
                System.out.println("   getHashedMessage(): '" + ts_info.getHashedMessage()+ "' (optional/ifvalid)");
            }
            if (sign_info.getSignatureTS() != null) {
                Verify.TimestampInfo ts_info = sign_info.getSignatureTS();
                System.out.println("  getSignatureTS():");
                System.out.println("   getGenTime(): '" + ts_info.getGenTime() + "'");
                System.out.println("   getPolicy(): '" + ts_info.getPolicy()+ "'");
                System.out.println("   getStatusDigest(): '" + ts_info.getStatusDigest()+ "'");
                System.out.println("   getHashAlgo(): '" + ts_info.getHashAlgo()+ "' (optional/ifvalid)");
                System.out.println("   getHashedMessage(): '" + ts_info.getHashedMessage()+ "' (optional/ifvalid)");
            }
            
            System.out.println("  getSignedAttributes(): " + gson.toJson(sign_info.getSignedAttributes()));
            System.out.println("  getUnsignedAttributes(), (optional): " + gson.toJson(sign_info.getUnsignedAttributes()));
        }
        System.out.println(" getReportTime(): '" + report.getReportTime() + "'");
    }

    @Test
    public void testSign () throws Exception {
        Gson gson = new Gson();

        final String PROVIDER_ID = "PKCS12";        
        final String PASSWORD = "testpassword";
        final String OPEN_PARAMS = "{\"bytes\":\"" + TestData.B64_PFX_AUGUSTO + "\"}";

        SignatureFormat sign_format = SignatureFormat.CADES_BES;
        PkiOid use_signalgo;
        use_signalgo = Oids.SignAlgo.Dstu4145.DSTU4145_WITH_GOST3411;

        lib.openStorage(PROVIDER_ID, "", PASSWORD, Open.Mode.RO, OPEN_PARAMS);

        System.out.println("\nStorage is opened.");
        System.out.println("List keys on storage: " + lib.getKeys().size());
        KeyId selected_keyid = lib.getKeys().get(0).getId();       
        System.out.println("SelectKey, keyId: " + selected_keyid);
        SelectKey.Result selectkey_result = lib.selectKey(selected_keyid);
        System.out.println("\nKey is selected.");
        if (selectkey_result.getCertificate() != null) {
            System.out.println("Certificate present");
            
            Sign.SignParams sign_params = new Sign.SignParams(sign_format);
            sign_params.SetDetachedData(true);
            sign_params.SetIncludeCert(true);
            sign_params.SetIncludeTime(true);
            sign_params.SetIncludeContentTS(false);
            if (use_signalgo != null) sign_params.SetSignAlgo(use_signalgo);
            
            PkiData content, digest_of_content;
            ArrayList<Sign.DataTbs> list_datatbses = new ArrayList<>();
            content = new PkiData(TestData.B64_WIKI_ALICE_AND_BOB);
            list_datatbses.add(new Sign.DataTbs("doc-1-data", content));
            digest_of_content = new PkiData("VFA1oGKgmZ3NirmGM+tEbEuEIluqLoUT7kaigCVyrBc=");
            list_datatbses.add(new Sign.DataTbs("doc-2-digest-of-data", digest_of_content, true));
            
            ArrayList<Document> signed_docs = lib.sign(sign_params, list_datatbses);
            System.out.println("Data signed: " + gson.toJson(signed_docs) + "\n");
            for (Document it : signed_docs) {
                System.out.println(" getId(): '" + it.getId() + "'  getBytes(): '" + it.getBytes() + "'");
            }

            System.out.println("\n========================================");
            for (int i = 0; i < signed_docs.size(); i++) {
                boolean is_digest = (i > 0);
                System.out.println("Verify id-signed-doc[" + i + "]: '" + signed_docs.get(i).getId() + "'");
                Verify.Result report = lib.verify(signed_docs.get(i).getBytes(), is_digest ? content : digest_of_content, is_digest);
                showReportVerify(report);
                System.out.println("\n========================================");
            }
        }
    }

    @Test
    public void testSignP12 () throws Exception {
        Gson gson = new Gson();

        final String PROVIDER_ID = "PKCS12";
        final String PASSWORD = "testpassword";
        final Boolean USE_PFX_FILE = true;

        String STORAGE_FILE = "";
        if (USE_PFX_FILE) STORAGE_FILE = testDir + "test-dstu-augusto.p12";

        SignatureFormat test_signformat = SignatureFormat.CADES_BES;
        //test_sign_format = SignatureFormat.CMS;
        PkiOid use_signalgo;
        use_signalgo = Oids.SignAlgo.Dstu4145.DSTU4145_WITH_GOST3411;
        final int TEST_CASE = 2+0;

        PkiData signed_data, original_content;

        // Відкриваємо сховище з ключем для якого вже є сертифікат
        if (USE_PFX_FILE) {
            lib.openStorage(PROVIDER_ID, STORAGE_FILE, PASSWORD, Open.Mode.RO);
        }
        else {
            String OPEN_PARAMS = "{\"bytes\":\"" + TestData.B64_PFX_AUGUSTO + "\"}";
            lib.openStorage(PROVIDER_ID, "", PASSWORD, Open.Mode.RO, OPEN_PARAMS);
        }
        System.out.println("\nStorage is opened.");

        // Отримуємо перелік ключів у сховищі
        final ArrayList<KeyInfo> key_infos = lib.getKeys();
        System.out.println("\nList keys on storage:");
        for (KeyInfo key_info : key_infos) {
            System.out.println(" id: '" + key_info.getId() + "'");
            System.out.println(" mechanismId: '" + key_info.getMechanismId() + "'");
            System.out.println(" parameterId: '" + key_info.getParameterId() + "'");
            System.out.println(" label: '" + key_info.getLabel() + "'");
            System.out.println(" signAlgos: " + key_info.getSignAlgo());
        }

        // Обираємо перший ключ у сховищі
        KeyId selected_keyid = key_infos.get(0).getId();
        System.out.println("\nSelectKey, keyId: " + selected_keyid);
        SelectKey.Result selectkey_result = lib.selectKey(selected_keyid);
        System.out.println(" getKeyMechanisms: " + selectkey_result.getKeyMechanisms());
        System.out.println(" getSignAlgo: " + selectkey_result.getSignAlgo());
        System.out.println(" getCertId: '" + selectkey_result.getCertId().toString() + "'");
        System.out.println(" getCertificate: '" + selectkey_result.getCertificate() + "'");
        System.out.println(" isExportable: " + selectkey_result.isExportable());

        // Якщо для обраного ключа знайдено сертифікат виконуємо наступні тести
        if (selectkey_result.getCertificate() != null) {
            System.out.println("Certificate present");

            // Отримуємо інформацію з сертифікату (виводимо тільки одне поле)
            CertInfo.Result cert_info = lib.certInfo(selectkey_result.getCertificate());
            System.out.println("Certificate info: " + gson.toJson(cert_info) + "\n");

            if ((TEST_CASE == 1) || (TEST_CASE == 2)) {
                // Створюємо запит на формування підпису. Інші параметри встановлені конструктором за замовчанням. Можна змінювати
                Sign.SignParams sign_params = new Sign.SignParams(test_signformat);
                if (TEST_CASE == 2) {
                    sign_params.SetDetachedData(false);
                    sign_params.SetIncludeCert(true);
                    sign_params.SetIncludeTime(true);
                    if (use_signalgo != null) sign_params.SetSignAlgo(use_signalgo);
                }

                // Дані для підпису. За одне звернення до функції формування підпису можна підписати декілька документів
                PkiData content;
                ArrayList<Sign.DataTbs> list_datatbses = new ArrayList<>();
                content = new PkiData(TestData.B64_WIKI_ALICE_AND_BOB);
                list_datatbses.add(new Sign.DataTbs("doc-1", content));
                content = new PkiData("0JvQsNCz0ZbQtNC90LAg0YPQutGA0LDRl9C90ZbQt9Cw0YbRltGP");
                list_datatbses.add(new Sign.DataTbs("doc-2", content));
                content = new PkiData("VGhpcyBpcyBiYXNlNjQgZW5jb2RlZCBkb2N1bWVudCBjb250ZW50Lg==");
                Sign.DataTbs data_tbs = new Sign.DataTbs("doc-3 with custom Signed Attribute (oid: 1.2.3, value: integer 1)", content);
                data_tbs.addSignedAttribute(new Attribute(new PkiOid("1.2.3"), new PkiData("AgEB")));
                list_datatbses.add(data_tbs);

                // Виконуємо підпис
                ArrayList<Document> signed_docs = lib.sign(sign_params, list_datatbses);
                System.out.println("Data signed: " + gson.toJson(signed_docs) + "\n");
                for (Document it : signed_docs) {
                    System.out.println(" getId(): '" + it.getId() + "'  getBytes(): '" + it.getBytes() + "'");
                }

                //  Save info for verify signedData
                signed_data = signed_docs.get(signed_docs.size() - 1).getBytes();
                original_content = content;
            }
            else {
                // Створюємо запит на формування підпису. Інші параметри встановлені конструктором за замовчанням. Можна змінювати
                Sign.Parameters sign_parameters  = new Sign.Parameters(test_signformat);
                if (TEST_CASE == 4) {
                    sign_parameters.getSignParams().SetDetachedData(false);
                    sign_parameters.getSignParams().SetIncludeCert(true);
                    sign_parameters.getSignParams().SetIncludeTime(true);
                }

                // Додаємо дані для підпису до запиту на підпис. За одне звернення до функції формування підпису можна підписати декілька документів
                PkiData content;
                content = new PkiData("QWxpY2UgYW5kIEJvYgpodHRwczovL2VuLndpa2lwZWRpYS5vcmcvd2lraS9BbGljZV9hbmRfQm9i");
                sign_parameters.addDocument("doc-1", content);
                content = new PkiData("0JvQsNCz0ZbQtNC90LAg0YPQutGA0LDRl9C90ZbQt9Cw0YbRltGP");
                sign_parameters.addDocument("doc-2", content);
                content = new PkiData("VGhpcyBpcyBiYXNlNjQgZW5jb2RlZCBkb2N1bWVudCBjb250ZW50Lg==");
                Sign.DataTbs data_tbs = new Sign.DataTbs("doc-3 with custom Attributes (2 signed, 1 unsigned)", content);
                data_tbs.addSignedAttribute(new Attribute(new PkiOid("1.2.3"), new PkiData("AgEB")));
                data_tbs.addSignedAttribute(new Attribute(new PkiOid("1.2.3.4"), new PkiData("AQH/")));
                data_tbs.addUnsignedAttribute(new Attribute(new PkiOid("1.2.3.4.5"), new PkiData("AgEC")));
                sign_parameters.addDocument(data_tbs);

                // Виконуємо підпис
                System.out.println("Signature request: " + gson.toJson(sign_parameters));
                ArrayList<Document> signed_datas = lib.sign(sign_parameters);
                System.out.println("Data signed: " + gson.toJson(signed_datas) + "\n");

                //  Save info for verify signedData
                signed_data = signed_datas.get(signed_datas.size() - 1).getBytes();
                original_content = content;
            }

            // Отримуємо підпис та перевіряємо його
            Verify.Result report = lib.verify(signed_data, original_content);
            showReportVerify(report);

            /*
            // Перевіряємо чинність сертифікату за OCSP
            CertificateVerificationReport certificateVerificationReport = lib.verifyCert(keyId, ValidationType.issuerAndOcsp);
            System.out.println("Verify certificate status by OCSP: " + certificateVerificationReport.validateByOCSP().getStatus());
            System.out.println("Full certificate verification report: " + gson.toJson(certificateVerificationReport) + "\n");

            // Перевіряємо чинність сертифікату за CRL
            certificateVerificationReport = lib.verifyCert(keyId, ValidationType.issuerAndCrl);
            System.out.println("Verify certificate status by CRL: " + certificateVerificationReport.validateByCRL().getStatus());
            System.out.println("Full certificate verification report: " + gson.toJson(certificateVerificationReport) + "\n");

            // Перевіряємо чинність сертифікату за CRL на визначений час (у разі наявності мітки часу від підпису)
            certificateVerificationReport = lib.verifyCert(keyId, "2020-08-31 16:00:00");
            System.out.println("Verify certificate status at time 2020-08-31 16:00:00: " + certificateVerificationReport.validateByCRL().getStatus() + " reason: " + certificateVerificationReport.validateByCRL().getRevocationReason());
            System.out.println("Full certificate verification report: " + gson.toJson(certificateVerificationReport) + "\n");*/
        }

        // Закриваємо сховище ключів
        lib.closeStorage();

        // Деініціалізуємо бібліотеку
        lib.deinit();
    }
   
    @Test
    public void testVerify () throws Exception {
        Gson gson = new Gson();

        final boolean USE_DETACHED_DATA = false;

        PkiData signeddata, content = null;
        signeddata = new PkiData(TestData.B64_P7S_DSTU_WITH_TS);
        //signeddata = new PkiData(TestData.B64_P7S_DSTU_DETACHED);
        //signeddata = new PkiData(TestData.B64_P7S_DSTU_CMS);
        //signeddata = new PkiData(TestData.B64_P7S_DSTU_DETACHED_WO_TIME);
        if (USE_DETACHED_DATA) {
            content = new PkiData(TestData.B64_P7S_DSTU_DETACHED_CONTENT);
            //content = new PkiData(TestData.B64_P7S_DSTU_DETACHED_WO_TIME_CONTENT);
        }

        Verify.Result report = lib.verify(signeddata, content);
        showReportVerify(report);
    }
    
    @Test
    public void testDigest () throws Exception {

        String file = WORK_DIR + "test-fox.txt";
        PkiOid hashalgo = Oids.HashAlgo.Sha2.SHA256;
        PkiOid signalgo = Oids.SignAlgo.Ecdsa.ECDSA_WITH_SHA256;
        PkiData bytes = new PkiData(TestData.B64_THE_QUICK_BROWN_FOX);

        Digest.Result digest_result;
        
        digest_result = lib.digest(hashalgo, bytes);
        System.out.println("Digest(hashAlgo: '" + hashalgo + "', bytes):");
        System.out.println(" getHashAlgo(): '" + digest_result.getHashAlgo() + "'");
        System.out.println(" getBytes(): '" + digest_result.getBytes() + "'\n");
        
        digest_result = lib.digest(hashalgo, file);
        System.out.println("Digest(hashAlgo: '" + hashalgo + "', file: '" + file + "'):");
        System.out.println(" getHashAlgo(): '" + digest_result.getHashAlgo() + "'");
        System.out.println(" getBytes(): '" + digest_result.getBytes() + "'\n");
        
        digest_result = lib.digest(bytes, signalgo);
        System.out.println("Digest(bytes, signAlgo: '" + hashalgo + "'):");
        System.out.println(" getHashAlgo(): '" + digest_result.getHashAlgo() + "'");
        System.out.println(" getBytes(): '" + digest_result.getBytes() + "'\n");

        digest_result = lib.digest(file, signalgo);
        System.out.println("Digest(file: '" + file + "', signAlgo: '" + hashalgo + "'):");
        System.out.println(" getHashAlgo(): '" + digest_result.getHashAlgo() + "'");
        System.out.println(" getBytes(): '" + digest_result.getBytes() + "'\n");
    }

    @Test
    public void testEnum () throws Exception {
        Gson gson = new Gson();

        System.out.println("CertificateRevocationStatus: " + gson.toJson(CertificateRevocationStatus.values()));
        System.out.println("OcspResponseStatus: " + gson.toJson(OcspResponseStatus.values()));
        System.out.println("RevocationReason: " + gson.toJson(RevocationReason.values()));
        System.out.println("SignatureFormat: " + gson.toJson(SignatureFormat.values()));
        System.out.println("SignatureValidationStatus: " + gson.toJson(SignatureValidationStatus.values()));
        System.out.println("VerificationStatus: " + gson.toJson(VerificationStatus.values()));

        {
            SignatureFormat s_format = SignatureFormat.CADES_BES;
            System.out.println("\ns_format: '" + s_format + "'");
            s_format = SignatureFormat.fromString("CAdES-T");
            System.out.println("s_format: '" + s_format + "'");
            s_format = SignatureFormat.fromString("CAdES-new");
            System.out.println("s_format: '" + s_format + "'");
        }
        
        {
            RevocationReason r_reason = RevocationReason.REMOVE_FROM_CRL;
            System.out.println("\nr_reason: '" + r_reason + "'");
            r_reason = RevocationReason.fromString("KEY_COMPROMISE");
            System.out.println("r_reason: '" + r_reason + "'");
            r_reason = RevocationReason.fromString("Reason-new");
            System.out.println("r_reason: '" + r_reason + "'");
        }

    }

}
