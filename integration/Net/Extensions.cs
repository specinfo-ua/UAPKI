using System.Resources;
using static UapkiNet.Uapki;

namespace UapkiNet;

public static class Extensions
{
    public static string DisplayName(this Enum e)
    {
        var rm = new ResourceManager(typeof(UapkiResources));
        var resourceDisplayName = rm.GetString(e.GetType().Name + "_" + e);

        return string.IsNullOrWhiteSpace(resourceDisplayName) ? string.Format("[[{0}]]", e) : resourceDisplayName;
    }

    public static string DisplayName(this KeyUsage usage)
    {
        switch (usage)
        {
            case KeyUsage.Signature: return "Підпис";
            case KeyUsage.KeyAgreement: return "Узгодження ключів";
        }
        return "";
    }

    public static string Oid(this KeyAlgo algo)
    {
        switch (algo)
        {
            case KeyAlgo.Dstu4145: return "1.2.804.2.1.1.1.1.3.1";
            case KeyAlgo.Ecdsa: return "1.2.840.10045.2.1";
            case KeyAlgo.Rsa: return "1.2.840.113549.1.1.1";
        }
        throw new UapkiException("Непідтримуваний алгоритм ключа");
    }

    public static string Oid(this KeyParameter param)
    {
        switch (param)
        {
            case KeyParameter.M233_PB: return "1.2.804.2.1.1.1.1.3.1.1.2.5";
            case KeyParameter.M257_PB: return "1.2.804.2.1.1.1.1.3.1.1.2.6";
            case KeyParameter.M307_PB: return "1.2.804.2.1.1.1.1.3.1.1.2.7";
            case KeyParameter.M367_PB: return "1.2.804.2.1.1.1.1.3.1.1.2.8";
            case KeyParameter.M431_PB: return "1.2.804.2.1.1.1.1.3.1.1.2.9";
            case KeyParameter.P256: return "1.2.840.10045.3.1.7";
            case KeyParameter.P384: return "1.3.132.0.34";
            case KeyParameter.P521: return "1.3.132.0.35";
            case KeyParameter.RSA1024: return "1024";
            case KeyParameter.RSA1536: return "1536";
            case KeyParameter.RSA2048: return "2048";
            case KeyParameter.RSA3072: return "3072";
            case KeyParameter.RSA4096: return "4096";
        }
        throw new UapkiException("Непідтримуваний параметр ключа");
    }

    public static string Oid(this SignAlgo algo)
    {
        switch (algo)
        {
            case SignAlgo.Dstu4145_Gost34311: return "1.2.804.2.1.1.1.1.3.1.1";
            case SignAlgo.Dstu4145_Kupyna256: return "1.2.804.2.1.1.1.1.3.6.1.1";
            case SignAlgo.Dstu4145_Kupyna384: return "1.2.804.2.1.1.1.1.3.6.2.1";
            case SignAlgo.Dstu4145_Kupyna512: return "1.2.804.2.1.1.1.1.3.6.3.1";

            case SignAlgo.Ecdsa_Sha: return "1.2.840.10045.4.1";
            case SignAlgo.Ecdsa_Sha224: return "1.2.840.10045.4.3.1";
            case SignAlgo.Ecdsa_Sha256: return "1.2.840.10045.4.3.2";
            case SignAlgo.Ecdsa_Sha384: return "1.2.840.10045.4.3.3";
            case SignAlgo.Ecdsa_Sha512: return "1.2.840.10045.4.3.4";

            case SignAlgo.RsaPkcs_Sha: return "1.2.840.113549.1.1.5";
            case SignAlgo.RsaPkcs_Sha224: return "1.2.840.113549.1.1.14";
            case SignAlgo.RsaPkcs_Sha256: return "1.2.840.113549.1.1.11";
            case SignAlgo.RsaPkcs_Sha384: return "1.2.840.113549.1.1.12";
            case SignAlgo.RsaPkcs_Sha512: return "1.2.840.113549.1.1.13";

            case SignAlgo.RsaPss: return "1.2.840.113549.1.1.10";
        }
        throw new UapkiException("Непідтримуваний алгоритм підпису");
    }

    public static string Oid(this HashAlgo algo)
    {
        switch (algo)
        {
            case HashAlgo.Gost34311: return "1.2.804.2.1.1.1.1.2.1";
            case HashAlgo.Kupyna256: return "1.2.804.2.1.1.1.1.2.2.1";
            case HashAlgo.Kupyna384: return "1.2.804.2.1.1.1.1.2.2.2";
            case HashAlgo.Kupyna512: return "1.2.804.2.1.1.1.1.2.2.3";

            case HashAlgo.Sha: return "1.3.14.3.2.26";

            case HashAlgo.Sha224: return "2.16.840.1.101.3.4.2.4";
            case HashAlgo.Sha256: return "2.16.840.1.101.3.4.2.1";
            case HashAlgo.Sha384: return "2.16.840.1.101.3.4.2.2";
            case HashAlgo.Sha512: return "2.16.840.1.101.3.4.2.3";

            case HashAlgo.Sha3_224: return "2.16.840.1.101.3.4.2.7";
            case HashAlgo.Sha3_256: return "2.16.840.1.101.3.4.2.8";
            case HashAlgo.Sha3_384: return "2.16.840.1.101.3.4.2.9";
            case HashAlgo.Sha3_512: return "2.16.840.1.101.3.4.2.10";
        }
        throw new UapkiException("Непідтримуваний алгоритм гешування");
    }

    public static KeyAlgo ToKeyAlgo(this string oid)
    {
        if (oid.StartsWith("1.2.804.2.1.1.1.1.3")) return KeyAlgo.Dstu4145;
        switch (oid)
        {
            case "1.2.840.10045.2.1": return KeyAlgo.Ecdsa;
            case "1.2.840.113549.1.1.1": return KeyAlgo.Rsa;
            default: return KeyAlgo.Unsupported;
        }
    }

    public static KeyParameter ToKeyParameter(this string value)
    {
        switch (value)
        {
            case "1.2.804.2.1.1.1.1.3.1.1.2.5": return KeyParameter.M233_PB;
            case "1.2.804.2.1.1.1.1.3.1.1.2.6": return KeyParameter.M257_PB;
            case "1.2.804.2.1.1.1.1.3.1.1.2.7": return KeyParameter.M307_PB;
            case "1.2.804.2.1.1.1.1.3.1.1.2.8": return KeyParameter.M367_PB;
            case "1.2.804.2.1.1.1.1.3.1.1.2.9": return KeyParameter.M431_PB;
            case "1.2.840.10045.3.1.7": return KeyParameter.P256;
            case "1.3.132.0.34": return KeyParameter.P384;
            case "1.3.132.0.35": return KeyParameter.P521;
            case "1024": return KeyParameter.RSA1024;
            case "1536": return KeyParameter.RSA1536;
            case "2048": return KeyParameter.RSA2048;
            case "3072": return KeyParameter.RSA3072;
            case "4096": return KeyParameter.RSA4096;
        }
        throw new UapkiException("Непідтримуваний параметр ключа");
    }

    public static KeyParameter DerToKeyParameter(this byte[] value, KeyAlgo algo)
    {
        if (algo == KeyAlgo.Dstu4145)
            return DstuParameters.GetKeyParameterByValue(value);

        if (algo == KeyAlgo.Ecdsa)
        {
            byte[] P256_OID = { 0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07 };
            byte[] P384_OID = { 0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x22 };
            byte[] P521_OID = { 0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x23 };
            if (value.SequenceEqual(P256_OID)) return KeyParameter.P256;
            if (value.SequenceEqual(P384_OID)) return KeyParameter.P384;
            if (value.SequenceEqual(P521_OID)) return KeyParameter.P521;
        }

        return KeyParameter.Unsupported;
    }

    public static SignAlgo ToSignAlgo(this string oid)
    {
        if (oid.StartsWith("1.2.804.2.1.1.1.1.3.6.1")) return SignAlgo.Dstu4145_Kupyna256;
        if (oid.StartsWith("1.2.804.2.1.1.1.1.3.6.2")) return SignAlgo.Dstu4145_Kupyna384;
        if (oid.StartsWith("1.2.804.2.1.1.1.1.3.6.3")) return SignAlgo.Dstu4145_Kupyna512;
        switch (oid)
        {
            case "1.2.804.2.1.1.1.1.3.1.1": return SignAlgo.Dstu4145_Gost34311;

            case "1.2.840.10045.4.1": return SignAlgo.Ecdsa_Sha;
            case "1.2.840.10045.4.3.1": return SignAlgo.Ecdsa_Sha224;
            case "1.2.840.10045.4.3.2": return SignAlgo.Ecdsa_Sha256;
            case "1.2.840.10045.4.3.3": return SignAlgo.Ecdsa_Sha384;
            case "1.2.840.10045.4.3.4": return SignAlgo.Ecdsa_Sha512;

            case "1.2.840.113549.1.1.5": return SignAlgo.RsaPkcs_Sha;
            case "1.2.840.113549.1.1.14": return SignAlgo.RsaPkcs_Sha224;
            case "1.2.840.113549.1.1.11": return SignAlgo.RsaPkcs_Sha256;
            case "1.2.840.113549.1.1.12": return SignAlgo.RsaPkcs_Sha384;
            case "1.2.840.113549.1.1.13": return SignAlgo.RsaPkcs_Sha512;

            case "1.2.840.113549.1.1.10": return SignAlgo.RsaPss;

            default: return SignAlgo.Unsupported;
        }
    }
}
