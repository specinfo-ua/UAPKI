using System.Text.Encodings.Web;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace UapkiNet.JsonConverters;

[JsonSerializable(typeof(Uapki.DistinguishedName))]
internal partial class JsonCtx : JsonSerializerContext
{
}

internal class KeyIdOrDistinguishedNameConverter : JsonConverter<Uapki.OcspResponderIdentifier>
{
    private  JsonCtx jsonCtx = new JsonCtx(new JsonSerializerOptions
    {
        PropertyNamingPolicy = null,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
        Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
        WriteIndented = false
    });

    public override Uapki.OcspResponderIdentifier Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
    {
        if (reader.TokenType == JsonTokenType.String)
            return new Uapki.OcspResponderIdentifier() { IdByKeyId = reader.GetString() };
        else if (reader.TokenType == JsonTokenType.StartObject)
            return new Uapki.OcspResponderIdentifier() { IdByName = JsonSerializer.Deserialize(ref reader, jsonCtx.DistinguishedName) };
        else
            throw new JsonException("Unexpected JSON token for 'details'");
    }

    public override void Write(Utf8JsonWriter writer, Uapki.OcspResponderIdentifier value, JsonSerializerOptions options)
    {
        if (value.IdByKeyId is not null)
            writer.WriteStringValue(value.IdByKeyId);
        else if (value.IdByName is not null)
            JsonSerializer.Serialize(writer, value.IdByName, jsonCtx.DistinguishedName);
        else
            writer.WriteNullValue();
    }
}
