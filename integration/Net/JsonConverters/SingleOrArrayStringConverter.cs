using System.Text.Json.Serialization;
using System.Text.Json;

namespace UapkiNet.JsonConverters;

public sealed class SingleOrArrayStringConverter : JsonConverter<List<string>>
{
    public SingleOrArrayStringConverter()
    {
    }

    public override List<string>? Read(
        ref Utf8JsonReader reader,
        Type typeToConvert,
        JsonSerializerOptions options)
    {
        var result = new List<string>();

        if (reader.TokenType == JsonTokenType.StartArray)
        {
            while (reader.Read())
            {
                if (reader.TokenType == JsonTokenType.EndArray)
                    break;
                if (reader.TokenType != JsonTokenType.String)
                    throw new JsonException($"Expected string in array, got {reader.TokenType}.");
                result.Add(reader.GetString()!);
            }
            return result;
        }

        if (reader.TokenType != JsonTokenType.String)
            throw new JsonException($"Expected string or start-array, got {reader.TokenType}.");

        result.Add(reader.GetString()!);
        return result;
    }

    public override void Write(
        Utf8JsonWriter writer,
        List<string> value,
        JsonSerializerOptions options)
    {
        if (value.Count == 1)
        {
            writer.WriteStringValue(value[0]);
            return;
        }

        writer.WriteStartArray();

        foreach (var s in value)
            writer.WriteStringValue(s);

        writer.WriteEndArray();
    }
}
