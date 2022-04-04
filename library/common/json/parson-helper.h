/*
 * Copyright (c) 2022, The UAPKI Project Authors.
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

#ifndef PARSON_HELPER_H
#define PARSON_HELPER_H


#include <stdint.h>
#include <stdbool.h>
#include <string>
#include "parson.h"


class ParsonHelper {
    JSON_Value*     m_JsonValue;
    JSON_Object*    m_JsonRefObj;

public:
    ParsonHelper (void);
    ~ParsonHelper (void);
    void cleanup (void);

public:
    JSON_Object* create (void);
    JSON_Array* setArray (const char* key);
    bool setBoolean (const char* key, const bool value);
    bool setInt32 (const char* key, const int32_t value);
    bool setInt64 (const char* key, const int64_t value);
    JSON_Object* setObject (const char* key);
    bool setString (const char* key, const char* value);
    bool setString (const char* key, const std::string& value);
    bool setUint32 (const char* key, const uint32_t value);
    bool setUint64 (const char* key, const uint64_t value);
    bool serialize (char** sJson);
    bool serialize (std::string& sJson);

public:
    JSON_Object* parse (const char* sJson, const bool withComments = false);
    JSON_Object* rootObject (void) const { return m_JsonRefObj; }
    JSON_Array* getArray (const char* key);
    bool getBoolean (const char* key, const bool defValue = false);
    int getInt (const char* key);
    JSON_Object* getObject (const char* key);
    const char* getString (const char* key);
    const char* getString (const char* key, std::string& s);
    bool hasValue (const char* key);
    bool hasValue (const char* key, const JSON_Value_Type type);

public:
    static void setEscapeSlashes (const int escapeSlashes = 0);
    static std::string jsonArrayGetString (JSON_Array* ja, const size_t index, const std::string& defValue = std::string());
    static bool jsonObjectGetBoolean (JSON_Object* jo, const char* key, const bool defValue = false);
    static int32_t jsonObjectGetInt32 (JSON_Object* jo, const char* key, const int32_t defValue = 0);
    static uint32_t jsonObjectGetUint32 (JSON_Object* jo, const char* key, const uint32_t defValue = 0);
    static std::string jsonObjectGetString (JSON_Object* jo, const char* key, const std::string& defValue = std::string());
    static bool jsonObjectHasValue (JSON_Object* jo, const char* key);
    static bool jsonObjectHasValue (JSON_Object* jo, const char* key, const JSON_Value_Type type);
    static JSON_Status jsonObjectSetBoolean (JSON_Object* jo, const char* key, const bool value);
    static JSON_Status jsonObjectSetInt32 (JSON_Object* jo, const char* key, const int32_t value);
    static JSON_Status jsonObjectSetInt64 (JSON_Object* jo, const char* key, const int64_t value);
    static JSON_Status jsonObjectSetUint32 (JSON_Object* jo, const char* key, const uint32_t value);
    static JSON_Status jsonObjectSetUint64 (JSON_Object* jo, const char* key, const uint64_t value);

};  //  end class ParsonHelper

#endif
