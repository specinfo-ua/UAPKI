/*
 SPDX-License-Identifier: MIT

 Copyright (c) 2021, The UAPKI Project Authors.
 Copyright (c) 2012 - 2020 Krzysztof Gabis
 Parson 1.1.0 ( http://kgabis.github.com/parson/ )

 Permission is hereby granted, free of charge, to any person obtaining a copy
 of this software and associated documentation files (the "Software"), to deal
 in the Software without restriction, including without limitation the rights
 to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 copies of the Software, and to permit persons to whom the Software is
 furnished to do so, subject to the following conditions:

 The above copyright notice and this permission notice shall be included in
 all copies or substantial portions of the Software.

 THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 THE SOFTWARE.

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
