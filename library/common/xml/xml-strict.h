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

#ifndef UAPKI_XML_STRICT_H
#define UAPKI_XML_STRICT_H


#include <cstdint>
#include <memory>
#include <string>
#include <vector>


namespace UapkiNS {

namespace Xml {

//  A strict reader of signed XML documents and Exclusive XML Canonicalization 1.0 without comments
//  (https://www.w3.org/TR/xml-exc-c14n/). The reader takes only what has one meaning for every XML processor:
//  UTF-8, elements, attributes, namespaces, character data, the five predefined entities and character
//  references. A document type declaration, entity declarations, processing instructions and CDATA sections are
//  refused, as are duplicate attributes and duplicate Id values: what is canonicalized (signed) and what is read
//  from the same tree cannot differ. A comment is accepted and dropped only where it cannot split a value:
//  outside the root element, or among the children of an element without character data other than white space.

enum class Error : uint32_t {
    OK = 0,
    TOO_BIG,                //  the document is larger than the limit
    TOO_DEEP,               //  the nesting of elements exceeds the limit
    NOT_UTF8,               //  not UTF-8, or a character XML does not allow
    NOT_WELL_FORMED,        //  the syntax of XML
    NOT_SUPPORTED,          //  a construct this reader refuses (DOCTYPE, comment, processing instruction, CDATA...)
    NAMESPACE,              //  a prefix that is not declared, or a declaration that is not allowed
    DUPLICATE_ATTRIBUTE,
    DUPLICATE_ID
};

struct Attribute {
    std::string prefix;
    std::string local;
    std::string nsUri;      //  empty for an attribute without a prefix
    std::string value;
};

struct Node {
    bool        isElement;
    //  Element
    std::string prefix;
    std::string local;
    std::string nsUri;      //  the namespace of the element (the default namespace for a name without a prefix)
    std::vector<Attribute>
                attributes; //  without namespace declarations
    std::vector<std::unique_ptr<Node>>
                children;
    Node*       parent;
    //  Character data
    std::string text;

    Node (void) : isElement(false), parent(nullptr) {}

    //  The value of an attribute without a prefix; nullptr if absent
    const std::string* attribute (const char* localName) const;
    //  The first child element with the name; nullptr if absent
    const Node* child (const char* namespaceUri, const char* localName) const;
    std::vector<const Node*> childElements (const char* namespaceUri, const char* localName) const;
    //  The character data of the element; false if it has child elements
    bool textContent (std::string& value) const;
};

class Document {
    std::unique_ptr<Node>
                m_Root;
    Error       m_Error;
    size_t      m_ErrorOffset;

public:
    static const size_t MAX_SIZE_DEFAULT = 64 * 1024 * 1024;
    static const size_t MAX_DEPTH = 64;

    Document (void);

    Error parse (const uint8_t* data, const size_t size, const size_t maxSize = MAX_SIZE_DEFAULT);
    const Node* root (void) const { return m_Root.get(); }
    Error error (void) const { return m_Error; }
    //  The offset in the document where the error was met
    size_t errorOffset (void) const { return m_ErrorOffset; }

    //  The element with the attribute Id of the value (the values are unique in a document that is parsed)
    const Node* elementById (const std::string& id) const;
};

//  Exclusive canonical form (without comments, no InclusiveNamespaces PrefixList) of the element apex with its
//  content; the element exclude with its content, if given, is left out (the enveloped signature transform)
void canonicalizeExclusive (
    const Node* apex,
    const Node* exclude,
    std::string& canonical
);

const char* errorToStr (
    const Error error
);

}   //  end namespace Xml

}   //  end namespace UapkiNS


#endif
