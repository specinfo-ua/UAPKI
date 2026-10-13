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

#include "xml-strict.h"
#include <algorithm>
#include <map>
#include <set>


using namespace std;


namespace UapkiNS {

namespace Xml {


static const char* NS_XML = "http://www.w3.org/XML/1998/namespace";
static const char* NS_XMLNS = "http://www.w3.org/2000/xmlns/";


const std::string* Node::attribute (const char* localName) const
{
    for (const auto& it : attributes) {
        if (it.prefix.empty() && (it.local == localName)) return &it.value;
    }
    return nullptr;
}

const Node* Node::child (const char* namespaceUri, const char* localName) const
{
    for (const auto& it : children) {
        if (it->isElement && (it->local == localName) && (it->nsUri == namespaceUri)) return it.get();
    }
    return nullptr;
}

vector<const Node*> Node::childElements (const char* namespaceUri, const char* localName) const
{
    vector<const Node*> rv;
    for (const auto& it : children) {
        if (it->isElement && (it->local == localName) && (it->nsUri == namespaceUri)) rv.push_back(it.get());
    }
    return rv;
}

bool Node::textContent (std::string& value) const
{
    value.clear();
    for (const auto& it : children) {
        if (it->isElement) return false;
        value += it->text;
    }
    return true;
}


namespace {

struct ParseError {
    Error   error;
    size_t  offset;
};

class Parser {
    const uint8_t*  m_Data;
    size_t          m_Size;
    size_t          m_Pos;
    //  The namespace declarations in scope: one frame per open element
    vector<vector<pair<string, string>>>
                    m_NsFrames;
    set<string>     m_Ids;
    //  Per open element: a comment was met among its children
    vector<bool>    m_HasComment;

    [[noreturn]] void fail (const Error error) const {
        throw ParseError{ error, m_Pos };
    }
    bool eof (void) const {
        return (m_Pos >= m_Size);
    }
    uint8_t peek (void) const {
        if (m_Pos >= m_Size) fail(Error::NOT_WELL_FORMED);
        return m_Data[m_Pos];
    }
    bool startsWith (const char* s) const {
        size_t i = 0;
        for (; s[i]; i++) {
            if ((m_Pos + i >= m_Size) || (m_Data[m_Pos + i] != (uint8_t)s[i])) return false;
        }
        return true;
    }
    void expect (const char* s) {
        if (!startsWith(s)) fail(Error::NOT_WELL_FORMED);
        while (*s) { m_Pos++; s++; }
    }
    static bool isSpace (const uint8_t c) {
        return (c == 0x20) || (c == 0x09) || (c == 0x0A) || (c == 0x0D);
    }
    bool skipSpaces (void) {
        const size_t start = m_Pos;
        while ((m_Pos < m_Size) && isSpace(m_Data[m_Pos])) m_Pos++;
        return (m_Pos > start);
    }
    //  Names: ASCII letters, digits, '_', '-', '.' and any non-ASCII character; ':' separates a prefix
    static bool isNameStart (const uint8_t c) {
        return ((c >= 'A') && (c <= 'Z')) || ((c >= 'a') && (c <= 'z')) || (c == '_') || (c >= 0x80);
    }
    static bool isNameChar (const uint8_t c) {
        return isNameStart(c) || ((c >= '0') && (c <= '9')) || (c == '-') || (c == '.');
    }
    string ncName (void) {
        const size_t start = m_Pos;
        if (eof() || !isNameStart(m_Data[m_Pos])) fail(Error::NOT_WELL_FORMED);
        while ((m_Pos < m_Size) && isNameChar(m_Data[m_Pos])) m_Pos++;
        return string((const char*)m_Data + start, m_Pos - start);
    }
    void qName (string& prefix, string& local) {
        prefix.clear();
        local = ncName();
        if (!eof() && (m_Data[m_Pos] == ':')) {
            m_Pos++;
            prefix = local;
            local = ncName();
        }
    }
    static void appendUtf8 (string& out, const uint32_t cp) {
        if (cp < 0x80) {
            out += (char)cp;
        }
        else if (cp < 0x800) {
            out += (char)(0xC0 | (cp >> 6));
            out += (char)(0x80 | (cp & 0x3F));
        }
        else if (cp < 0x10000) {
            out += (char)(0xE0 | (cp >> 12));
            out += (char)(0x80 | ((cp >> 6) & 0x3F));
            out += (char)(0x80 | (cp & 0x3F));
        }
        else {
            out += (char)(0xF0 | (cp >> 18));
            out += (char)(0x80 | ((cp >> 12) & 0x3F));
            out += (char)(0x80 | ((cp >> 6) & 0x3F));
            out += (char)(0x80 | (cp & 0x3F));
        }
    }
    //  Char of XML 1.0: #x9 | #xA | #xD | [#x20-#xD7FF] | [#xE000-#xFFFD] | [#x10000-#x10FFFF]
    static bool isXmlChar (const uint32_t cp) {
        return (cp == 0x9) || (cp == 0xA) || (cp == 0xD) || ((cp >= 0x20) && (cp <= 0xD7FF)) ||
            ((cp >= 0xE000) && (cp <= 0xFFFD)) || ((cp >= 0x10000) && (cp <= 0x10FFFF));
    }
    //  After '&': one of the five predefined entities or a character reference
    void reference (string& out) {
        if (startsWith("amp;")) { m_Pos += 4; out += '&'; }
        else if (startsWith("lt;")) { m_Pos += 3; out += '<'; }
        else if (startsWith("gt;")) { m_Pos += 3; out += '>'; }
        else if (startsWith("quot;")) { m_Pos += 5; out += '"'; }
        else if (startsWith("apos;")) { m_Pos += 5; out += '\''; }
        else if (startsWith("#")) {
            m_Pos++;
            const bool hex = startsWith("x");
            if (hex) m_Pos++;
            uint32_t cp = 0;
            size_t digits = 0;
            while (!eof() && (m_Data[m_Pos] != ';')) {
                const uint8_t c = m_Data[m_Pos];
                uint32_t d;
                if ((c >= '0') && (c <= '9')) d = c - '0';
                else if (hex && (c >= 'a') && (c <= 'f')) d = c - 'a' + 10;
                else if (hex && (c >= 'A') && (c <= 'F')) d = c - 'A' + 10;
                else fail(Error::NOT_WELL_FORMED);
                cp = cp * (hex ? 16 : 10) + d;
                if ((cp > 0x10FFFF) || (++digits > 8)) fail(Error::NOT_WELL_FORMED);
                m_Pos++;
            }
            if (eof() || (digits == 0)) fail(Error::NOT_WELL_FORMED);
            m_Pos++;
            if (!isXmlChar(cp)) fail(Error::NOT_UTF8);
            appendUtf8(out, cp);
        }
        else {
            //  An entity that would need a declaration
            fail(Error::NOT_SUPPORTED);
        }
    }
    //  One character of the input, checked: well-formed UTF-8 (shortest form) of a character XML allows
    void character (string& out) {
        const uint8_t c = m_Data[m_Pos];
        uint32_t cp;
        size_t len;
        if (c < 0x80) { cp = c; len = 1; }
        else if ((c & 0xE0) == 0xC0) { cp = c & 0x1F; len = 2; }
        else if ((c & 0xF0) == 0xE0) { cp = c & 0x0F; len = 3; }
        else if ((c & 0xF8) == 0xF0) { cp = c & 0x07; len = 4; }
        else fail(Error::NOT_UTF8);
        if (m_Pos + len > m_Size) fail(Error::NOT_UTF8);
        for (size_t i = 1; i < len; i++) {
            const uint8_t cc = m_Data[m_Pos + i];
            if ((cc & 0xC0) != 0x80) fail(Error::NOT_UTF8);
            cp = (cp << 6) | (cc & 0x3F);
        }
        static const uint32_t MIN_BY_LEN[5] = { 0, 0, 0x80, 0x800, 0x10000 };
        if ((cp < MIN_BY_LEN[len]) || !isXmlChar(cp)) fail(Error::NOT_UTF8);
        out.append((const char*)m_Data + m_Pos, len);
        m_Pos += len;
    }
    //  Attribute value: line ends and tabs given literally become spaces (XML 1.0, 3.3.3); what comes from
    //  a character reference stays
    string attributeValue (void) {
        const uint8_t quote = peek();
        if ((quote != '"') && (quote != '\'')) fail(Error::NOT_WELL_FORMED);
        m_Pos++;
        string value;
        while (true) {
            const uint8_t c = peek();
            if (c == quote) { m_Pos++; break; }
            if (c == '<') fail(Error::NOT_WELL_FORMED);
            if (c == '&') { m_Pos++; reference(value); continue; }
            if (c == 0x0D) {
                m_Pos++;
                if (!eof() && (m_Data[m_Pos] == 0x0A)) m_Pos++;
                value += ' ';
                continue;
            }
            if ((c == 0x0A) || (c == 0x09)) { m_Pos++; value += ' '; continue; }
            character(value);
        }
        return value;
    }
    const string* lookupNs (const string& prefix) const {
        for (size_t i = m_NsFrames.size(); i > 0; i--) {
            for (const auto& it : m_NsFrames[i - 1]) {
                if (it.first == prefix) return &it.second;
            }
        }
        return nullptr;
    }
    //  After the name of a start-tag: attributes and namespace declarations up to '>' or '/>'
    bool startTagRest (Node& node) {
        vector<pair<string, string>> frame;
        vector<Attribute> attrs;
        bool is_empty = false;
        while (true) {
            const bool spaces = skipSpaces();
            const uint8_t c = peek();
            if (c == '>') { m_Pos++; break; }
            if (c == '/') { expect("/>"); is_empty = true; break; }
            if (!spaces) fail(Error::NOT_WELL_FORMED);

            Attribute attr;
            qName(attr.prefix, attr.local);
            skipSpaces();
            expect("=");
            skipSpaces();
            attr.value = attributeValue();

            const bool is_default_decl = attr.prefix.empty() && (attr.local == "xmlns");
            if (is_default_decl || (attr.prefix == "xmlns")) {
                const string prefix = is_default_decl ? string() : attr.local;
                //  The prefixes xml and xmlns are bound by XML itself; a prefix cannot be unbound; a relative or
                //  empty namespace name for a prefix is refused
                if ((prefix == "xml") || (prefix == "xmlns") || (attr.value == NS_XML) || (attr.value == NS_XMLNS)) fail(Error::NAMESPACE);
                if (!is_default_decl && attr.value.empty()) fail(Error::NAMESPACE);
                for (const auto& it : frame) {
                    if (it.first == prefix) fail(Error::DUPLICATE_ATTRIBUTE);
                }
                frame.push_back(make_pair(prefix, attr.value));
            }
            else {
                attrs.push_back(attr);
            }
        }
        m_NsFrames.push_back(frame);
        m_HasComment.push_back(false);

        if (node.prefix == "xmlns") fail(Error::NAMESPACE);
        if (node.prefix == "xml") {
            node.nsUri = NS_XML;
        }
        else {
            const string* uri = lookupNs(node.prefix);
            if (!uri && !node.prefix.empty()) fail(Error::NAMESPACE);
            node.nsUri = uri ? *uri : string();
        }
        for (auto& it : attrs) {
            if (it.prefix == "xml") {
                it.nsUri = NS_XML;
            }
            else if (!it.prefix.empty()) {
                const string* uri = lookupNs(it.prefix);
                if (!uri) fail(Error::NAMESPACE);
                it.nsUri = *uri;
            }
        }
        //  Two attributes with one expanded name
        for (size_t i = 0; i < attrs.size(); i++) {
            for (size_t j = i + 1; j < attrs.size(); j++) {
                if ((attrs[i].local == attrs[j].local) && (attrs[i].nsUri == attrs[j].nsUri)) fail(Error::DUPLICATE_ATTRIBUTE);
            }
            if (attrs[i].prefix.empty() && (attrs[i].local == "Id")) {
                if (!m_Ids.insert(attrs[i].value).second) fail(Error::DUPLICATE_ID);
            }
        }
        node.attributes = attrs;
        return is_empty;
    }
    void prolog (void) {
        if ((m_Size >= 3) && (m_Data[0] == 0xEF) && (m_Data[1] == 0xBB) && (m_Data[2] == 0xBF)) m_Pos = 3;
        if (startsWith("<?xml") && (m_Pos + 5 < m_Size) && isSpace(m_Data[m_Pos + 5])) {
            //  The XML declaration: version 1.0, the encoding UTF-8 if given
            const size_t start = m_Pos;
            size_t end = start;
            while ((end + 1 < m_Size) && !((m_Data[end] == '?') && (m_Data[end + 1] == '>'))) end++;
            if (end + 1 >= m_Size) fail(Error::NOT_WELL_FORMED);
            string decl((const char*)m_Data + start, end - start);
            std::transform(decl.begin(), decl.end(), decl.begin(), [](unsigned char ch) { return (char)tolower(ch); });
            if ((decl.find("version=\"1.0\"") == string::npos) && (decl.find("version='1.0'") == string::npos)) fail(Error::NOT_SUPPORTED);
            const size_t enc = decl.find("encoding");
            if ((enc != string::npos) && (decl.find("utf-8", enc) == string::npos)) fail(Error::NOT_UTF8);
            m_Pos = end + 2;
        }
        //  Before the root element: white space and comments
        do {
            skipSpaces();
        } while (skipComment());
    }
    //  Markup that is refused, at '<'
    void refuseMarkup (void) const {
        if (startsWith("<!--") || startsWith("<?") || startsWith("<![CDATA[") || startsWith("<!")) fail(Error::NOT_SUPPORTED);
    }
    //  At "<!--": the comment is skipped (the canonical form is the one without comments). "--" is not allowed
    //  inside a comment (XML 1.0, 2.5)
    bool skipComment (void) {
        if (!startsWith("<!--")) return false;
        m_Pos += 4;
        string ignored;
        while (true) {
            if (eof()) fail(Error::NOT_WELL_FORMED);
            if (startsWith("--")) {
                if (!startsWith("-->")) fail(Error::NOT_WELL_FORMED);
                m_Pos += 3;
                return true;
            }
            character(ignored);
            ignored.clear();
        }
    }
    static bool isWhiteSpace (const string& text) {
        for (const char c : text) {
            if (!isSpace((uint8_t)c)) return false;
        }
        return true;
    }
    //  A comment is accepted only where it cannot split a value: among the children of an element that has no
    //  character data but white space. Called when the element is closed
    void checkComments (const Node& element) const {
        if (!m_HasComment.back()) return;
        for (const auto& it : element.children) {
            if (!it->isElement && !isWhiteSpace(it->text)) fail(Error::NOT_SUPPORTED);
        }
    }

public:
    Parser (const uint8_t* data, const size_t size)
        : m_Data(data), m_Size(size), m_Pos(0)
    {}

    unique_ptr<Node> parse (void) {
        prolog();
        if (eof() || (m_Data[m_Pos] != '<')) fail(Error::NOT_WELL_FORMED);
        refuseMarkup();

        unique_ptr<Node> root(new Node());
        Node* current = nullptr;
        while (true) {
            if (!current) {
                //  The start-tag of the root element
                m_Pos++;
                root->isElement = true;
                qName(root->prefix, root->local);
                if (startTagRest(*root)) { m_NsFrames.pop_back(); m_HasComment.pop_back(); break; }
                current = root.get();
                continue;
            }

            if (eof()) fail(Error::NOT_WELL_FORMED);
            if (m_Data[m_Pos] != '<') {
                //  Character data up to the next markup; line ends become #xA (XML 1.0, 2.11)
                unique_ptr<Node> text(new Node());
                text->parent = current;
                while (!eof() && (m_Data[m_Pos] != '<')) {
                    const uint8_t c = m_Data[m_Pos];
                    if (c == '&') { m_Pos++; reference(text->text); }
                    else if (c == 0x0D) {
                        m_Pos++;
                        if (!eof() && (m_Data[m_Pos] == 0x0A)) m_Pos++;
                        text->text += '\n';
                    }
                    else {
                        if ((c == ']') && startsWith("]]>")) fail(Error::NOT_WELL_FORMED);
                        character(text->text);
                    }
                }
                current->children.push_back(std::move(text));
                continue;
            }

            if (startsWith("</")) {
                m_Pos += 2;
                string prefix, local;
                qName(prefix, local);
                if ((prefix != current->prefix) || (local != current->local)) fail(Error::NOT_WELL_FORMED);
                skipSpaces();
                expect(">");
                checkComments(*current);
                m_NsFrames.pop_back();
                m_HasComment.pop_back();
                current = current->parent;
                if (!current) break;
                continue;
            }

            if (skipComment()) {
                m_HasComment.back() = true;
                continue;
            }
            refuseMarkup();
            if (m_NsFrames.size() >= Document::MAX_DEPTH) fail(Error::TOO_DEEP);
            m_Pos++;
            unique_ptr<Node> element(new Node());
            element->isElement = true;
            element->parent = current;
            qName(element->prefix, element->local);
            const bool is_empty = startTagRest(*element);
            Node* added = element.get();
            current->children.push_back(std::move(element));
            if (is_empty) {
                m_NsFrames.pop_back();
                m_HasComment.pop_back();
            }
            else {
                current = added;
            }
        }

        //  After the root element: only white space and comments
        do {
            skipSpaces();
        } while (skipComment());
        if (!eof()) {
            if (m_Data[m_Pos] == '<') refuseMarkup();
            fail(Error::NOT_WELL_FORMED);
        }
        return root;
    }
};  //  end class Parser


const Node* find_by_id (const Node* node, const string& id)
{
    //  Without recursion: the depth is limited, the width is not
    vector<const Node*> stack;
    stack.push_back(node);
    while (!stack.empty()) {
        const Node* it = stack.back();
        stack.pop_back();
        if (!it->isElement) continue;
        const string* value = it->attribute("Id");
        if (value && (*value == id)) return it;
        for (const auto& it_child : it->children) {
            stack.push_back(it_child.get());
        }
    }
    return nullptr;
}

void escape_text (const string& text, string& out)
{
    for (const char c : text) {
        switch (c) {
        case '&':   out += "&amp;"; break;
        case '<':   out += "&lt;"; break;
        case '>':   out += "&gt;"; break;
        case 0x0D:  out += "&#xD;"; break;
        default:    out += c; break;
        }
    }
}

void escape_attribute (const string& value, string& out)
{
    for (const char c : value) {
        switch (c) {
        case '&':   out += "&amp;"; break;
        case '<':   out += "&lt;"; break;
        case '"':   out += "&quot;"; break;
        case 0x09:  out += "&#x9;"; break;
        case 0x0A:  out += "&#xA;"; break;
        case 0x0D:  out += "&#xD;"; break;
        default:    out += c; break;
        }
    }
}

//  rendered: the namespace declarations the output ancestors of the element have, innermost last
void canonicalize_element (
        const Node* element,
        const Node* exclude,
        vector<pair<string, string>>& rendered,
        string& out
)
{
    const size_t rendered_before = rendered.size();
    const auto rendered_uri = [&rendered](const string& prefix) -> const string* {
        for (size_t i = rendered.size(); i > 0; i--) {
            if (rendered[i - 1].first == prefix) return &rendered[i - 1].second;
        }
        return nullptr;
    };

    //  The namespaces visibly utilized by the element: of its own name and of the names of its attributes
    map<string, string> declare;
    {
        const string* uri = rendered_uri(element->prefix);
        if (element->prefix.empty()) {
            //  The default namespace: also xmlns="" when an output ancestor has a default namespace
            if ((uri ? *uri : string()) != element->nsUri) declare[string()] = element->nsUri;
        }
        else if ((element->prefix != "xml") && (!uri || (*uri != element->nsUri))) {
            declare[element->prefix] = element->nsUri;
        }
    }
    for (const auto& it : element->attributes) {
        if (it.prefix.empty() || (it.prefix == "xml")) continue;
        const string* uri = rendered_uri(it.prefix);
        if (!uri || (*uri != it.nsUri)) declare[it.prefix] = it.nsUri;
    }

    const string name = element->prefix.empty() ? element->local : (element->prefix + ":" + element->local);
    out += '<';
    out += name;
    //  std::map: sorted by the prefix, the default namespace (the empty prefix) first
    for (const auto& it : declare) {
        out += it.first.empty() ? string(" xmlns") : (" xmlns:" + it.first);
        out += "=\"";
        escape_attribute(it.second, out);
        out += '"';
        rendered.push_back(it);
    }
    //  The attributes: by the namespace name, then by the local name (no namespace sorts first)
    vector<const Attribute*> attrs;
    for (const auto& it : element->attributes) {
        attrs.push_back(&it);
    }
    std::sort(attrs.begin(), attrs.end(), [](const Attribute* a, const Attribute* b) {
        return (a->nsUri != b->nsUri) ? (a->nsUri < b->nsUri) : (a->local < b->local);
    });
    for (const auto& it : attrs) {
        out += ' ';
        out += it->prefix.empty() ? it->local : (it->prefix + ":" + it->local);
        out += "=\"";
        escape_attribute(it->value, out);
        out += '"';
    }
    out += '>';

    for (const auto& it : element->children) {
        if (it.get() == exclude) continue;
        if (it->isElement) {
            canonicalize_element(it.get(), exclude, rendered, out);
        }
        else {
            escape_text(it->text, out);
        }
    }

    out += "</";
    out += name;
    out += '>';
    rendered.resize(rendered_before);
}

}   //  end namespace


Document::Document (void)
    : m_Error(Error::OK), m_ErrorOffset(0)
{}

Error Document::parse (const uint8_t* data, const size_t size, const size_t maxSize)
{
    m_Root.reset();
    m_Error = Error::OK;
    m_ErrorOffset = 0;
    if (!data || (size == 0)) {
        m_Error = Error::NOT_WELL_FORMED;
        return m_Error;
    }
    if (size > maxSize) {
        m_Error = Error::TOO_BIG;
        return m_Error;
    }

    try {
        Parser parser(data, size);
        m_Root = parser.parse();
    }
    catch (const ParseError& e) {
        m_Error = e.error;
        m_ErrorOffset = e.offset;
    }
    return m_Error;
}

const Node* Document::elementById (const std::string& id) const
{
    return m_Root ? find_by_id(m_Root.get(), id) : nullptr;
}

void canonicalizeExclusive (
        const Node* apex,
        const Node* exclude,
        std::string& canonical
)
{
    canonical.clear();
    if (!apex || !apex->isElement || (apex == exclude)) return;
    vector<pair<string, string>> rendered;
    canonicalize_element(apex, exclude, rendered, canonical);
}

const char* errorToStr (
        const Error error
)
{
    switch (error) {
    case Error::OK:                     return "OK";
    case Error::TOO_BIG:                return "TOO_BIG";
    case Error::TOO_DEEP:               return "TOO_DEEP";
    case Error::NOT_UTF8:               return "NOT_UTF8";
    case Error::NOT_WELL_FORMED:        return "NOT_WELL_FORMED";
    case Error::NOT_SUPPORTED:          return "NOT_SUPPORTED";
    case Error::NAMESPACE:              return "NAMESPACE";
    case Error::DUPLICATE_ATTRIBUTE:    return "DUPLICATE_ATTRIBUTE";
    case Error::DUPLICATE_ID:           return "DUPLICATE_ID";
    default:                            return "UNKNOWN";
    }
}


}   //  end namespace Xml

}   //  end namespace UapkiNS
