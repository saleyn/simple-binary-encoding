/*
 * Copyright 2015 Omnibius, LLC
 * Copyright 2013 Real Logic Ltd.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package uk.co.real_logic.sbe.generation.cpp11;

import uk.co.real_logic.sbe.PrimitiveType;
import uk.co.real_logic.sbe.generation.CodeGenerator;
import uk.co.real_logic.agrona.generation.OutputManager;
import uk.co.real_logic.sbe.ir.Encoding;
import uk.co.real_logic.sbe.ir.Ir;
import uk.co.real_logic.sbe.ir.Signal;
import uk.co.real_logic.sbe.ir.Token;
import uk.co.real_logic.agrona.Verify;

import java.io.IOException;
import java.io.Writer;
import java.util.Arrays;
import java.util.ArrayList;
import java.util.LinkedList;
import java.util.Calendar;
import java.util.List;
import java.util.Collections;
import java.util.stream.Collectors;

import static uk.co.real_logic.sbe.generation.cpp11.Cpp11Util.*;
import uk.co.real_logic.sbe.generation.cpp11.Cpp11Util.NodeList;
import uk.co.real_logic.sbe.generation.cpp11.Cpp11Util.Node;
import uk.co.real_logic.sbe.generation.cpp11.Cpp11Util.FieldType;

public class Cpp11Generator implements CodeGenerator
{
    private static final String BASE_INDENT = "";
    private static final String INDENT = "    ";
    private static final int    TAG_PRINT_WIDTH  = 5;
    private static final int    NAME_PRINT_WIDTH = 30;
    private static final int    TYPE_PRINT_WIDTH = 20;

    private final Ir ir;
    private final OutputManager outputManager;
    private String              innerNamespace;
    private final String        outerNamespace;
    private final String        copyright;
    private final String        outputSubdir;

    public Cpp11Generator(final Ir ir, final String subdir, final OutputManager outputManager)
        throws IOException
    {
        Verify.notNull(ir, "ir");
        Verify.notNull(outputManager, "outputManager");

        this.ir = ir;
        this.outputManager  = outputManager;
        this.outputSubdir   = subdir;
        this.outerNamespace = System.getProperty("sbe.target.namespace0");
        this.copyright      = System.getProperty("sbe.target.copyright");
    }

    public String uncamelName(final String name)
    {
        return name.replaceAll("(.)([A-Z][a-z]+)",  "$1_$2")
                   .replaceAll("([a-z0-9])([A-Z])", "$1_$2")
                   .toLowerCase();
    }

    private void fileEndIfdef(final Writer out, final String name, boolean closeNamespaces)
        throws IOException
    {
        if (closeNamespaces)
        {
            this.closeNamespaces(out, innerNamespace);
        }
        out.append("\n#endif // ");
        out.append(ifdefName(name));
        out.append("\n");
    }

    private void closeNamespaces(final Writer out, final String namespace)
        throws IOException
    {
        out.append("} // namespace ");
        if (namespace != null)
        {
            out.append(namespace + "\n");
        }
        if (outerNamespace != null)
        {
            out.append("} // namespace ");
            out.append(outerNamespace + "\n");
        }
    }

    public void generateMessageHeaderStub() throws IOException
    {
        try (final Writer out = outputManager.createOutput(MESSAGE_HEADER_TYPE))
        {
            final List<Token> tokens = ir.headerStructure().tokens();
            final String className   = ir.applicableNamespace().replace('.', '_');
            out.append(generateFileHeader(className, MESSAGE_HEADER_TYPE, null));
            out.append(generateClassDeclaration(MESSAGE_HEADER_TYPE));
            out.append(generateFixedFlyweightCode(MESSAGE_HEADER_TYPE, tokens.get(0).size()));
            out.append(
                generatePrimitivePropertyEncodings(MESSAGE_HEADER_TYPE, tokens.subList(1, tokens.size() - 1), BASE_INDENT));

            out.append("};\n\n");
            fileEndIfdef(out, className, true);
        }
    }

    static final String MESSAGES_FILE = "Messages";

    private void generateMessagesFile(final String namespace, final List<String> messages)
        throws IOException
    {
        try (final Writer out = outputManager.createOutput(MESSAGES_FILE))
        {
            out.append(generateFileHeader(namespace, MESSAGES_FILE, messages, false, false));
            fileEndIfdef(out, MESSAGES_FILE, false);
        }
    }

    public List<String> generateTypeStubs() throws IOException
    {
        final List<String> typesToInclude = new ArrayList<>();

        for (final List<Token> tokens : ir.types())
        {
            switch (tokens.get(0).signal())
            {
                case BEGIN_ENUM:
                    generateEnum(tokens);
                    break;

                case BEGIN_SET:
                    generateChoiceSet(tokens);
                    break;

                case BEGIN_COMPOSITE:
                    generateComposite(tokens);
                    break;
            }

            typesToInclude.add(tokens.get(0).name());
        }

        return typesToInclude;
    }

    public void generate() throws IOException
    {
        generateMessageHeaderStub();
        final String namespace = ir.applicableNamespace().replace('.', '_');
        final List<String> typesToInclude = generateTypeStubs();
        typesToInclude.add("<iomanip>");

        generateSbeMainInclude(namespace);

        final List<String> messages = new ArrayList<String>();

        for (final List<Token> tokens : ir.messages())
        {
            final Token msgToken = tokens.get(0);
            final String className = formatClassName(msgToken.name());

            messages.add(className);

            try (final Writer out = outputManager.createOutput(className))
            {
                out.append(generateFileHeader(namespace, className, typesToInclude));
                out.append(generateClassDeclaration(className));
                out.append(generateMessageFlyweightCode(className, msgToken));

                final List<Token> messageBody = tokens.subList(1, tokens.size() - 1);
                int offset = 0;

                final List<Token> rootFields = new ArrayList<>();
                final NodeList fields = new NodeList();

                offset = collectRootFields(messageBody, offset, rootFields);
                out.append(generateFields(className, rootFields, BASE_INDENT, fields));

                final List<Token> groups = new ArrayList<>();
                offset = collectGroups(messageBody, offset, groups);
                StringBuilder sb = new StringBuilder();
                generateGroups(sb, groups, 0, BASE_INDENT, fields);
                out.append(sb);

                final List<Token> varData = messageBody.subList(offset, messageBody.size());
                out.append(generateVarData(varData, fields));

                out.append(generateStreamPrint(false, className, fields, BASE_INDENT));

                out.append(String.format("}; // %s\n", className));
                fileEndIfdef(out, className, true);
            }
        }

        if (!messages.isEmpty())
        {
            generateMessagesFile(namespace, messages);
        }
    }

    private int collectRootFields(final List<Token> tokens, int index, final List<Token> rootFields)
    {
        for (int size = tokens.size(); index < size; index++)
        {
            final Token token = tokens.get(index);
            if (Signal.BEGIN_GROUP == token.signal() ||
                Signal.END_GROUP == token.signal() ||
                Signal.BEGIN_VAR_DATA == token.signal())
            {
                return index;
            }

            rootFields.add(token);
        }

        return index;
    }

    private int collectGroups(final List<Token> tokens, int index, final List<Token> groups)
    {
        for (int size = tokens.size(); index < size; index++)
        {
            final Token token = tokens.get(index);
            if (Signal.BEGIN_VAR_DATA == token.signal())
            {
                return index;
            }

            groups.add(token);
        }

        return index;
    }

    private int generateGroups(final StringBuilder sb, final List<Token> tokens, int index,
        final String indent, final NodeList fields)
    {
        for (int size = tokens.size(); index < size; index++)
        {
            if (tokens.get(index).signal() == Signal.BEGIN_GROUP)
            {
                final Token groupToken = tokens.get(index);
                final String groupName = groupToken.name();

                if (fields != null)
                {
                    fields.add(groupToken);
                }

                generateGroupClassHeader(sb, groupName, tokens, index, indent + INDENT);

                final List<Token> rootFields = new ArrayList<>();
                final NodeList groupFields = new NodeList();
                index = collectRootFields(tokens, ++index, rootFields);
                sb.append(generateFields(groupName, rootFields, indent + INDENT, groupFields));

                if (tokens.get(index).signal() == Signal.BEGIN_GROUP)
                {
                    index = generateGroups(sb, tokens, index, indent + INDENT, null);
                }

                sb.append(generateStreamPrint(
                              true, groupName, groupFields, indent + INDENT
                          ));
                sb.append(indent).append("    };\n");
                sb.append(generateGroupProperty(groupName, groupToken, indent, groupFields));
            }
        }

        return index;
    }

    private void generateGroupClassHeader(
        final StringBuilder sb, final String groupName, final List<Token> tokens, final int index, final String indent)
    {
        final String  dimensionsClassName = formatClassName(tokens.get(index + 1).name());
        final Integer dimensionHeaderSize = Integer.valueOf(tokens.get(index + 1).size());

        sb.append(String.format(
            "\n" +
            indent + "class %1$s {\n" +
            indent + "private:\n" +
            indent + "    // Fields are mutable because the class can be used for both encoding/decoding\n" +
            indent + "    mutable char*  m_buf;\n" +
            indent + "    mutable size_t m_buf_size;\n" +
            indent + "    mutable int    m_block_len;\n" +
            indent + "    mutable int    m_count;\n" +
            indent + "    mutable int    m_index;\n" +
            indent + "    mutable int    m_version;\n" +
            indent + "    mutable int*   m_pos_ptr;\n" +
            indent + "    mutable int    m_offset;\n" +
            indent + "    mutable %2$s m_dimensions;\n\n" +
            indent + "public:\n\n",
            formatClassName(groupName),
            dimensionsClassName
        ));

        sb.append(String.format(
            indent + "    void WrapForDecode(const char* buffer, int* pos, int vsn, int bufsz) const {\n" +
            indent + "        m_buf        = const_cast<char*>(buffer);\n" +
            indent + "        m_buf_size   = bufsz;\n" +
            indent + "        m_dimensions.Wrap(m_buf, *pos, vsn, bufsz);\n" +
            indent + "        m_block_len  = m_dimensions.block_length();\n" +
            indent + "        m_count      = m_dimensions.num_in_group();\n" +
            indent + "        m_index      = 0;\n" +
            indent + "        m_version    = vsn;\n" +
            indent + "        m_pos_ptr    = pos;\n" +
            indent + "        *m_pos_ptr   = *m_pos_ptr + %1$d;\n" +
            indent + "        m_offset     = *m_pos_ptr;\n" +
            indent + "    }\n\n",
            dimensionHeaderSize
        ));

        final Integer blockLen        = Integer.valueOf(tokens.get(index).size());
        final String  typeForBlkLen   = cpp11TypeName(tokens.get(index + 2));
        final String  typeForNumInGrp = cpp11TypeName(tokens.get(index + 3));

        sb.append(String.format(
            indent + "    void WrapForEncode(char* buffer, int count,\n" +
            indent + "                       int*  pos,    int vsn, int bufsz) {\n" +
            indent + "        m_buf       = buffer;\n" +
            indent + "        m_buf_size  = bufsz;\n" +
            indent + "        m_block_len = %2$d;\n" +
            indent + "        m_count     = count;\n" +
            indent + "        m_index     = 0;\n" +
            indent + "        m_version   = vsn;\n" +
            indent + "        m_dimensions.Wrap(m_buf, *pos, vsn, bufsz);\n" +
            indent + "        m_dimensions.block_length((%1$s)%2$d);\n" +
            indent + "        m_dimensions.num_in_group((%3$s)count);\n" +
            indent + "        m_pos_ptr   = pos;\n" +
            indent + "        *m_pos_ptr  = *m_pos_ptr + %4$d;\n" +
            indent + "    }\n\n",
            typeForBlkLen, blockLen, typeForNumInGrp, dimensionHeaderSize
        ));

        sb.append(String.format(
            indent + "    static const char* Name()          { return \"%1$s\"; }\n" +
            indent + "    static const int   HeaderSize()    { return %2$d; }\n" +
            indent + "    static const int   BlockLen()      { return %3$d; }\n\n" +
            indent + "    int                Index()   const { return m_index; }\n" +
            indent + "    int                Count()   const { return m_count; }\n" +
            indent + "    bool               HasNext() const { return m_index < m_count; }\n",
            groupName,
            dimensionHeaderSize,
            blockLen
        ));

        sb.append(String.format(
            indent + "    const %1$s& Next() const {\n" +
            indent + "        m_offset = *m_pos_ptr;\n" +
            indent + "        if (SBE_BOUNDS_CHECK_EXPECT(( (m_offset + m_block_len) > long(m_buf_size) ),0))\n" +
            indent + "            throw std::runtime_error(\"buffer too short to support next group index [E108]\");\n" +
            indent + "        *m_pos_ptr = m_offset + m_block_len;\n" +
            indent + "        ++m_index;\n\n" +
            indent + "        return *this;\n" +
            indent + "    }\n\n",
            formatClassName(groupName)
        ));
    }

    private CharSequence generateGroupProperty(final String groupName, final Token token,
        final String indent, final NodeList fields)
    {
        final StringBuilder sb = new StringBuilder();

        final String className = formatClassName(groupName);
        final String propertyName = formatPropertyName(groupName);

        sb.append(String.format(
            "\n" +
            indent + "private:\n" +
            indent + "    %1$s m_%2$s;\n\n" +
            indent + "public:\n",
            className,
            uncamelName(propertyName)
        ));

        sb.append(String.format(
            "\n" +
            indent + "    static const char* %2$s_name()         { return \"%1$s\"; }\n" +
            indent + "    static const int   %2$s_tag()          { return %3$d; }\n" +
            indent + "    int                %2$s_offset() const { return m_offset + %4$d; }\n\n",
            groupName,
            uncamelName(groupName),
            token.id(),
            token.offset()
        ));

        sb.append(String.format(
            "\n" +
            indent + "    const %1$s& %2$s() const {\n" +
            indent + "        m_%2$s.WrapForDecode(m_buf, m_pos_ptr, m_version, m_buf_size);\n" +
            indent + "        return m_%2$s;\n" +
            indent + "    }\n",
            className,
            uncamelName(propertyName)
        ));

        sb.append(String.format(
            "\n" +
            indent + "    %1$s& %2$s_count(int count) {\n" +
            indent + "        m_%2$s.WrapForEncode(m_buf, count, m_pos_ptr, m_version, m_buf_size);\n" +
            indent + "        return m_%2$s;\n" +
            indent + "    }\n",
            className,
            uncamelName(propertyName)
        ));

        fields.add(propertyName, token);

        return sb;
    }

    private CharSequence generateVarData(final List<Token> tokens, final NodeList fields)
    {
        final StringBuilder sb = new StringBuilder();

        for (int i = 0, size = tokens.size(); i < size; i++)
        {
            final Token token = tokens.get(i);
            if (token.signal() == Signal.BEGIN_VAR_DATA)
            {
                final String      propertyName = toUpperFirstChar(token.name());
                final String characterEncoding = tokens.get(i + 3).encoding().characterEncoding();
                final Token        lengthToken = tokens.get(i + 2);
                final int             lenFldSz = lengthToken.size();
                final String   lengthCpp11Type = cpp11TypeName(lengthToken);

                fields.add(propertyName, token);

                generateFieldMetaAttributeMethod(sb, token, BASE_INDENT);

                generateVarDataDescriptors(
                    sb, token, propertyName, characterEncoding, lengthToken, lenFldSz, lengthCpp11Type);

                sb.append(String.format(
                    "    const char* %1$s() {\n" +
                             "%2$s" +
                    "         const char* p = (m_buf + Position() + %3$d);\n" +
                    "         Position(Position() + %3$d + *((%4$s *)(m_buf + Position())));\n" +
                    "         return p;\n" +
                    "    }\n\n",
                    uncamelName(formatPropertyName(propertyName)),
                    generateTypeFieldNotPresentCondition(token.version(), BASE_INDENT),
                    lenFldSz,
                    lengthCpp11Type
                ));

                sb.append(String.format(
                    "    int get_%1$s(char* dst, long len) {\n" +
                            "%2$s" +
                    "        auto lenFldSz        = %3$d;\n" +
                    "        auto lenPosition     = Position();\n" +
                    "        Position(lenPosition + lenFldSz);\n" +
                    "        auto dataLength      = %4$s(*((%5$s *)(m_buf + lenPosition)));\n" +
                    "        int  bytesToCopy     = (len < dataLength) ? len : dataLength;\n" +
                    "        auto pos             = Position();\n" +
                    "        Position(Position()  + dataLength);\n" +
                    "        ::memcpy(dst,  m_buf + pos, bytesToCopy);\n" +
                    "        return bytesToCopy;\n" +
                    "    }\n\n",
                    uncamelName(propertyName),
                    generateArrayFieldNotPresentCondition(token.version(), BASE_INDENT),
                    lenFldSz,
                    formatByteOrderEncoding(lengthToken.encoding().byteOrder(), lengthToken.encoding().primitiveType()),
                    lengthCpp11Type
                ));

                sb.append(String.format(
                    "    int put_%1$s(const char* src, long len) {\n" +
                    "        auto lenFldSz        = %2$d;\n" +
                    "        auto lenPosition     = Position();\n" +
                    "        *((%3$s *)(m_buf     + lenPosition)) = %4$s((%3$s)len);\n" +
                    "        Position(lenPosition + lenFldSz);\n" +
                    "        auto pos             = Position();\n" +
                    "        Position(Position()  + len);\n" +
                    "        ::memcpy(m_buf + pos, src, len);\n" +
                    "        return len;\n" +
                    "    }\n",
                    uncamelName(propertyName),
                    lenFldSz,
                    lengthCpp11Type,
                    formatByteOrderEncoding(lengthToken.encoding().byteOrder(), lengthToken.encoding().primitiveType())
                ));
            }
        }

        return sb;
    }

    private void generateVarDataDescriptors(
        final StringBuilder sb,
        final Token token,
        final String propertyName,
        final String characterEncoding,
        final Token lengthToken,
        final Integer lenFldSz,
        final String lengthCpp11Type)
    {
        final String uname = uncamelName(formatPropertyName(propertyName));

        sb.append(String.format(
            "\n"  +
            "    static const char* %1$s_char_encoding() { return \"%2$s\"; }\n",
            uname,
            characterEncoding
        ));

        sb.append(String.format(
            "    static const char* %1$s_name()          { return \"%5$s\"; }\n" +
            "    static int %1$s_tag()                   { return %3$d; }\n" +
            "    static int %1$s_since_version()         { return %2$d; }\n" +
            "    bool   %1$s_in_version()          const { return m_version >= %2$s; }\n" +
            "    int    %1$s_offset()              const { return m_offset + %4$d; }\n",
            uname,
            token.version(),
            token.id(),
            token.offset(),
            formatPropertyName(propertyName)
            ));

        sb.append(String.format(
            "    static const int %s_header_size()       { return %d; }\n",
            uname,
            lenFldSz
        ));

        sb.append(String.format(
            "    sbe_int64_t %1$s_len()            const {\n" +
                    "%2$s" +
            "        return %3$s(*((%4$s *)(m_buf + Position())));\n" +
            "    }\n\n",
            uname,
            generateArrayFieldNotPresentCondition(token.version(), BASE_INDENT),
            formatByteOrderEncoding(lengthToken.encoding().byteOrder(), lengthToken.encoding().primitiveType()),
            lengthCpp11Type
        ));
    }

    private void generateChoiceSet(final List<Token> tokens) throws IOException
    {
        final String bitSetName = formatClassName(tokens.get(0).name());

        try (final Writer out = outputManager.createOutput(bitSetName))
        {
            final List<String> headers = Arrays.asList("<algorithm>", "<vector>");
            out.append(generateFileHeader(ir.applicableNamespace().replace('.', '_'), bitSetName, headers));
            out.append(generateClassDeclaration(bitSetName));
            out.append(generateFixedFlyweightCode(bitSetName, tokens.get(0).size()));

            out.append(String.format(
                "\n" +
                "    %1$s& Clear() {\n" +
                "        *((%2$s *)(m_buf + m_offset)) = 0;\n" +
                "        return *this;\n" +
                "    }\n\n",
                bitSetName,
                cpp11TypeName(tokens.get(0))
            ));

            List<String> choices = new ArrayList<String>();
            out.append(generateChoices(bitSetName, tokens.subList(1, tokens.size() - 1), choices));
            out.append(generateChoiceSetPrint(bitSetName, choices));

            out.append("};\n");
            fileEndIfdef(out, bitSetName, true);
        }
    }

    private void generateEnum(final List<Token> tokens) throws IOException
    {
        final Token enumToken = tokens.get(0);
        final String enumName = formatClassName(tokens.get(0).name());

        try (final Writer out = outputManager.createOutput(enumName))
        {
            out.append(generateFileHeader(ir.applicableNamespace().replace('.', '_'), enumName, null));
            out.append(generateEnumDeclaration(enumName, enumToken, tokens.subList(1, tokens.size() - 1)));

            out.append(generateEnumLookupMethod(
                           tokens.subList(1, tokens.size() - 1), enumToken
                       ));
            out.append(generateEnumToStringMethod(tokens.subList(1, tokens.size() - 1)));

            out.append("};\n");
            fileEndIfdef(out, enumName, true);
        }
    }

    private void generateComposite(final List<Token> tokens) throws IOException
    {
        final String compositeName = formatClassName(tokens.get(0).name());

        try (final Writer out = outputManager.createOutput(compositeName))
        {
            out.append(generateFileHeader(ir.applicableNamespace().replace('.', '_'), compositeName, null));
            out.append(generateClassDeclaration(compositeName));
            out.append(generateFixedFlyweightCode(compositeName, tokens.get(0).size()));

            final List<Token> fieldTokens = tokens.subList(1, tokens.size() - 1);
            out.append(generatePrimitivePropertyEncodings(
                           compositeName, fieldTokens, BASE_INDENT
                       ));

            NodeList fields = fieldTokens.stream()
                                         .collect(NodeList::new, NodeList::add, NodeList::addAll);
            out.append(generateCompositePrint(compositeName, fields, BASE_INDENT));

            out.append("};\n\n");

            fileEndIfdef(out, compositeName, true);
        }
    }

    private CharSequence generateChoiceNotPresentCondition(final int sinceVersion, final String indent)
    {
        if (0 == sinceVersion)
        {
            return "";
        }

        return String.format(
            indent + "        if (m_version < %1$d)\n" +
            indent + "            return false;\n\n",
            sinceVersion
        );
    }

    private CharSequence generateStreamPrint(boolean isGroup, final String name, final NodeList fields, final String indent)
    {
        final StringBuilder sb = new StringBuilder();

        sb.append(String.format(
            indent + "    // Print method for %1$s %2$s\n" +
            indent + "    friend inline std::ostream& operator<< (std::ostream& out, const %1$s& a) {\n",
            name, isGroup ? "group" : "message"));

        if (!isGroup)
        {
            sb.append(indent);
            sb.append("        out << a.Name()  << \" (\" << a.SemanticType() << \") {sz=\"    << a.BufSize()\n");
            sb.append(indent);
            sb.append("            << \", blen=\" << a.BlockLen() << \", ver=\" << a.Version() << \"}\\n\";\n");
        }

        for (final Node node : fields)
        {
            final String uname = uncamelName(node.name);

            sb.append(String.format(
                indent + "        out << '|' << std::setw(%1$3d) << std::right << a.%2$s_tag() << std::left;\n" +
                indent + "        out << '|' << std::setw( 5) << a.%2$s_offset() << std::right << '|';\n",
                TAG_PRINT_WIDTH,
                uname
            ));

            if (node.type == FieldType.GROUP)
            {
                sb.append(String.format(
                    indent + "        out << \"==[ group ]\" << std::string(%4$d-11, '=') << '|' << std::string(%5$d-%6$d, '=');\n" +
                    indent + "        out << \"[ \" << a.%7$s_name() << \" ]\\n\";\n" +
                    indent + "        {\n" +
                    indent + "            auto& g = a.%7$s();\n" +
                    indent + "            while (g.HasNext()) {\n" +
                    indent + "                g.Next();\n" +
                    indent + "                out << '|' << std::setw(%3$d) << ' ';\n" +
                    indent + "                out << '|' << std::setw(6) << '|';\n" +
                    indent + "                out << \"--[\" << std::setw(3) << std::right;\n" +
                    indent + "                out << g.Index()    << '/' << std::setw(3) << std::left;\n" +
                    indent + "                out << g.Count()    << ']' << std::string(%4$d-11, '-');\n" +
                    indent + "                out << '|' << std::right << std::string(%5$d-%6$d, '-') << \"[ \";\n" +
                    indent + "                out << g.Name()     << \" ] (hdrsz=\" << g.HeaderSize() << \", blen=\"\n" +
                    indent + "                    << g.BlockLen() << ')' << std::endl;\n" +
                    indent + "                out << g;\n" +
                    indent + "            }\n" +
                    indent + "        }\n",
                    NAME_PRINT_WIDTH + TYPE_PRINT_WIDTH - 13,
                    NAME_PRINT_WIDTH + TYPE_PRINT_WIDTH - uname.length() - 13,
                    TAG_PRINT_WIDTH,
                    TYPE_PRINT_WIDTH,
                    NAME_PRINT_WIDTH,
                    uname.length(),
                    uname
                ));
            }
            else
            {
                sb.append(String.format(
                    indent + "        out << std::left  << std::setw(%1$3d) << a.%3$s_meta(MetaAttr::SEMANTIC_TYPE) << '|';\n" +
                    indent + "        out << std::right << std::setw(%2$3d) << \"%4$s\";\n" +
                    indent + "        out << \" = \"; %5$s << std::endl;\n",
                    TYPE_PRINT_WIDTH,
                    NAME_PRINT_WIDTH,
                    uname,
                    node.name,
                    valOrNull(node, "out", "a.")
                ));
            }
        }

        sb.append(indent).append("        return out;\n")
          .append(indent).append("    }\n\n");
        return sb;
    }

    private CharSequence valOrNull(final Node node, final String stream, final String pfx)
    {
        if (node.type != FieldType.SIMPLE)
        {
            return String.format("%s << %s%s()", stream, pfx, uncamelName(node.name));
        }

        String castType;
        final String type = cpp11TypeName(node.token);

        switch (node.ctype) {
            case CHAR:
                castType = node.isArray ? "const char*" : "char";
                break;
            case UINT8:
            case UINT16:
            case INT8:
            case INT16:
                castType = "int";
                break;
            default:
                castType = type;
                break;
        }

        return String.format(
            "ValOrNull<%1$s>(%2$s, %3$s%4$s(), %3$s%4$s_null())",
            castType, stream, pfx, uncamelName(node.name)
        );
    }

    private CharSequence generateCompositePrint(final String name, final List<Node> fields, final String indent)
    {
        final StringBuilder sb  = new StringBuilder();
        int                 i   = fields.size();
        final String        eol = (i > 5 ? "\\n" : "");

        sb.append(String.format(
            indent + "    friend inline std::ostream& operator<< (std::ostream& out, const %1$s& a) {\n" +
            indent + "        out << \"%1$s{\"%2$s;\n",
            name, eol
        ));

        for (final Node node : fields)
        {
            final String comma = --i > 0 ? (eol.isEmpty() ? "<< \", \"" : "\",\"") : "";
            sb.append(String.format(
                indent + "        out << \"%1$s=\"; %2$s%3$s%4$s;\n",
                node.name,
                valOrNull(node, "out", "a."),
                comma,
                eol
            ));
        }
        sb.append(indent + "        out << \"}\";\n" +
            indent + "        return out;\n" +
            indent + "    }\n\n"
        );
        return sb;
    }

    private CharSequence generateChoiceSetPrint(final String name, final List<String> choices)
    {
        final StringBuilder sb = new StringBuilder();
        sb.append(String.format(
            "    friend inline std::ostream& operator<< (std::ostream& out, const %1$s& a) {\n" +
            "        std::vector<std::string> v;\n",
            name
        ));
        int maxWid = Math.max(
            1, choices.stream().mapToInt(String::length).summaryStatistics().getMax()
        );

        for (final String s : choices)
        {
            final String fmt = "%-" + (maxWid - s.length() + 1) + "s";
            sb.append(String.format(
            "        if (a.%s())" + fmt + "v.push_back(\"%s\");\n", uncamelName(s), " ", s));
        }
        sb.append(
            "        int i=v.size();\n" +
            "        for(auto& s : v) { out << s; if (--i) out << '|'; }\n" +
            "        return out;\n" +
            "    }\n\n"
        );
        return sb;
    }

    private CharSequence generateChoices(final String bitsetClassName, final List<Token> tokens,
        List<String> choices)
    {
        final StringBuilder sb = new StringBuilder();

        for (final Token token : tokens)
        {
            if (token.signal() == Signal.CHOICE)
            {
                final String choiceName = token.name();
                final String typeName = cpp11TypeName(token);
                final String choiceBitPosition = token.encoding().constValue().toString();
                final String byteOrderStr = formatByteOrderEncoding(
                    token.encoding().byteOrder(), token.encoding().primitiveType());

                choices.add(choiceName);

                sb.append(String.format(
                    "    bool %1$s() const {\n" +
                            "%2$s" +
                    "        return (%3$s(*((%4$s *)(m_buf + m_offset))) & (0x1L << %5$s)) != 0;\n" +
                    "    }\n\n",
                    uncamelName(choiceName),
                    generateChoiceNotPresentCondition(token.version(), BASE_INDENT),
                    byteOrderStr,
                    typeName,
                    choiceBitPosition
                ));

                sb.append(String.format(
                    "    %1$s& %2$s(bool val) {\n" +
                    "        %3$s bits = %4$s(*((%3$s *)(m_buf + m_offset)));\n" +
                    "        bits = val ? (bits | (0x1L << %5$s)) : (bits & ~(0x1L << %5$s));\n" +
                    "        *((%3$s *)(m_buf + m_offset)) = %4$s(bits);\n" +
                    "        return *this;\n" +
                    "    }\n\n",
                    bitsetClassName,
                    uncamelName(choiceName),
                    typeName,
                    byteOrderStr,
                    choiceBitPosition
                ));
            }
        }

        return sb;
    }

    private CharSequence generateEnumValues(final List<Token> tokens, final Token encodingToken)
    {
        final StringBuilder  sb = new StringBuilder();
        final Encoding encoding = encodingToken.encoding();
        final String    nullVal = "NULL_VALUE";

        int maxWid = Collections.max(
            tokens.stream().collect(
                () -> new LinkedList<>(Arrays.asList(nullVal.length())),
                (c, t) -> c.add(t.name().length()), LinkedList::addAll
            )
        );

        sb.append("    enum Value {\n");

        for (final Token token : tokens)
        {
            final CharSequence constVal = generateLiteral(token, token.encoding().constValue().toString(), false);
            sb.append(
                String.format(
                    "        %-" + maxWid + "s = %s,\n",
                    token.name(),
                    constVal
            ));
        }

        sb.append(String.format(
            "        %1$-" + maxWid + "s = %2$s",
            nullVal,
            generateLiteral(encodingToken, encoding.applicableNullValue().toString(), false)
        ));

        sb.append("\n    };\n");

        return sb;
    }

    private CharSequence generateEnumToStringMethod(final List<Token> tokens)
    {
        final StringBuilder  sb = new StringBuilder();
        final String defaultVal = "default";
        final String nullVal    = "NULL_VALUE";

        int maxWid = Collections.max(
            tokens.stream()
                  .collect(
                      () -> new LinkedList<>(Arrays.asList(defaultVal.length() + 5)),
                      (c, t) -> c.add(t.name().length()), LinkedList::addAll
                  ));

        sb.append(
            "    const char* c_str() const { return c_str(m_val); }\n" +
            "    static const char* c_str(Value v) {\n" +
            "        switch (v) {\n");

        for (final Token token : tokens)
        {
            sb.append(
                String.format(
                    "            case %1$-" + maxWid + "s: return \"%1$s\";\n",
                    token.name()
                )
            );
        }

        sb.append(
            String.format(
                "            %1$-" + (maxWid + 5) + "s: return \"%2$s\";\n" +
                "        }\n" +
                "    }\n",
                defaultVal,
                nullVal
            )
        );

        return sb;
    }

    private CharSequence generateEnumLookupMethod(final List<Token> tokens, final Token encodingToken)
    {
        final String enumName = formatClassName(encodingToken.name());
        final StringBuilder sb = new StringBuilder();

        sb.append(String.format(
           "    static %1$s Get(const %2$s val) {\n" +
           "        switch (val) {\n",
           enumName,
           cpp11TypeName(tokens.get(0))
        ));

        final String nullVal = encodingToken.encoding().applicableNullValue().toString();
        int maxWid = Collections.max(
            tokens.stream().collect(
                () -> new LinkedList<>(Arrays.asList(nullVal.length())),
                (c, t) -> c.add(t.encoding().constValue().toString().length()),
                LinkedList::addAll
            ));

        for (final Token token : tokens)
        {
            final String sval = token.encoding().constValue().toString();
            sb.append(String.format(
                "            case %1$-" + maxWid + "s: return %2$s;\n",
                sval,
                token.name())
            );
        }

        sb.append(String.format(
            "            case %1$-" + maxWid + "s: return NULL_VALUE;\n" +
            "            default: throw std::runtime_error(\"unknown value for enum %2$s [E103]\");\n" +
            "        }\n" +
            "    }\n",
            nullVal,
            enumName
        ));

        return sb;
    }

    private CharSequence generateFieldNotPresentCondition(final Token token, final String indent, boolean isConst)
    {
        if (0 == token.version())
        {
            return "";
        }

        return String.format(
            indent + "        if (m_version < %1$d)\n" +
            indent + "            return %2$s;\n\n",
            token.version(),
            generateLiteral(token, token.encoding().applicableNullValue().toString(), isConst)
        );
    }

    private CharSequence generateArrayFieldNotPresentCondition(final int sinceVersion, final String indent)
    {
        if (0 == sinceVersion)
        {
            return "";
        }

        return String.format(
            indent + "        if (m_version < %1$d)\n" +
            indent + "            return 0;\n\n",
            sinceVersion
        );
    }

    private CharSequence generateTypeFieldNotPresentCondition(final int sinceVersion, final String indent)
    {
        if (0 == sinceVersion)
        {
            return "";
        }

        return String.format(
            indent + "        if (m_version < %1$d)\n" +
            indent + "            return NULL;\n\n",
            sinceVersion
        );
    }

    private String ifdefName(final String name)
    {
        final StringBuilder sb = new StringBuilder();
        sb.append("_SBE");
        if (outerNamespace != null)
        {
            sb.append("_"); sb.append(outerNamespace.toUpperCase());
        }
        sb.append("_");
        sb.append(innerNamespace.toUpperCase());
        sb.append("_");
        sb.append(name.toUpperCase());
        sb.append("_HPP_");
        return sb.toString();
    }

    private CharSequence generateFileHeader(final String namespaceName, final String className,
        final List<String> typesToInclude)
    {
        return generateFileHeader(namespaceName, className, typesToInclude, true, true);
    }

    private void generateSbeMainInclude(final String namespace) throws IOException
    {
        final String fileName = "sbe";
        try (final Writer out = outputManager.createOutput(fileName))
        {
            out.append(generateFileHeader(namespace, fileName, null, false, false));

            out.append(
                "#if defined(SBE_HAVE_CMATH)\n" +
                "/* cmath needed for std::numeric_limits<double>::quiet_NaN() */\n" +
                "#  include <cmath>\n" +
                "#  define SBE_FLOAT_NAN  std::numeric_limits<float>::quiet_NaN()\n" +
                "#  define SBE_DOUBLE_NAN std::numeric_limits<double>::quiet_NaN()\n" +
                "#else\n" +
                "/* math.h needed for NAN */\n" +
                "#  include <math.h>\n" +
                "#  define SBE_FLOAT_NAN  NAN\n" +
                "#  define SBE_DOUBLE_NAN NAN\n" +
                "#endif\n\n" +
                "#include <limits>\n" +
                "#include <cassert>\n" +
                "#ifndef _SBE_CPP11_GENERATOR_\n" +
                "#define _SBE_CPP11_GENERATOR_\n" +
                "#endif\n" +
                "#include <sbe/sbe.hpp>\n" +
                "#include <type_traits>\n" +
                "#include <ostream>\n\n");

            out.append(String.format(
                (outerNamespace == null ? "" : ("namespace " + outerNamespace + " {\n")) +
                "namespace %1$s {\n\n" +
                "    using sbe::MetaAttr;\n\n" +
                "    inline const char* MetaAttrStr(MetaAttr a, const char* s1, const char* s2, const char* s3) {\n" +
                "        const char* vals[] = {s1, s2, s3};\n" +
                "        assert(std::size_t(a) < (sizeof(vals) / sizeof(vals[0])));\n" +
                "        return vals[std::size_t(a)];\n" +
                "    }\n\n" +
                "template <class CastT, class T>\n" +
                "inline std::ostream& ValOrNull(std::ostream& out, const T& a, const T& null) {\n" +
                "    if      (a == null)                     out << \"<null>\";\n" +
                "    else if (std::is_same<T, CastT>::value) out << a;\n" +
                "    else                                    out << (CastT)a;\n" +
                "    return out;\n" +
                "}\n\n",
                namespace
            ));

            fileEndIfdef(out, fileName, true);
        }
    }


    private CharSequence generateFileHeader(final String namespaceName, final String className,
        final List<String> typesToInclude, boolean incDefines, boolean incNamespace)
    {
        this.innerNamespace = namespaceName;
        final StringBuilder sb = new StringBuilder();

        sb.append("// vim:ts=4:sw=4:et\n");
        sb.append("//------------------------------------------------------------------------------\n");
        sb.append("// Generated SBE (Simple Binary Encoding) message codec\n");
        sb.append("//------------------------------------------------------------------------------\n");
        if (this.copyright != null)
        {
            sb.append(String.format(
                "// Copyright (c) %1$d %2$s\n",
                Calendar.getInstance().get(Calendar.YEAR),
                this.copyright));
        }
        sb.append("// Copyright (c) 2013 Real Logic Limited (Apache 2.0 license)\n");
        sb.append("//------------------------------------------------------------------------------\n");
        sb.append("// FILE IS AUTO-GENERATED FROM SCHEMA - DON'T MODIFY BY HAND!\n");
        sb.append("//------------------------------------------------------------------------------\n");

        sb.append(String.format(
            "#ifndef %1$s\n" +
            "#define %1$s\n\n",
            ifdefName(className)
        ));

        boolean addnl = false;

        if (incDefines)
        {
            sb.append(String.format("#include <%1$s/sbe.hpp>\n", outputSubdir));
            addnl = true;
        }

        if (typesToInclude != null)
        {
            for (final String incName : typesToInclude)
            {
                if (!incName.isEmpty() && incName.charAt(0) == '<' && incName.endsWith(">"))
                {
                    sb.append("#include " + incName + "\n");
                }
                else
                {
                    sb.append(String.format(
                        "#include <%1$s/%2$s.hpp>\n",
                        outputSubdir,
                        toUpperFirstChar(incName)
                    ));
                }
            }
            addnl = true;
        }

        if (addnl)
        {
            sb.append("\n");
        }

        if (incNamespace)
        {
            sb.append(String.format(
                (outerNamespace == null ? "" : ("namespace " + outerNamespace + " {\n")) +
                "namespace %1$s {\n\n",
                namespaceName
            ));
        }

        return sb;
    }

    private CharSequence generateClassDeclaration(final String className)
    {
        return String.format(
            "class %s {\n",
            className
        );
    }

    private CharSequence generateEnumDeclaration(final String name, final Token token, final List<Token> tokens)
    {
        final CharSequence values = generateEnumValues(tokens, token);
        return String.format(
            "struct %1$s {\n" +
            "%3$s\n" +
            "private:\n" +
            "    static const size_t s_size = 1+%2$d;\n" +
            "    Value  m_val;\n" +
            "public:\n\n" +
            "    explicit %1$s(int    v) : m_val(Value(v))   {}\n" +    // TODO: Add assert() ???
            "    explicit %1$s(size_t v) : m_val(Value(v))   {}\n" +
            "    %1$s()                  : m_val(NULL_VALUE) {}\n" +
            "    constexpr %1$s(Value v) : m_val(v) {}\n\n"  +
            "    operator Value() const { return m_val; }\n" +
            "    bool     Empty() const { return m_val == NULL_VALUE; }\n\n" +
            "    inline friend std::ostream& operator<< (std::ostream& out, %1$s a) {\n" +
            "        return out << %1$s::c_str(a);\n" +
            "    }\n",
            name,
            tokens.size(),
            values
        );
    }

    private CharSequence generatePrimitivePropertyEncodings(
        final String containingClassName, final List<Token> tokens, final String indent)
    {
        final StringBuilder sb = new StringBuilder();

        for (final Token token : tokens)
        {
            if (token.signal() == Signal.ENCODING)
            {
                sb.append(generatePrimitiveProperty(containingClassName, token.name(), token, indent));
            }
        }

        return sb;
    }

    private CharSequence generatePrimitiveProperty(
        final String containingClassName, final String propertyName, final Token token, final String indent)
    {
        final StringBuilder sb = new StringBuilder();

        sb.append(generatePrimitiveFieldMetaData(propertyName, token, indent));

        if (Encoding.Presence.CONSTANT == token.encoding().presence())
        {
            sb.append(generateConstPropertyMethods(propertyName, token, indent));
        }
        else
        {
            sb.append(generatePrimitivePropertyMethods(containingClassName, propertyName, token, indent));
        }

        return sb;
    }

    private CharSequence generatePrimitivePropertyMethods(
        final String containingClassName, final String propertyName, final Token token, final String indent)
    {
        final int arrayLength = token.arrayLength();

        if (arrayLength == 1)
        {
            return generateSingleValueProperty(containingClassName, propertyName, token, indent);
        }
        else if (arrayLength > 1)
        {
            return generateArrayProperty(containingClassName, propertyName, token, indent);
        }

        return "";
    }

    private CharSequence generatePrimitiveFieldMetaData(final String propertyName, final Token token, final String indent)
    {
        final StringBuilder sb = new StringBuilder();

        final String cpp11TypeName = cpp11TypeName(token, true);
        final CharSequence nullValueString = generateNullValueLiteral(token, true);

        sb.append(String.format(
            indent + "    static %1$s %2$s_null() { return %3$s; }\n",
            cpp11TypeName,
            uncamelName(propertyName),
            nullValueString
        ));

        sb.append(String.format(
            indent + "    static %1$s %2$s_min()  { return %3$s; }\n",
            cpp11TypeName,
            uncamelName(propertyName),
            generateLiteral(token, token.encoding().applicableMinValue().toString(), true)
        ));

        sb.append(String.format(
            indent + "    static %1$s %2$s_max()  { return %3$s; }\n",
            cpp11TypeName,
            uncamelName(propertyName),
            generateLiteral(token, token.encoding().applicableMaxValue().toString(), true)
        ));

        return sb;
    }

    private CharSequence generateSingleValueProperty(
        final String containingClassName, final String propertyName, final Token token, final String indent)
    {
        final String cpp11TypeName = cpp11TypeName(token);
        final int offset = token.offset();

        final StringBuilder sb = new StringBuilder();

        sb.append(String.format(
            "\n" +
            indent + "    %1$s %2$s() const {\n" +
                              "%3$s" +
            indent + "        return %4$s(*((%1$s *)(m_buf + m_offset + %5$d)));\n" +
            indent + "    }\n\n",
            cpp11TypeName,
            uncamelName(propertyName),
            generateFieldNotPresentCondition(token, indent, true),
            formatByteOrderEncoding(
                token.encoding().byteOrder(), token.encoding().primitiveType()
            ),
            offset
        ));

        sb.append(String.format(
            indent + "    %1$s& %2$s(const %3$s val) {\n" +
            indent + "        *((%3$s *)(m_buf + m_offset + %4$d)) = %5$s(val);\n" +
            indent + "        return *this;\n" +
            indent + "    }\n\n",
            formatClassName(containingClassName),
            uncamelName(propertyName),
            cpp11TypeName,
            offset,
            formatByteOrderEncoding(
                token.encoding().byteOrder(), token.encoding().primitiveType()
            )
        ));

        return sb;
    }

    private CharSequence generateArrayProperty(
        final String containingClassName, final String propertyName, final Token token, final String indent)
    {
        final String cpp11Type         = cpp11TypeName(token);
        final String cpp11NonArrayType = cpp11TypeName(token.encoding().primitiveType(), false);
        final Integer offset = Integer.valueOf(token.offset());

        final StringBuilder sb = new StringBuilder();

        sb.append(String.format(
            "\n" +
            indent + "    static const int %1$s_len() { return %2$d; }\n",
            uncamelName(propertyName),
            Integer.valueOf(token.arrayLength())
        ));

        sb.append(String.format(
            indent + "    const char* %1$s() const {\n" +
                              "%2$s" +
            indent + "        return (m_buf + m_offset + %3$d);\n" +
            indent + "    }\n\n",
            uncamelName(propertyName),
            generateTypeFieldNotPresentCondition(token.version(), indent),
            offset
        ));

        sb.append(String.format(
            indent + "    %1$s %2$s(int idx) const {\n" +
            indent + "        if (idx < 0 || idx >= %3$d)\n" +
            indent + "            throw std::runtime_error(\"index out of range for %2$s [E104]\");\n\n" +
                             "%4$s" +
            indent + "        return %5$s(*((%1$s*)(m_buf + m_offset + %6$d + (idx * %7$d))));\n" +
            indent + "    }\n\n",
            cpp11NonArrayType,
            uncamelName(propertyName),
            token.arrayLength(),
            generateFieldNotPresentCondition(token, indent, true),
            formatByteOrderEncoding(token.encoding().byteOrder(), token.encoding().primitiveType()),
            offset,
            token.encoding().primitiveType().size()
        ));

        sb.append(String.format(
            indent + "    void %1$s(int idx, %2$s val) {\n" +
            indent + "        if (idx < 0 || idx >= %3$d)\n" +
            indent + "            throw std::runtime_error(\"index out of range for %1$s [E105]\");\n\n" +
            indent + "        *((%2$s*)(m_buf + m_offset + %4$d + (idx * %5$d))) = %6$s(val);\n" +
            indent + "    }\n\n",
            uncamelName(propertyName),
            cpp11NonArrayType,
            token.arrayLength(),
            offset,
            token.encoding().primitiveType().size(),
            formatByteOrderEncoding(token.encoding().byteOrder(), token.encoding().primitiveType())
        ));

        sb.append(String.format(
            indent + "    int %1$s(char* dst, const int length) const {\n" +
            indent + "        if (length > %2$d)\n" +
            indent + "             throw std::runtime_error(\"length too large for get %1$s [E106]\");\n\n" +
                             "%3$s" +
            indent + "        ::memcpy(dst, m_buf + m_offset + %4$d, length);\n" +
            indent + "        return length;\n" +
            indent + "    }\n\n",
            uncamelName(propertyName),
            token.arrayLength(),
            generateArrayFieldNotPresentCondition(token.version(), indent),
            offset
        ));

        sb.append(String.format(
            indent + "    %1$s& %2$s(const char* src) {\n" +
            indent + "        ::memcpy(m_buf + m_offset + %3$d, src, %4$d);\n" +
            indent + "        return *this;\n" +
            indent + "    }\n",
            containingClassName,
            uncamelName(propertyName),
            offset,
            token.arrayLength()
        ));

        return sb;
    }

    private CharSequence generateConstPropertyMethods(final String propertyName, final Token token, final String indent)
    {
        final String cpp11TypeName = cpp11TypeName(token);

        if (token.encoding().primitiveType() != PrimitiveType.CHAR)
        {
            return String.format(
                "\n" +
                indent + "    %1$s %2$s() const { return %3$s; }\n\n",
                cpp11TypeName,
                uncamelName(propertyName),
                generateLiteral(token, token.encoding().constValue().toString(), true)
            );
        }

        final StringBuilder sb = new StringBuilder();

        final byte[] constantValue = token.encoding().constValue().byteArrayValue(token.encoding().primitiveType());
        final StringBuilder values = new StringBuilder();
        for (final byte b : constantValue)
        {
            values.append(b).append(", ");
        }
        if (values.length() > 0)
        {
            values.setLength(values.length() - 2);
        }

        sb.append(String.format(
            "\n" +
            indent + "    static const int %1$s_len() { return %2$d; }\n\n",
            uncamelName(propertyName),
            constantValue.length
        ));

        sb.append(String.format(
            indent + "    const char* %1$s() const {\n" +
            indent + "        static const uint8_t s_%1$s_vals[] = {%2$s, '\\0'};\n\n" +
            indent + "        return (const char*)s_%1$s_vals;\n" +
            indent + "    }\n\n",
            uncamelName(propertyName),
            values
        ));

        sb.append(String.format(
            indent + "    %1$s %2$s(int idx) const {\n" +
            indent + "        static const uint8_t s_%2$s_vals[] = {%3$s, '\\0'};\n\n" +
            indent + "        return s_%2$s_vals[idx];\n" +
            indent + "    }\n\n",
            cpp11TypeName,
            uncamelName(propertyName),
            values
        ));

        sb.append(String.format(
            indent + "    int %1$s(char* dst, int len) const {\n" +
            indent + "        static const uint8_t s_%2$s_vals[] = {%3$s, '\\0'};\n" +
            indent + "        static const int     s_size = sizeof(s_%2$s_vals)-1;\n" +
            indent + "        int bytes = (len <   s_size) ? len : s_size;\n\n" +
            indent + "        ::memcpy(dst, s_%2$s_vals, bytes);\n" +
            indent + "        return bytes;\n" +
            indent + "    }\n",
            uncamelName(propertyName),
            uncamelName(propertyName),
            values
        ));

        return sb;
    }

    private CharSequence generateFixedFlyweightCode(final String className, final int size)
    {
        return String.format(
            "private:\n" +
            "    // Fields are mutable because the class can be used for both encoding/decoding\n" +
            "    mutable char* m_buf;\n" +
            "    mutable int   m_offset;\n" +
            "    mutable int   m_version;\n\n" +
            "public:\n" +
            "    %1$s() : m_buf(NULL), m_offset(0), m_version(0) {}\n\n" +
            "    %1$s(char* buffer, int offset, int vsn, int bufsz)\n" +
            "        : m_buf(buffer), m_offset(offset), m_version(vsn)\n" +
            "    {\n" +
            "        if (SBE_BOUNDS_CHECK_EXPECT((offset > (bufsz - %2$s)), 0))\n" +
            "            throw std::runtime_error(\"buffer too short for flyweight [E107]\");\n" +
            "    }\n\n" +
            "    %1$s& Wrap(char* buffer, int offset, int vsn, int bufsz) {\n" +
            "        new (this) %1$s(buffer, offset, vsn, bufsz);\n" +
            "        return *this;\n" +
            "    }\n\n" +
            "    const %1$s& Wrap(char* buffer, int offset, int vsn, int bufsz) const {\n" +
            "        new (const_cast<%1$s*>(this)) %1$s(buffer, offset, vsn, bufsz);\n" +
            "        return *this;\n" +
            "    }\n\n" +
            "    static const int Size() { return %2$s; }\n\n",
            className,
            Integer.valueOf(size)
        );
    }

    private CharSequence generateMessageFlyweightCode(final String className, final Token token)
    {
        final String blockLengthType = cpp11TypeName(ir.headerStructure().blockLengthType(), false);
        final String templateIdType = cpp11TypeName(ir.headerStructure().templateIdType(), false);
        final String schemaIdType = cpp11TypeName(ir.headerStructure().schemaIdType(), false);
        final String schemaVersionType = cpp11TypeName(ir.headerStructure().schemaVersionType(), false);
        final String semanticType = token.encoding().semanticType() == null ? "" : token.encoding().semanticType();

        return String.format(
            "private:\n" +
            "    // Fields are mutable because the class can be used for both encoding/decoding\n" +
            "    mutable char*  m_buf;\n" +
            "    mutable size_t m_buf_size;\n" +
            "    mutable int    m_offset;\n" +
            "    mutable int    m_position;\n" +
            "    mutable int    m_block_len;\n" +
            "    mutable int    m_version;\n" +
            "    mutable int*   m_pos_ptr;\n\n" +
            "    %10$s(const %10$s&) {}\n" +
            "public:\n\n" +
            "    %10$s() : m_buf(NULL), m_buf_size(0), m_offset(0) {}\n\n" +
            "    %10$s(const char* buf, int offset, int blk_len, int vsn, size_t bufsz)\n" +
            "        : m_buf(const_cast<char*>(buf)), m_buf_size(bufsz),   m_offset(offset)\n" +
            "        , m_position(offset + blk_len),  m_block_len(blk_len), m_version(vsn)\n" +
            "        , m_pos_ptr(&m_position)\n" +
            "    {}\n\n" +
            "    static constexpr %1$s BlockLen()            { return %2$s; }\n" +
            "    static constexpr %3$s TemplateID()          { return %4$s; }\n" +
            "    static constexpr %5$s SchemaID()            { return %6$s; }\n" +
            "    static constexpr %7$s SchemaVersion()       { return %8$s; }\n" +
            "    static constexpr const char* SemanticType() { return \"%9$s\"; }\n" +
            "    static constexpr const char* Name()         { return \"%10$s\"; }\n" +
            "    uint64_t                     Offset() const { return m_offset; }\n\n" +
            "    %10$s&\n" +
            "    WrapForEncode(char* buffer, int offset, size_t bufsz) {\n" +
            "        m_buf           = buffer;\n" +
            "        m_offset        = offset;\n" +
            "        m_buf_size      = bufsz;\n" +
            "        m_block_len     = BlockLen();\n" +
            "        m_version       = SchemaVersion();\n" +
            "        Position(offset + m_block_len);\n" +
            "        m_pos_ptr       = &m_position;\n" +
            "        return *this;\n" +
            "    }\n\n" +
            "    const %10$s&\n" +
            "    WrapForDecode(const char* buffer, int offset, int blk_len, int vsn, size_t bufsz) const {\n" +
            "        m_buf           = const_cast<char*>(buffer);\n" +
            "        m_offset        = offset;\n" +
            "        m_buf_size      = bufsz;\n" +
            "        m_block_len     = blk_len;\n" +
            "        m_version       = vsn;\n" +
            "        int pos         = offset+m_block_len;\n" +
            "        if (SBE_BOUNDS_CHECK_EXPECT((pos > long(m_buf_size)), 0))\n" +
            "            throw std::runtime_error(\"buffer too short [E100]\");\n" +
            "        m_position      = pos;\n" +
            "        m_pos_ptr       = &m_position;\n" +
            "        return *this;\n" +
            "    }\n\n" +
            "    uint64_t    Position() const { return m_position; }\n" +
            "    void Position(uint64_t position) {\n" +
            "        if (SBE_BOUNDS_CHECK_EXPECT((position > long(m_buf_size)), 0))\n" +
            "            throw std::runtime_error(\"buffer too short [E100]\");\n" +
            "        m_position = position;\n" +
            "    }\n\n" +
            "    int         Size()     const { return Position() - m_offset; }\n" +
            "    char*       Buffer()         { return m_buf; }\n" +
            "    const char* Buffer()   const { return m_buf; }\n" +
            "    size_t      BufSize()  const { return m_buf_size; }\n" +
            "    int         Version()  const { return m_version; }\n",
            blockLengthType,
            generateLiteral(ir.headerStructure().blockLengthType(), Integer.toString(token.size()), false, false),
            templateIdType,
            generateLiteral(ir.headerStructure().templateIdType(), Integer.toString(token.id()), false, false),
            schemaIdType,
            generateLiteral(ir.headerStructure().schemaIdType(), Integer.toString(ir.id()), false, false),
            schemaVersionType,
            generateLiteral(ir.headerStructure().schemaVersionType(), Integer.toString(token.version()), false, false),
            semanticType,
            className
        );
    }

    private CharSequence generateFields(final String containingClassName,
        final List<Token> tokens, final String indent, final NodeList fields)
    {
        final StringBuilder sb = new StringBuilder();

        for (int i = 0, size = tokens.size(); i < size; i++)
        {
            final Token signalToken = tokens.get(i);
            if (signalToken.signal() == Signal.BEGIN_FIELD)
            {
                final Token encodingToken = tokens.get(i + 1);
                final String propertyName = formatPropertyName(signalToken.name());

                sb.append(String.format(
                    "\n" +
                    indent + "    static const char* %1$s_name()             { return \"%3$s\"; }\n" +
                    indent + "    static const int   %1$s_tag()              { return %2$d; }\n",
                    uncamelName(propertyName),
                    signalToken.id(),
                    propertyName
                ));

                sb.append(String.format(
                    indent + "    static const int   %1$s_since_version()    { return %2$d; }\n" +
                    indent + "    bool               %1$s_in_version() const { return (m_version >= %2$d); }\n" +
                    indent + "    int                %1$s_offset()     const { return m_offset + %3$d; }\n",
                    uncamelName(propertyName),
                    signalToken.version(),
                    signalToken.offset()
                ));

                generateFieldMetaAttributeMethod(sb, signalToken, indent);

                switch (encodingToken.signal())
                {
                    case ENCODING:
                        if (Encoding.Presence.CONSTANT != encodingToken.encoding().presence())
                        {
                            fields.add(propertyName, encodingToken);
                        }
                        sb.append(generatePrimitiveProperty(containingClassName, propertyName, encodingToken, indent));
                        break;

                    case BEGIN_ENUM:
                        final Node node = fields.add(propertyName, encodingToken);
                        sb.append(generateEnumProperty(containingClassName, propertyName, encodingToken, node, indent));
                        break;

                    case BEGIN_SET:
                        fields.add(propertyName, encodingToken);
                        sb.append(generateBitsetProperty(propertyName, encodingToken, indent));
                        break;

                    case BEGIN_COMPOSITE:
                        fields.add(propertyName, encodingToken);
                        sb.append(generateCompositeProperty(propertyName, encodingToken, indent));
                        break;
                }
            }
        }

        return sb;
    }

    private void generateFieldMetaAttributeMethod(final StringBuilder sb, final Token token, final String indent)
    {
        final Encoding encoding = token.encoding();
        final String epoch = encoding.epoch() == null ? "" : encoding.epoch();
        final String timeUnit = encoding.timeUnit() == null ? "" : encoding.timeUnit();
        final String semanticType = encoding.semanticType() == null ? "" : encoding.semanticType();

        sb.append(String.format(
            "\n" +
            indent + "    static const char* %1$s_meta(MetaAttr a) { return MetaAttrStr(a, \"%2$s\", \"%3$s\", \"%4$s\"); }\n",
            uncamelName(token.name()),
            epoch,
            timeUnit,
            semanticType
        ));
    }

    private CharSequence generateEnumFieldNotPresentCondition(final int sinceVersion, final String enumName, final String indent)
    {
        if (0 == sinceVersion)
        {
            return "";
        }

        return String.format(
            indent + "        if (m_version < %1$d)\n" +
            indent + "            return %2$s::NULL_VALUE;\n",
            Integer.valueOf(sinceVersion),
            enumName
        );
    }

    private CharSequence generateEnumProperty(
        final String containingClassName, final String propertyName, final Token token, final Node node, final String indent)
    {
        final String enumName = token.name();
        final String typeName = cpp11TypeName(token);
        final Integer offset = Integer.valueOf(token.offset());

        final StringBuilder sb = new StringBuilder();

        sb.append(String.format(
            "\n" +
            indent + "    %1$s %2$s() const {\n" +
                             "%3$s" +
            indent + "        return %1$s(%4$s(*((%5$s *)(m_buf + m_offset + %6$d))));\n" +
            indent + "    }\n\n",
            enumName,
            uncamelName(propertyName),
            generateEnumFieldNotPresentCondition(token.version(), enumName, indent),
            formatByteOrderEncoding(token.encoding().byteOrder(), token.encoding().primitiveType()),
            typeName,
            offset
        ));

        sb.append(String.format(
            indent + "    %1$s& %2$s(%3$s val) {\n" +
            indent + "        *((%4$s *)(m_buf + m_offset + %5$d)) = %6$s(val);\n" +
            indent + "        return *this;\n" +
            indent + "    }\n\n",
            formatClassName(containingClassName),
            uncamelName(propertyName),
            enumName,
            typeName,
            offset,
            formatByteOrderEncoding(token.encoding().byteOrder(), token.encoding().primitiveType())
        ));

        return sb;
    }

    private Object generateBitsetProperty(final String propertyName, final Token token, final String indent)
    {
        final StringBuilder sb = new StringBuilder();

        final String bitsetName = formatClassName(token.name());
        final Integer offset = Integer.valueOf(token.offset());

        sb.append(String.format(
            "\n" +
            indent + "private:\n" +
            indent + "    mutable %1$s m_%2$s;\n\n" +
            indent + "public:\n",
            bitsetName,
            uncamelName(propertyName)
        ));

        sb.append(String.format(
            "\n" +
            indent + "    %1$s& %2$s() {\n" +
            indent + "        m_%2$s.Wrap(m_buf, m_offset + %3$d, m_version, m_buf_size);\n" +
            indent + "        return m_%2$s;\n" +
            indent + "    }\n" +
            indent + "    const %1$s& %2$s() const {\n" +
            indent + "        m_%2$s.Wrap(m_buf, m_offset + %3$d, m_version, m_buf_size);\n" +
            indent + "        return m_%2$s;\n" +
            indent + "    }\n\n",
            bitsetName,
            uncamelName(propertyName),
            offset
        ));

        return sb;
    }

    private Object generateCompositeProperty(final String propertyName, final Token token, final String indent)
    {
        final String compositeName = formatClassName(token.name());
        final Integer offset = Integer.valueOf(token.offset());

        final StringBuilder sb = new StringBuilder();

        sb.append(String.format(
            "\n" +
            indent + "private:\n" +
            indent + "    mutable %1$s m_%2$s;\n\n" +
            indent + "public:\n",
            compositeName,
            uncamelName(propertyName)
        ));

        sb.append(String.format(
            "\n" +
            indent + "    %1$s& %2$s() {\n" +
            indent + "        m_%2$s.Wrap(m_buf, m_offset + %3$d, m_version, m_buf_size);\n" +
            indent + "        return m_%2$s;\n" +
            indent + "    }\n" +
            indent + "    const %1$s& %2$s() const {\n" +
            indent + "        m_%2$s.Wrap(m_buf, m_offset + %3$d, m_version, m_buf_size);\n" +
            indent + "        return m_%2$s;\n" +
            indent + "    }\n",
            compositeName,
            uncamelName(propertyName),
            offset
        ));

        return sb;
    }

    private CharSequence generateNullValueLiteral(final Token token, boolean isConst)
    {
        // Visual C++ does not handle minimum integer values properly
        // See: http://msdn.microsoft.com/en-us/library/4kh09110.aspx
        // So some of the null values get special handling
        if(null == token.encoding().nullValue())
        {
            switch (token.encoding().primitiveType())
            {
                case CHAR:
                case FLOAT:
                case DOUBLE:
                    break; // no special handling
                case INT8:
                    return "std::numeric_limits<int8_t>::lowest()";
                case INT16:
                    return "std::numeric_limits<int16_t>::lowest()";
                case INT32:
                    return "std::numeric_limits<int>::lowest()";
                case INT64:
                    return "std::numeric_limits<int64_t>::lowest()";
                case UINT8:
                    return "std::numeric_limits<uint8_t>::max()";
                case UINT16:
                    return "std::numeric_limits<uint16_t>::max()";
                case UINT32:
                    return "std::numeric_limits<uint32_t>::max()";
                case UINT64:
                    return "std::numeric_limits<uint64_t>::max()";
            }
        }
        return generateLiteral(token, token.encoding().applicableNullValue().toString(), isConst);
    }


    private CharSequence generateLiteral(final Token token, final String value, boolean isConst)
    {
        final PrimitiveType type = token.encoding().primitiveType();
        return generateLiteral(type, value, token.arrayLength() > 1, isConst);
    }

    private CharSequence generateLiteral(final PrimitiveType type, final String value, boolean isArray, boolean isConst)
    {
        String literal = "";

        final String castType = cpp11TypeName(type, isArray, isConst);

        switch (type)
        {
            case CHAR:
            case UINT8:
            case INT8:
            case UINT16:
            case INT16:
                literal = "(" + castType + ")" + value;
                break;

            case UINT32:
            case INT32:
                literal = value;
                break;

            case FLOAT:
                if (value.endsWith("NaN"))
                {
                    literal = "SBE_FLOAT_NAN";
                }
                else
                {
                    literal = value + "f";
                }
                break;

            case INT64:
                literal = value + "L";
                break;

            case UINT64:
                literal = "0x" + Long.toHexString(Long.parseLong(value)) + "L";
                break;

            case DOUBLE:
                if (value.endsWith("NaN"))
                {
                    literal = "SBE_DOUBLE_NAN";
                }
                else
                {
                    literal = value;
                }
        }

        return literal;
    }
}
