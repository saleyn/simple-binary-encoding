/*
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
import java.util.ArrayList;
import java.util.Calendar;
import java.util.List;

import static uk.co.real_logic.sbe.generation.cpp11.Cpp11Util.*;

public class Cpp11Generator implements CodeGenerator
{
    private static final String BASE_INDENT = "";
    private static final String INDENT = "    ";

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
        final List<String> typesToInclude = generateTypeStubs();
        final String namespace = ir.applicableNamespace().replace('.', '_');

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
                offset = collectRootFields(messageBody, offset, rootFields);
                out.append(generateFields(className, rootFields, BASE_INDENT));

                final List<Token> groups = new ArrayList<>();
                offset = collectGroups(messageBody, offset, groups);
                StringBuilder sb = new StringBuilder();
                generateGroups(sb, groups, 0, BASE_INDENT);
                out.append(sb);

                final List<Token> varData = messageBody.subList(offset, messageBody.size());
                out.append(generateVarData(varData));

                out.append("};\n");
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

    private int generateGroups(final StringBuilder sb, final List<Token> tokens, int index, final String indent)
    {
        for (int size = tokens.size(); index < size; index++)
        {
            if (tokens.get(index).signal() == Signal.BEGIN_GROUP)
            {
                final Token groupToken = tokens.get(index);
                final String groupName = groupToken.name();

                generateGroupClassHeader(sb, groupName, tokens, index, indent + INDENT);

                final List<Token> rootFields = new ArrayList<>();
                index = collectRootFields(tokens, ++index, rootFields);
                sb.append(generateFields(groupName, rootFields, indent + INDENT));

                if (tokens.get(index).signal() == Signal.BEGIN_GROUP)
                {
                    index = generateGroups(sb, tokens, index, indent + INDENT);
                }

                sb.append(indent).append("    };\n");
                sb.append(generateGroupProperty(groupName, groupToken, indent));
            }
        }

        return index;
    }

    private void generateGroupClassHeader(
        final StringBuilder sb, final String groupName, final List<Token> tokens, final int index, final String indent)
    {
        final String dimensionsClassName = formatClassName(tokens.get(index + 1).name());
        final Integer dimensionHeaderSize = Integer.valueOf(tokens.get(index + 1).size());

        sb.append(String.format(
            "\n" +
            indent + "class %1$s {\n" +
            indent + "private:\n" +
            indent + "    char* m_buf;\n" +
            indent + "    int   m_buf_len;\n" +
            indent + "    int*  m_pos_ptr;\n" +
            indent + "    int   m_block_len;\n" +
            indent + "    int   m_count;\n" +
            indent + "    int   m_index;\n" +
            indent + "    int   m_offset;\n" +
            indent + "    int   m_version;\n" +
            indent + "    %2$s m_dimensions;\n\n" +
            indent + "public:\n\n",
            formatClassName(groupName),
            dimensionsClassName
        ));

        sb.append(String.format(
            indent + "    void wrap_for_decode(char* buffer, int* pos, const int vsn, const int buflen) {\n" +
            indent + "        m_buf        = buffer;\n" +
            indent + "        m_buf_len    = buflen;\n" +
            indent + "        m_dimensions.wrap(m_buf, *pos, vsn, buflen);\n" +
            indent + "        m_block_len  = m_dimensions.block_length();\n" +
            indent + "        m_count      = m_dimensions.num_in_group();\n" +
            indent + "        m_index      = -1;\n" +
            indent + "        m_version    = vsn;\n" +
            indent + "        m_pos_ptr    = pos;\n" +
            indent + "        *m_pos_ptr   = *m_pos_ptr + %1$d;\n" +
            indent + "    }\n\n",
            dimensionHeaderSize
        ));

        final Integer blockLen = Integer.valueOf(tokens.get(index).size());
        final String cpp11TypeForBlockLength = cpp11TypeName(tokens.get(index + 2).encoding().primitiveType());
        final String cpp11TypeForNumInGroup = cpp11TypeName(tokens.get(index + 3).encoding().primitiveType());

        sb.append(String.format(
            indent + "    void wrap_for_encode(char* buffer, const int count,\n" +
            indent + "                         int* pos, const int vsn, const int buflen) {\n" +
            indent + "        m_buf       = buffer;\n" +
            indent + "        m_buf_len   = buflen;\n" +
            indent + "        m_dimensions.wrap(m_buf, *pos, vsn, buflen);\n" +
            indent + "        m_dimensions.block_length((%1$s)%2$d);\n" +
            indent + "        m_dimensions.num_in_group((%3$s)count);\n" +
            indent + "        m_index     = -1;\n" +
            indent + "        m_count     = count;\n" +
            indent + "        m_block_len = %2$d;\n" +
            indent + "        m_version   = vsn;\n" +
            indent + "        m_pos_ptr   = pos;\n" +
            indent + "        *m_pos_ptr  = *m_pos_ptr + %4$d;\n" +
            indent + "    }\n\n",
            cpp11TypeForBlockLength, blockLen, cpp11TypeForNumInGroup, dimensionHeaderSize
        ));

        sb.append(String.format(
            indent + "    static const int sbe_header_size() { return %d; }\n\n",
            dimensionHeaderSize
        ));

        sb.append(String.format(
            indent + "    static const int sbe_block_len() { return %d; }\n\n",
            blockLen
        ));

        sb.append(String.format(
            indent + "    int  count()    const { return m_count; }\n\n" +
            indent + "    bool has_next() const { return m_index + 1 < m_count; }\n\n"
        ));

        sb.append(String.format(
            indent + "    %1$s& next() {\n" +
            indent + "        m_offset = *m_pos_ptr;\n" +
            indent + "        if (SBE_BOUNDS_CHECK_EXPECT(( (m_offset + m_block_len) > m_buf_len ),0))\n" +
            indent + "            throw std::runtime_error(\"buffer too short to support next group index [E108]\");\n" +
            indent + "        *m_pos_ptr = m_offset + m_block_len;\n" +
            indent + "        ++m_index;\n\n" +
            indent + "        return *this;\n" +
            indent + "    }\n\n",
            formatClassName(groupName)
        ));
    }

    private CharSequence generateGroupProperty(final String groupName, final Token token, final String indent)
    {
        final StringBuilder sb = new StringBuilder();

        final String className = formatClassName(groupName);
        final String propertyName = formatPropertyName(groupName);

        sb.append(String.format(
            "\n" +
            "private:\n" +
            indent + "    %1$s m_%2$s;\n\n" +
            "public:\n",
            className,
            uncamelName(propertyName)
        ));

        sb.append(String.format(
            "\n" +
            indent + "    static const int %1$s_id() { return %2$d; }\n\n",
            uncamelName(groupName),
            Long.valueOf(token.id())
        ));

        sb.append(String.format(
            "\n" +
            indent + "    %1$s& %2$s() {\n" +
            indent + "        m_%2$s.wrap_for_decode(m_buf, m_pos_ptr, m_version, m_buf_len);\n" +
            indent + "        return m_%2$s;\n" +
            indent + "    }\n",
            className,
            uncamelName(propertyName)
        ));

        sb.append(String.format(
            "\n" +
            indent + "    %1$s& %2$s_count(int count) {\n" +
            indent + "        m_%2$s.wrap_for_encode(m_buf, count, m_pos_ptr, m_version, m_buf_len);\n" +
            indent + "        return m_%2$s;\n" +
            indent + "    }\n",
            className,
            uncamelName(propertyName)
        ));

        return sb;
    }

    private CharSequence generateVarData(final List<Token> tokens)
    {
        final StringBuilder sb = new StringBuilder();

        for (int i = 0, size = tokens.size(); i < size; i++)
        {
            final Token token = tokens.get(i);
            if (token.signal() == Signal.BEGIN_VAR_DATA)
            {
                final String propertyName = toUpperFirstChar(token.name());
                final String characterEncoding = tokens.get(i + 3).encoding().characterEncoding();
                final Token lengthToken = tokens.get(i + 2);
                final Integer sizeOfLengthField = Integer.valueOf(lengthToken.size());
                final String lengthCpp11Type = cpp11TypeName(lengthToken.encoding().primitiveType());

                generateFieldMetaAttributeMethod(sb, token, BASE_INDENT);

                generateVarDataDescriptors(
                    sb, token, propertyName, characterEncoding, lengthToken, sizeOfLengthField, lengthCpp11Type);

                sb.append(String.format(
                    "    const char* %1$s() {\n" +
                             "%2$s" +
                    "         const char* p = (m_buf + position() + %3$d);\n" +
                    "         position(position() + %3$d + *((%4$s *)(m_buf + position())));\n" +
                    "         return p;\n" +
                    "    }\n\n",
                    uncamelName(formatPropertyName(propertyName)),
                    generateTypeFieldNotPresentCondition(token.version(), BASE_INDENT),
                    sizeOfLengthField,
                    lengthCpp11Type
                ));

                sb.append(String.format(
                    "    int get_%1$s(char* dst, const int length) {\n" +
                            "%2$s" +
                    "        auto sizeOfLengthField  = %3$d;\n" +
                    "        auto lengthPosition     = position();\n" +
                    "        position(lengthPosition + sizeOfLengthField);\n" +
                    "        auto dataLength         = %4$s(*((%5$s *)(m_buf + lengthPosition)));\n" +
                    "        int  bytesToCopy        = (length < dataLength) ? length : dataLength;\n" +
                    "        auto pos                = position();\n" +
                    "        position(position()     + (sbe_uint64_t)dataLength);\n" +
                    "        ::memcpy(dst, m_buf  + pos, bytesToCopy);\n" +
                    "        return bytesToCopy;\n" +
                    "    }\n\n",
                    uncamelName(propertyName),
                    generateArrayFieldNotPresentCondition(token.version(), BASE_INDENT),
                    sizeOfLengthField,
                    formatByteOrderEncoding(lengthToken.encoding().byteOrder(), lengthToken.encoding().primitiveType()),
                    lengthCpp11Type
                ));

                sb.append(String.format(
                    "    int put_%1$s(const char* src, int length) {\n" +
                    "        auto sizeOfLengthField  = %2$d;\n" +
                    "        auto lengthPosition     = position();\n" +
                    "        *((%3$s *)(m_buf     + lengthPosition)) = %4$s((%3$s)length);\n" +
                    "        position(lengthPosition + sizeOfLengthField);\n" +
                    "        auto pos                = position();\n" +
                    "        position(position()     + (sbe_uint64_t)length);\n" +
                    "        ::memcpy(m_buf + pos, src, length);\n" +
                    "        return length;\n" +
                    "    }\n",
                    uncamelName(propertyName),
                    sizeOfLengthField,
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
        final Integer sizeOfLengthField,
        final String lengthCpp11Type)
    {
        sb.append(String.format(
            "\n"  +
            "    static const char* %1$s_char_encoding() { return \"%2$s\"; }\n",
            uncamelName(formatPropertyName(propertyName)),
            characterEncoding
        ));

        sb.append(String.format(
            "    static const int %1$s_since_version()   { return %2$d; }\n" +
            "    bool   %1$s_in_version()          const { return m_version >= %2$s; }\n" +
            "    static const int %1$s_id()              { return %3$d; }\n",
            uncamelName(formatPropertyName(propertyName)),
            Long.valueOf(token.version()),
            Integer.valueOf(token.id())
        ));

        sb.append(String.format(
            "\n" +
            "    static const int %s_header_size()       { return %d; }\n",
            uncamelName(propertyName),
            sizeOfLengthField
        ));

        sb.append(String.format(
            "\n" +
            "    sbe_int64_t %1$s_len() const            {\n" +
                    "%2$s" +
            "        return %3$s(*((%4$s *)(m_buf + position())));\n" +
            "    }\n\n",
            uncamelName(propertyName),
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
            out.append(generateFileHeader(ir.applicableNamespace().replace('.', '_'), bitSetName, null));
            out.append(generateClassDeclaration(bitSetName));
            out.append(generateFixedFlyweightCode(bitSetName, tokens.get(0).size()));

            out.append(String.format(
                "\n" +
                "    %1$s& clear() {\n" +
                "        *((%2$s *)(m_buf + m_offset)) = 0;\n" +
                "        return *this;\n" +
                "    }\n\n",
                bitSetName,
                cpp11TypeName(tokens.get(0).encoding().primitiveType())
            ));

            out.append(generateChoices(bitSetName, tokens.subList(1, tokens.size() - 1)));

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
            out.append(generateEnumDeclaration(enumName));

            out.append(generateEnumValues(tokens.subList(1, tokens.size() - 1), enumToken));

            out.append(generateEnumLookupMethod(tokens.subList(1, tokens.size() - 1), enumToken));

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

            out.append(generatePrimitivePropertyEncodings(compositeName, tokens.subList(1, tokens.size() - 1), BASE_INDENT));

            out.append("};\n");
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
            Integer.valueOf(sinceVersion)
        );
    }

    private CharSequence generateChoices(final String bitsetClassName, final List<Token> tokens)
    {
        final StringBuilder sb = new StringBuilder();

        for (final Token token : tokens)
        {
            if (token.signal() == Signal.CHOICE)
            {
                final String choiceName = token.name();
                final String typeName = cpp11TypeName(token.encoding().primitiveType());
                final String choiceBitPosition = token.encoding().constValue().toString();
                final String byteOrderStr = formatByteOrderEncoding(
                    token.encoding().byteOrder(), token.encoding().primitiveType());

                sb.append(String.format(
                    "\n" +
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
        final StringBuilder sb = new StringBuilder();
        final Encoding encoding = encodingToken.encoding();

        sb.append("    enum value {\n");

        for (final Token token : tokens)
        {
            final CharSequence constVal = generateLiteral(
                token.encoding().primitiveType(), token.encoding().constValue().toString());
            sb.append("        ").append(token.name()).append(" = ").append(constVal).append(",\n");
        }

        sb.append(String.format(
            "        NULL_VALUE = %1$s",
            generateLiteral(encoding.primitiveType(), encoding.applicableNullValue().toString())
        ));

        sb.append("\n    };\n\n");

        return sb;
    }

    private CharSequence generateEnumLookupMethod(final List<Token> tokens, final Token encodingToken)
    {
        final String enumName = formatClassName(encodingToken.name());
        final StringBuilder sb = new StringBuilder();

        sb.append(String.format(
           "    static const %1$s::value get(const %2$s val) {\n" +
           "        switch (val) {\n",
           enumName,
           cpp11TypeName(tokens.get(0).encoding().primitiveType())
        ));

        for (final Token token : tokens)
        {
            sb.append(String.format(
                "            case %1$s: return %2$s;\n",
                token.encoding().constValue().toString(),
                token.name())
            );
        }

        sb.append(String.format(
            "            case %1$s: return NULL_VALUE;\n" +
            "        }\n\n" +
            "        throw std::runtime_error(\"unknown value for enum %2$s [E103]\");\n" +
            "    }\n",
            encodingToken.encoding().applicableNullValue().toString(),
            enumName
        ));

        return sb;
    }

    private CharSequence generateFieldNotPresentCondition(final int sinceVersion, final Encoding encoding, final String indent)
    {
        if (0 == sinceVersion)
        {
            return "";
        }

        return String.format(
            indent + "        if (m_version < %1$d)\n" +
            indent + "            return %2$s;\n\n",
            Integer.valueOf(sinceVersion),
            generateLiteral(encoding.primitiveType(), encoding.applicableNullValue().toString())
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
            Integer.valueOf(sinceVersion)
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
            Integer.valueOf(sinceVersion)
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
                "#ifndef _SBE_CPP11_GENERATOR_\n" +
                "#define _SBE_CPP11_GENERATOR_\n" +
                "#endif\n" +
                "#include <sbe/sbe.hpp>\n\n");

            out.append(String.format(
                (outerNamespace == null ? "" : ("namespace " + outerNamespace + " {\n")) +
                "namespace %1$s {\n\n" +
                "    using sbe::meta_attr;\n\n" +
                "    inline const char* meta_attr_str(meta_attr attr) {\n" +
                "        static const char* s_vals[] = {\"unix\", \"nanosecond\", \"UTCTimestamp\"};\n" +
                "        return (std::size_t(attr) < (sizeof(s_vals) / sizeof(s_vals[0])))\n" +
                "            ? s_vals[std::size_t(attr)] : \"undefined\";\n" +
                "    }\n\n",
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

        if (incDefines)
        {
            sb.append(String.format("#include <%1$s/sbe.hpp>\n", outputSubdir));
        }

        if (typesToInclude != null)
        {
            for (final String incName : typesToInclude)
            {
                sb.append(String.format(
                    "#include <%1$s/%2$s.hpp>\n",
                    outputSubdir,
                    toUpperFirstChar(incName)
                ));
            }
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

    private CharSequence generateEnumDeclaration(final String name)
    {
        return "class " + name + " {\npublic:\n\n";
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

        final Encoding encoding = token.encoding();
        final PrimitiveType primitiveType = encoding.primitiveType();
        final String cpp11TypeName = cpp11TypeName(primitiveType);
        final CharSequence nullValueString = generateNullValueLiteral(primitiveType, encoding);

        sb.append(String.format(
            indent + "    static const %1$s %2$s_null() { return %3$s; }\n",
            cpp11TypeName,
            uncamelName(propertyName),
            nullValueString
        ));

        sb.append(String.format(
            indent + "    static const %1$s %2$s_min()  { return %3$s; }\n",
            cpp11TypeName,
            uncamelName(propertyName),
            generateLiteral(primitiveType, token.encoding().applicableMinValue().toString())
        ));

        sb.append(String.format(
            indent + "    static const %1$s %2$s_max()  { return %3$s; }\n",
            cpp11TypeName,
            uncamelName(propertyName),
            generateLiteral(primitiveType, token.encoding().applicableMaxValue().toString())
        ));

        return sb;
    }

    private CharSequence generateSingleValueProperty(
        final String containingClassName, final String propertyName, final Token token, final String indent)
    {
        final String cpp11TypeName = cpp11TypeName(token.encoding().primitiveType());
        final Integer offset = Integer.valueOf(token.offset());

        final StringBuilder sb = new StringBuilder();

        sb.append(String.format(
            "\n" +
            indent + "    %1$s %2$s() const {\n" +
                              "%3$s" +
            indent + "        return %4$s(*((%1$s *)(m_buf + m_offset + %5$d)));\n" +
            indent + "    }\n\n",
            cpp11TypeName,
            uncamelName(propertyName),
            generateFieldNotPresentCondition(token.version(), token.encoding(), indent),
            formatByteOrderEncoding(token.encoding().byteOrder(), token.encoding().primitiveType()),
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
            formatByteOrderEncoding(token.encoding().byteOrder(), token.encoding().primitiveType())
        ));

        return sb;
    }

    private CharSequence generateArrayProperty(
        final String containingClassName, final String propertyName, final Token token, final String indent)
    {
        final String cpp11TypeName = cpp11TypeName(token.encoding().primitiveType());
        final Integer offset = Integer.valueOf(token.offset());

        final StringBuilder sb = new StringBuilder();

        sb.append(String.format(
            "\n" +
            indent + "    static const int %1$s_len() {\n" +
            indent + "        return %2$d;\n" +
            indent + "    }\n\n",
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
            indent + "        return %5$s(*((%1$s *)(m_buf + m_offset + %6$d + (idx * %7$d))));\n" +
            indent + "    }\n\n",
            cpp11TypeName,
            uncamelName(propertyName),
            Integer.valueOf(token.arrayLength()),
            generateFieldNotPresentCondition(token.version(), token.encoding(), indent),
            formatByteOrderEncoding(token.encoding().byteOrder(), token.encoding().primitiveType()),
            offset,
            Integer.valueOf(token.encoding().primitiveType().size())
        ));

        sb.append(String.format(
            indent + "    void %1$s(int idx, const %2$s val) {\n" +
            indent + "        if (idx < 0 || idx >= %3$d)\n" +
            indent + "            throw std::runtime_error(\"index out of range for %1$s [E105]\");\n\n" +
            indent + "        *((%2$s *)(m_buf + m_offset + %4$d + (idx * %5$d))) = %6$s(val);\n" +
            indent + "    }\n\n",
            uncamelName(propertyName),
            cpp11TypeName,
            Integer.valueOf(token.arrayLength()),
            offset,
            Integer.valueOf(token.encoding().primitiveType().size()),
            formatByteOrderEncoding(token.encoding().byteOrder(), token.encoding().primitiveType())
        ));

        sb.append(String.format(
            indent + "    int %1$s(char* dst, const int length) const {\n" +
            indent + "        if (length > %2$d)\n" +
            indent + "             throw std::runtime_error(\"length too large for get%1$s [E106]\");\n\n" +
                             "%3$s" +
            indent + "        ::memcpy(dst, m_buf + m_offset + %4$d, length);\n" +
            indent + "        return length;\n" +
            indent + "    }\n\n",
            uncamelName(propertyName),
            Integer.valueOf(token.arrayLength()),
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
            Integer.valueOf(token.arrayLength())
        ));

        return sb;
    }

    private CharSequence generateConstPropertyMethods(final String propertyName, final Token token, final String indent)
    {
        final String cpp11TypeName = cpp11TypeName(token.encoding().primitiveType());

        if (token.encoding().primitiveType() != PrimitiveType.CHAR)
        {
            return String.format(
                "\n" +
                indent + "    %1$s %2$s() const { return %3$s; }\n\n",
                cpp11TypeName,
                uncamelName(propertyName),
                generateLiteral(token.encoding().primitiveType(), token.encoding().constValue().toString())
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
            Integer.valueOf(constantValue.length)
        ));

        sb.append(String.format(
            indent + "    const char* %1$s() const {\n" +
            indent + "        static const sbe_uint8_t s_%1$s_vals[] = {%2$s};\n\n" +
            indent + "        return (const char* )s_%1$s_vals;\n" +
            indent + "    }\n\n",
            uncamelName(propertyName),
            values
        ));

        sb.append(String.format(
            indent + "    %1$s %2$s(int idx) const {\n" +
            indent + "        static const sbe_uint8_t s_%2$s_vals[] = {%3$s};\n\n" +
            indent + "        return s_%2$s_vals[idx];\n" +
            indent + "    }\n\n",
            cpp11TypeName,
            uncamelName(propertyName),
            values
        ));

        sb.append(String.format(
            indent + "    int %1$s(char* dst, const int len) const {\n" +
            indent + "        static const sbe_uint8_t s_%2$s_vals[] = {%3$s};\n" +
            indent + "        int bytes = (len < sizeof(s_%2$s_vals)) ? len : sizeof(s_%2$s_vals);\n\n" +
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
            "    char* m_buf;\n" +
            "    int   m_offset;\n" +
            "    int   m_version;\n\n" +
            "public:\n" +
            "    %1$s& wrap(char* buffer, const int offset, const int vsn, const int buflen) {\n" +
            "        if (SBE_BOUNDS_CHECK_EXPECT((offset > (buflen - %2$s)), 0))\n" +
            "            throw std::runtime_error(\"buffer too short for flyweight [E107]\");\n" +
            "        m_buf     = buffer;\n" +
            "        m_offset  = offset;\n" +
            "        m_version = vsn;\n" +
            "        return *this;\n" +
            "    }\n\n" +
            "    static const int size() { return %2$s; }\n",
            className,
            Integer.valueOf(size)
        );
    }

    private CharSequence generateMessageFlyweightCode(final String className, final Token token)
    {
        final String blockLengthType = cpp11TypeName(ir.headerStructure().blockLengthType());
        final String templateIdType = cpp11TypeName(ir.headerStructure().templateIdType());
        final String schemaIdType = cpp11TypeName(ir.headerStructure().schemaIdType());
        final String schemaVersionType = cpp11TypeName(ir.headerStructure().schemaVersionType());
        final String semanticType = token.encoding().semanticType() == null ? "" : token.encoding().semanticType();

        return String.format(
            "private:\n" +
            "    char* m_buf;\n" +
            "    int   m_buf_len;\n" +
            "    int*  m_pos_ptr;\n" +
            "    int   m_offset;\n" +
            "    int   m_position;\n" +
            "    int   m_block_len;\n" +
            "    int   m_version;\n\n" +
            "    %10$s(const %10$s&) {}\n" +
            "public:\n\n" +
            "    %10$s() : m_buf(NULL), m_buf_len(0), m_offset(0) {}\n\n" +
            "    static constexpr %1$s sbe_block_len()            { return %2$s; }\n" +
            "    static constexpr %3$s sbe_template_id()          { return %4$s; }\n" +
            "    static constexpr %5$s sbe_schema_id()            { return %6$s; }\n" +
            "    static constexpr %7$s sbe_schema_version()       { return %8$s; }\n" +
            "    static constexpr const char* sbe_semantic_type() { return \"%9$s\"; }\n" +
            "    static constexpr const char* name()              { return \"%10$s\"; }\n" +
            "    sbe_uint64_t                 offset()      const { return m_offset; }\n\n" +
            "    %10$s&\n" +
            "    wrap_for_encode(char* buffer, const int offset, const int buflen) {\n" +
            "        m_buf           = buffer;\n" +
            "        m_offset        = offset;\n" +
            "        m_buf_len       = buflen;\n" +
            "        m_block_len     = sbe_block_len();\n" +
            "        m_version       = sbe_schema_version();\n" +
            "        position(offset + m_block_len);\n" +
            "        m_pos_ptr       = &m_position;\n" +
            "        return *this;\n" +
            "    }\n\n" +
            "    %10$s&\n" +
            "    wrap_for_decode(char* buffer,  const int offset, const int blk_len,\n" +
            "                           const int vsn, const int buflen) {\n" +
            "        m_buf           = buffer;\n" +
            "        m_offset        = offset;\n" +
            "        m_buf_len       = buflen;\n" +
            "        m_block_len     = blk_len;\n" +
            "        m_version       = vsn;\n" +
            "        m_pos_ptr       = &m_position;\n" +
            "        position(offset + m_block_len);\n" +
            "        return *this;\n" +
            "    }\n\n" +
            "    sbe_uint64_t position() const  { return m_position; }\n" +
            "    void position(sbe_uint64_t position) {\n" +
            "        if (SBE_BOUNDS_CHECK_EXPECT((position > m_buf_len), 0))\n" +
            "            throw std::runtime_error(\"buffer too short [E100]\");\n" +
            "        m_position = position;\n" +
            "    }\n\n" +
            "    int   size()     const { return position() - m_offset; }\n" +
            "    char* buffer()         { return m_buf; }\n" +
            "    int   version()  const { return m_version; }\n",
            blockLengthType,
            generateLiteral(ir.headerStructure().blockLengthType(), Integer.toString(token.size())),
            templateIdType,
            generateLiteral(ir.headerStructure().templateIdType(), Integer.toString(token.id())),
            schemaIdType,
            generateLiteral(ir.headerStructure().schemaIdType(), Integer.toString(ir.id())),
            schemaVersionType,
            generateLiteral(ir.headerStructure().schemaVersionType(), Integer.toString(token.version())),
            semanticType,
            className
        );
    }

    private CharSequence generateFields(final String containingClassName, final List<Token> tokens, final String indent)
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
                    indent + "    static const int %1$s_id() { return %2$d; }\n",
                    uncamelName(propertyName),
                    Integer.valueOf(signalToken.id())
                ));

                sb.append(String.format(
                    indent + "    static const int %1$s_since_version() { return %2$d; }\n" +
                    indent + "    bool %1$s_in_version()          const { return (m_version >= %2$d); }\n",
                    uncamelName(propertyName),
                    Long.valueOf(signalToken.version())
                ));

                generateFieldMetaAttributeMethod(sb, signalToken, indent);

                switch (encodingToken.signal())
                {
                    case ENCODING:
                        sb.append(generatePrimitiveProperty(containingClassName, propertyName, encodingToken, indent));
                        break;

                    case BEGIN_ENUM:
                        sb.append(generateEnumProperty(containingClassName, propertyName, encodingToken, indent));
                        break;

                    case BEGIN_SET:
                        sb.append(generateBitsetProperty(propertyName, encodingToken, indent));
                        break;

                    case BEGIN_COMPOSITE:
                        sb.append(generateCompositeProperty(propertyName, encodingToken, indent));
                        break;
                }
            }
        }

        return sb;
    }

    private void generateFieldMetaAttributeMethod(final StringBuilder sb, final Token token, final String indent)
    {
        /*
        final Encoding encoding = token.encoding();
        final String epoch = encoding.epoch() == null ? "" : encoding.epoch();
        final String timeUnit = encoding.timeUnit() == null ? "" : encoding.timeUnit();
        final String semanticType = encoding.semanticType() == null ? "" : encoding.semanticType();
        */
        sb.append(String.format(
            "\n" +
            indent + "    static const char* %s_meta_attr(meta_attr attr) { return meta_attr_str(attr); }\n",
            uncamelName(token.name()) /*,
            epoch,
            timeUnit,
            semanticType */
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
        final String containingClassName, final String propertyName, final Token token, final String indent)
    {
        final String enumName = token.name();
        final String typeName = cpp11TypeName(token.encoding().primitiveType());
        final Integer offset = Integer.valueOf(token.offset());

        final StringBuilder sb = new StringBuilder();

        sb.append(String.format(
            "\n" +
            indent + "    %1$s::value %2$s() const {\n" +
                             "%3$s" +
            indent + "        return %1$s::get(%4$s(*((%5$s *)(m_buf + m_offset + %6$d))));\n" +
            indent + "    }\n\n",
            enumName,
            uncamelName(propertyName),
            generateEnumFieldNotPresentCondition(token.version(), enumName, indent),
            formatByteOrderEncoding(token.encoding().byteOrder(), token.encoding().primitiveType()),
            typeName,
            offset
        ));

        sb.append(String.format(
            indent + "    %1$s& %2$s(%3$s::value value) {\n" +
            indent + "        *((%4$s *)(m_buf + m_offset + %5$d)) = %6$s(value);\n" +
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
            indent + "    %1$s m_%2$s;\n\n" +
            indent + "public:\n",
            bitsetName,
            uncamelName(propertyName)
        ));

        sb.append(String.format(
            "\n" +
            indent + "    %1$s& %2$s() {\n" +
            indent + "        m_%2$s.wrap(m_buf, m_offset + %3$d, m_version, m_buf_len);\n" +
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
            "private:\n" +
            indent + "    %1$s m_%2$s;\n\n" +
            "public:\n",
            compositeName,
            uncamelName(propertyName)
        ));

        sb.append(String.format(
            "\n" +
            indent + "    %1$s& %2$s() {\n" +
            indent + "        m_%2$s.wrap(m_buf, m_offset + %3$d, m_version, m_buf_len);\n" +
            indent + "        return m_%2$s;\n" +
            indent + "    }\n",
            compositeName,
            uncamelName(propertyName),
            offset
        ));

        return sb;
    }

    private CharSequence generateNullValueLiteral(final PrimitiveType primitiveType, final Encoding encoding)
    {
        // Visual C++ does not handle minimum integer values properly
        // See: http://msdn.microsoft.com/en-us/library/4kh09110.aspx
        // So some of the null values get special handling
        if(null == encoding.nullValue())
        {
            switch (primitiveType)
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
        return generateLiteral(primitiveType, encoding.applicableNullValue().toString());
    }

    private CharSequence generateLiteral(final PrimitiveType type, final String value)
    {
        String literal = "";

        final String castType = cpp11TypeName(type);
        switch (type)
        {
            case CHAR:
            case UINT8:
            case UINT16:
            case INT8:
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
