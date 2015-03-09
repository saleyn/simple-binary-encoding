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
import java.util.List;

import static uk.co.real_logic.sbe.generation.cpp11.Cpp11Util.*;

public class Cpp11Generator implements CodeGenerator
{
    private static final String BASE_INDENT = "";
    private static final String INDENT = "    ";

    private final Ir ir;
    private final OutputManager outputManager;

    public Cpp11Generator(final Ir ir, final OutputManager outputManager)
        throws IOException
    {
        Verify.notNull(ir, "ir");
        Verify.notNull(outputManager, "outputManager");

        this.ir = ir;
        this.outputManager = outputManager;
    }

    public void generateMessageHeaderStub() throws IOException
    {
        try (final Writer out = outputManager.createOutput(MESSAGE_HEADER_TYPE))
        {
            final List<Token> tokens = ir.headerStructure().tokens();
            out.append(generateFileHeader(ir.applicableNamespace().replace('.', '_'), MESSAGE_HEADER_TYPE, null));
            out.append(generateClassDeclaration(MESSAGE_HEADER_TYPE));
            out.append(generateFixedFlyweightCode(MESSAGE_HEADER_TYPE, tokens.get(0).size()));
            out.append(
                generatePrimitivePropertyEncodings(MESSAGE_HEADER_TYPE, tokens.subList(1, tokens.size() - 1), BASE_INDENT));

            out.append("};\n}\n#endif\n");
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

        for (final List<Token> tokens : ir.messages())
        {
            final Token msgToken = tokens.get(0);
            final String className = formatClassName(msgToken.name());

            try (final Writer out = outputManager.createOutput(className))
            {
                out.append(generateFileHeader(ir.applicableNamespace().replace('.', '_'), className, typesToInclude));
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

                out.append("};\n}\n#endif\n");
            }
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
            indent + "    char *m_buffer;\n" +
            indent + "    int m_bufferLength;\n" +
            indent + "    int *m_positionPtr;\n" +
            indent + "    int m_blockLength;\n" +
            indent + "    int m_count;\n" +
            indent + "    int m_index;\n" +
            indent + "    int m_offset;\n" +
            indent + "    int m_actingVersion;\n" +
            indent + "    %2$s m_dimensions;\n\n" +
            indent + "public:\n\n",
            formatClassName(groupName),
            dimensionsClassName
        ));

        sb.append(String.format(
            indent + "    void wrapForDecode(char *buffer, int *pos, const int actingVersion, const int bufferLength) {\n" +
            indent + "        m_buffer          = buffer;\n" +
            indent + "        m_bufferLength    = bufferLength;\n" +
            indent + "        m_dimensions.wrap(m_buffer, *pos, actingVersion, bufferLength);\n" +
            indent + "        m_blockLength     = m_dimensions.blockLength();\n" +
            indent + "        m_count           = m_dimensions.numInGroup();\n" +
            indent + "        m_index           = -1;\n" +
            indent + "        m_actingVersion   = actingVersion;\n" +
            indent + "        m_positionPtr     = pos;\n" +
            indent + "        *m_positionPtr    = *m_positionPtr + %1$d;\n" +
            indent + "    }\n\n",
            dimensionHeaderSize
        ));

        final Integer blockLength = Integer.valueOf(tokens.get(index).size());
        final String cpp11TypeForBlockLength = cpp11TypeName(tokens.get(index + 2).encoding().primitiveType());
        final String cpp11TypeForNumInGroup = cpp11TypeName(tokens.get(index + 3).encoding().primitiveType());

        sb.append(String.format(
            indent + "    void wrapForEncode(char *buffer, const int count,\n" +
            indent + "                       int *pos, const int actingVersion, const int bufferLength) {\n" +
            indent + "        m_buffer          = buffer;\n" +
            indent + "        m_bufferLength    = bufferLength;\n" +
            indent + "        m_dimensions.wrap(m_buffer, *pos, actingVersion, bufferLength);\n" +
            indent + "        m_dimensions.blockLength((%1$s)%2$d);\n" +
            indent + "        m_dimensions.numInGroup((%3$s)count);\n" +
            indent + "        m_index           = -1;\n" +
            indent + "        m_count           = count;\n" +
            indent + "        m_blockLength     = %2$d;\n" +
            indent + "        m_actingVersion   = actingVersion;\n" +
            indent + "        m_positionPtr     = pos;\n" +
            indent + "        *m_positionPtr    = *m_positionPtr + %4$d;\n" +
            indent + "    }\n\n",
            cpp11TypeForBlockLength, blockLength, cpp11TypeForNumInGroup, dimensionHeaderSize
        ));

        sb.append(String.format(
            indent + "    static const int sbeHeaderSize() { return %d; }\n\n",
            dimensionHeaderSize
        ));

        sb.append(String.format(
            indent + "    static const int sbeBlockLength() { return %d; }\n\n",
            blockLength
        ));

        sb.append(String.format(
            indent + "    int  count(void)   const { return m_count; }\n\n" +
            indent + "    bool hasNext(void) const { return m_index + 1 < m_count; }\n\n"
        ));

        sb.append(String.format(
            indent + "    %1$s& next(void) {\n" +
            indent + "        m_offset = *m_positionPtr;\n" +
            indent + "        if (SBE_BOUNDS_CHECK_EXPECT(( (m_offset + m_blockLength) > m_bufferLength ),0))\n" +
            indent + "            throw std::runtime_error(\"buffer too short to support next group index [E108]\");\n" +
            indent + "        *m_positionPtr = m_offset + m_blockLength;\n" +
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
            propertyName
        ));

        sb.append(String.format(
            "\n" +
            indent + "    static const int %1$sId(void) { return %2$d; }\n\n",
            groupName,
            Long.valueOf(token.id())
        ));

        sb.append(String.format(
            "\n" +
            indent + "    %1$s& %2$s(void) {\n" +
            indent + "        m_%2$s.wrapForDecode(m_buffer, m_positionPtr, m_actingVersion, m_bufferLength);\n" +
            indent + "        return m_%2$s;\n" +
            indent + "    }\n",
            className,
            propertyName
        ));

        sb.append(String.format(
            "\n" +
            indent + "    %1$s &%2$sCount(const int count) {\n" +
            indent + "        m_%2$s.wrapForEncode(m_buffer, count, m_positionPtr, m_actingVersion, m_bufferLength);\n" +
            indent + "        return m_%2$s;\n" +
            indent + "    }\n",
            className,
            propertyName
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
                    "    const char* %1$s(void) {\n" +
                             "%2$s" +
                    "         const char* fieldPtr = (m_buffer + position() + %3$d);\n" +
                    "         position(position() + %3$d + *((%4$s *)(m_buffer + position())));\n" +
                    "         return fieldPtr;\n" +
                    "    }\n\n",
                    formatPropertyName(propertyName),
                    generateTypeFieldNotPresentCondition(token.version(), BASE_INDENT),
                    sizeOfLengthField,
                    lengthCpp11Type
                ));

                sb.append(String.format(
                    "    int get%1$s(char *dst, const int length) {\n" +
                            "%2$s" +
                    "        auto sizeOfLengthField  = %3$d;\n" +
                    "        auto lengthPosition     = position();\n" +
                    "        position(lengthPosition + sizeOfLengthField);\n" +
                    "        auto dataLength         = %4$s(*((%5$s *)(m_buffer + lengthPosition)));\n" +
                    "        int  bytesToCopy        = (length < dataLength) ? length : dataLength;\n" +
                    "        auto pos                = position();\n" +
                    "        position(position()     + (sbe_uint64_t)dataLength);\n" +
                    "        ::memcpy(dst, m_buffer  + pos, bytesToCopy);\n" +
                    "        return bytesToCopy;\n" +
                    "    }\n\n",
                    propertyName,
                    generateArrayFieldNotPresentCondition(token.version(), BASE_INDENT),
                    sizeOfLengthField,
                    formatByteOrderEncoding(lengthToken.encoding().byteOrder(), lengthToken.encoding().primitiveType()),
                    lengthCpp11Type
                ));

                sb.append(String.format(
                    "    int put%1$s(const char *src, const int length) {\n" +
                    "        auto sizeOfLengthField  = %2$d;\n" +
                    "        auto lengthPosition     = position();\n" +
                    "        *((%3$s *)(m_buffer     + lengthPosition)) = %4$s((%3$s)length);\n" +
                    "        position(lengthPosition + sizeOfLengthField);\n" +
                    "        auto pos                = position();\n" +
                    "        position(position()     + (sbe_uint64_t)length);\n" +
                    "        ::memcpy(m_buffer + pos, src, length);\n" +
                    "        return length;\n" +
                    "    }\n",
                    propertyName,
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
            "    static const char *%1$sCharacterEncoding() { return \"%2$s\"; }\n\n",
            formatPropertyName(propertyName),
            characterEncoding
        ));

        sb.append(String.format(
            "    static const int %1$sSinceVersion(void)    { return %2$d; }\n\n" +
            "    bool   %1$sInActingVersion(void)           { return m_actingVersion >= %2$s; }\n\n" +
            "    static const int %1$sId(void)              { return %3$d; }\n\n",
            formatPropertyName(propertyName),
            Long.valueOf(token.version()),
            Integer.valueOf(token.id())
        ));

        sb.append(String.format(
            "\n" +
            "    static const int %sHeaderSize()            { return %d; }\n\n",
            toLowerFirstChar(propertyName),
            sizeOfLengthField
        ));

        sb.append(String.format(
            "\n" +
            "    sbe_int64_t %1$sLength(void) const         {\n" +
                    "%2$s" +
            "        return %3$s(*((%4$s *)(m_buffer + position())));\n" +
            "    }\n\n",
            formatPropertyName(propertyName),
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
                "    %1$s &clear(void) {\n" +
                "        *((%2$s *)(m_buffer + m_offset)) = 0;\n" +
                "        return *this;\n" +
                "    }\n\n",
                bitSetName,
                cpp11TypeName(tokens.get(0).encoding().primitiveType())
            ));

            out.append(generateChoices(bitSetName, tokens.subList(1, tokens.size() - 1)));

            out.append("};\n}\n#endif\n");
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

            out.append("};\n}\n#endif\n");
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

            out.append("};\n}\n#endif\n");
        }
    }

    private CharSequence generateChoiceNotPresentCondition(final int sinceVersion, final String indent)
    {
        if (0 == sinceVersion)
        {
            return "";
        }

        return String.format(
            indent + "        if (m_actingVersion < %1$d)\n" +
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
                    "    bool %1$s(void) const {\n" +
                            "%2$s" +
                    "        return (%3$s(*((%4$s *)(m_buffer + m_offset))) & (0x1L << %5$s)) != 0;\n" +
                    "    }\n\n",
                    choiceName,
                    generateChoiceNotPresentCondition(token.version(), BASE_INDENT),
                    byteOrderStr,
                    typeName,
                    choiceBitPosition
                ));

                sb.append(String.format(
                    "    %1$s &%2$s(const bool value) {\n" +
                    "        %3$s bits = %4$s(*((%3$s *)(m_buffer + m_offset)));\n" +
                    "        bits = value ? (bits | (0x1L << %5$s)) : (bits & ~(0x1L << %5$s));\n" +
                    "        *((%3$s *)(m_buffer + m_offset)) = %4$s(bits);\n" +
                    "        return *this;\n" +
                    "    }\n",
                    bitsetClassName,
                    choiceName,
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

        sb.append("    enum Value {\n");

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
           "    static %1$s::Value get(const %2$s value) {\n" +
           "        switch (value) {\n",
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
            indent + "        if (m_actingVersion < %1$d)\n" +
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
            indent + "        if (m_actingVersion < %1$d)\n" +
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
            indent + "        if (m_actingVersion < %1$d)\n" +
            indent + "            return NULL;\n\n",
            Integer.valueOf(sinceVersion)
        );
    }

    private CharSequence generateFileHeader(final String namespaceName, final String className, final List<String> typesToInclude)
    {
        final StringBuilder sb = new StringBuilder();

        sb.append(String.format(
            "/* Generated SBE (Simple Binary Encoding) message codec */\n"
        ));

        sb.append(String.format(
            "#ifndef _%1$s_HPP_\n" +
            "#define _%1$s_HPP_\n\n" +
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
            "#include <sbe/sbe.hpp>\n\n",
            className.toUpperCase()
        ));

        if (typesToInclude != null)
        {
            for (final String incName : typesToInclude)
            {
                sb.append(String.format(
                    "#include <%1$s/%2$s.hpp>\n",
                    namespaceName,
                    toUpperFirstChar(incName)
                ));
            }
            sb.append("\n");
        }

        sb.append(String.format(
            "using namespace sbe;\n\n" +
            "namespace %1$s {\n\n",
            namespaceName
        ));

        return sb;
    }

    private CharSequence generateClassDeclaration(final String className)
    {
        return String.format(
            "class %s {\n" +
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
            "\n" +
            indent + "    static const %1$s %2$sNullValue() { return %3$s; }\n",
            cpp11TypeName,
            propertyName,
            nullValueString
        ));

        sb.append(String.format(
            "\n" +
            indent + "    static const %1$s %2$sMinValue() { return %3$s; }\n",
            cpp11TypeName,
            propertyName,
            generateLiteral(primitiveType, token.encoding().applicableMinValue().toString())
        ));

        sb.append(String.format(
            "\n" +
            indent + "    static const %1$s %2$sMaxValue() { return %3$s; }\n",
            cpp11TypeName,
            propertyName,
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
            indent + "    %1$s %2$s(void) const {\n" +
                              "%3$s" +
            indent + "        return %4$s(*((%1$s *)(m_buffer + m_offset + %5$d)));\n" +
            indent + "    }\n\n",
            cpp11TypeName,
            propertyName,
            generateFieldNotPresentCondition(token.version(), token.encoding(), indent),
            formatByteOrderEncoding(token.encoding().byteOrder(), token.encoding().primitiveType()),
            offset
        ));

        sb.append(String.format(
            indent + "    %1$s& %2$s(const %3$s value) {\n" +
            indent + "        *((%3$s *)(m_buffer + m_offset + %4$d)) = %5$s(value);\n" +
            indent + "        return *this;\n" +
            indent + "    }\n",
            formatClassName(containingClassName),
            propertyName,
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
            indent + "    static const int %1$sLength(void) {\n" +
            indent + "        return %2$d;\n" +
            indent + "    }\n\n",
            propertyName,
            Integer.valueOf(token.arrayLength())
        ));

        sb.append(String.format(
            indent + "    const char *%1$s(void) const {\n" +
                              "%2$s" +
            indent + "        return (m_buffer + m_offset + %3$d);\n" +
            indent + "    }\n\n",
            propertyName,
            generateTypeFieldNotPresentCondition(token.version(), indent),
            offset
        ));

        sb.append(String.format(
            indent + "    %1$s %2$s(const int index) const {\n" +
            indent + "        if (index < 0 || index >= %3$d)\n" +
            indent + "            throw std::runtime_error(\"index out of range for %2$s [E104]\");\n\n" +
                             "%4$s" +
            indent + "        return %5$s(*((%1$s *)(m_buffer + m_offset + %6$d + (index * %7$d))));\n" +
            indent + "    }\n\n",
            cpp11TypeName,
            propertyName,
            Integer.valueOf(token.arrayLength()),
            generateFieldNotPresentCondition(token.version(), token.encoding(), indent),
            formatByteOrderEncoding(token.encoding().byteOrder(), token.encoding().primitiveType()),
            offset,
            Integer.valueOf(token.encoding().primitiveType().size())
        ));

        sb.append(String.format(
            indent + "    void %1$s(const int index, const %2$s value) {\n" +
            indent + "        if (index < 0 || index >= %3$d)\n" +
            indent + "            throw std::runtime_error(\"index out of range for %1$s [E105]\");\n\n" +
            indent + "        *((%2$s *)(m_buffer + m_offset + %4$d + (index * %5$d))) = %6$s(value);\n" +
            indent + "    }\n\n",
            propertyName,
            cpp11TypeName,
            Integer.valueOf(token.arrayLength()),
            offset,
            Integer.valueOf(token.encoding().primitiveType().size()),
            formatByteOrderEncoding(token.encoding().byteOrder(), token.encoding().primitiveType())
        ));

        sb.append(String.format(
            indent + "    int get%1$s(char *dst, const int length) const {\n" +
            indent + "        if (length > %2$d)\n" +
            indent + "             throw std::runtime_error(\"length too large for get%1$s [E106]\");\n\n" +
                             "%3$s" +
            indent + "        ::memcpy(dst, m_buffer + m_offset + %4$d, length);\n" +
            indent + "        return length;\n" +
            indent + "    }\n\n",
            toUpperFirstChar(propertyName),
            Integer.valueOf(token.arrayLength()),
            generateArrayFieldNotPresentCondition(token.version(), indent),
            offset
        ));

        sb.append(String.format(
            indent + "    %1$s& put%2$s(const char *src) {\n" +
            indent + "        ::memcpy(m_buffer + m_offset + %3$d, src, %4$d);\n" +
            indent + "        return *this;\n" +
            indent + "    }\n",
            containingClassName,
            toUpperFirstChar(propertyName),
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
                indent + "    %1$s %2$s(void) const { return %3$s; }\n\n",
                cpp11TypeName,
                propertyName,
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
            indent + "    static const int %1$sLength(void) { return %2$d; }\n\n",
            propertyName,
            Integer.valueOf(constantValue.length)
        ));

        sb.append(String.format(
            indent + "    const char* %1$s(void) const {\n" +
            indent + "        static sbe_uint8_t %1$sValues[] = {%2$s};\n\n" +
            indent + "        return (const char *)%1$sValues;\n" +
            indent + "    }\n\n",
            propertyName,
            values
        ));

        sb.append(String.format(
            indent + "    %1$s %2$s(const int index) const {\n" +
            indent + "        static sbe_uint8_t %2$sValues[] = {%3$s};\n\n" +
            indent + "        return %2$sValues[index];\n" +
            indent + "    }\n\n",
            cpp11TypeName,
            propertyName,
            values
        ));

        sb.append(String.format(
            indent + "    int get%1$s(char* dst, const int length) const {\n" +
            indent + "        static sbe_uint8_t %2$sValues[] = {%3$s};\n" +
            indent + "        int bytesToCopy = (length < sizeof(%2$sValues)) ? length : sizeof(%2$sValues);\n\n" +
            indent + "        ::memcpy(dst, %2$sValues, bytesToCopy);\n" +
            indent + "        return bytesToCopy;\n" +
            indent + "    }\n",
            toUpperFirstChar(propertyName),
            propertyName,
            values
        ));

        return sb;
    }

    private CharSequence generateFixedFlyweightCode(final String className, final int size)
    {
        return String.format(
            "private:\n" +
            "    char* m_buffer;\n" +
            "    int   m_offset;\n" +
            "    int   m_actingVersion;\n\n" +
            "public:\n" +
            "    %1$s& wrap(char* buffer, const int offset, const int actingVersion, const int bufferLength) {\n" +
            "    {\n" +
            "        if (SBE_BOUNDS_CHECK_EXPECT((offset > (bufferLength - %2$s)), 0))\n" +
            "            throw std::runtime_error(\"buffer too short for flyweight [E107]\");\n" +
            "        m_buffer        = buffer;\n" +
            "        m_offset        = offset;\n" +
            "        m_actingVersion = actingVersion;\n" +
            "        return *this;\n" +
            "    }\n\n" +
            "    static const int size(void) const { return %2$s; }\n\n",
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
            "    char* m_buffer;\n" +
            "    int   m_bufferLength;\n" +
            "    int*  m_positionPtr;\n" +
            "    int   m_offset;\n" +
            "    int   m_position;\n" +
            "    int   m_actingBlockLength;\n" +
            "    int   m_actingVersion;\n\n" +
            "    %10$s(const %10$s&) {}\n\n" +
            "public:\n\n" +
            "    %10$s(void) : m_buffer(NULL), m_bufferLength(0), m_offset(0) {}\n\n" +
            "    static const %1$s sbeBlockLength(void)     { return %2$s; }\n\n" +
            "    static const %3$s sbeTemplateId(void)      { return %4$s; }\n\n" +
            "    static const %5$s sbeSchemaId(void)        { return %6$s; }\n\n" +
            "    static const %7$s sbeSchemaVersion(void)   { return %8$s; }\n\n" +
            "    static const char* sbeSemanticType(void)   { return %9$s; }\n\n" +
            "    sbe_uint64_t offset(void) const            { return m_offset; }\n\n" +
            "    %10$s& wrapForEncode(char* buffer, const int offset, const int bufferLength) {\n" +
            "        m_buffer            = buffer;\n" +
            "        m_offset            = offset;\n" +
            "        m_bufferLength      = bufferLength;\n" +
            "        m_actingBlockLength = sbeBlockLength();\n" +
            "        m_actingVersion     = sbeSchemaVersion();\n" +
            "        position(offset     + m_actingBlockLength);\n" +
            "        m_positionPtr       = &m_position;\n" +
            "        return *this;\n" +
            "    }\n\n" +
            "    %10$s &wrapForDecode(char *buffer, const int offset, const int actingBlockLength,\n" +
            "                         const int actingVersion, const int bufferLength) {\n" +
            "        m_buffer = buffer;\n" +
            "        m_offset = offset;\n" +
            "        m_bufferLength = bufferLength;\n" +
            "        m_actingBlockLength = actingBlockLength;\n" +
            "        m_actingVersion = actingVersion;\n" +
            "        m_positionPtr = &m_position;\n" +
            "        position(offset + m_actingBlockLength);\n" +
            "        return *this;\n" +
            "    }\n\n" +
            "    sbe_uint64_t position(void) const  { return m_position; }\n\n" +
            "    void position(const sbe_uint64_t position) {\n" +
            "        if (SBE_BOUNDS_CHECK_EXPECT((position > m_bufferLength), 0))\n" +
            "            throw std::runtime_error(\"buffer too short [E100]\");\n" +
            "        m_position = position;\n" +
            "    }\n\n" +
            "    int size(void) const               { return position() - m_offset; }\n\n" +
            "    char* buffer(void)                 { return m_buffer; }\n\n" +
            "    int actingVersion(void) const      { return m_actingVersion; }\n",
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
                    indent + "    static const int %1$sId(void) { return %2$d; }\n\n",
                    propertyName,
                    Integer.valueOf(signalToken.id())
                ));

                sb.append(String.format(
                    indent + "    static const int %1$sSinceVersion(void) { return %2$d; }\n\n" +
                    indent + "    bool %1$sInActingVersion(void)          { return (m_actingVersion >= %2$d); }\n\n",
                    propertyName,
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
        final Encoding encoding = token.encoding();
        final String epoch = encoding.epoch() == null ? "" : encoding.epoch();
        final String timeUnit = encoding.timeUnit() == null ? "" : encoding.timeUnit();
        final String semanticType = encoding.semanticType() == null ? "" : encoding.semanticType();

        sb.append(String.format(
            "\n" +
            indent + "    static const char *%sMetaAttribute(const MetaAttribute::Attribute attr) {\n" +
            indent + "        switch (attr) {\n" +
            indent + "            case MetaAttribute::EPOCH:         return \"%s\";\n" +
            indent + "            case MetaAttribute::TIME_UNIT:     return \"%s\";\n" +
            indent + "            case MetaAttribute::SEMANTIC_TYPE: return \"%s\";\n" +
            indent + "            default:                           return \"\";\n"   +
            indent + "        }\n" +
            indent + "    }\n",
            token.name(),
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
            indent + "        if (m_actingVersion < %1$d)\n" +
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
            indent + "    %1$s::Value %2$s(void) const {\n" +
                             "%3$s" +
            indent + "        return %1$s::get(%4$s(*((%5$s *)(m_buffer + m_offset + %6$d))));\n" +
            indent + "    }\n\n",
            enumName,
            propertyName,
            generateEnumFieldNotPresentCondition(token.version(), enumName, indent),
            formatByteOrderEncoding(token.encoding().byteOrder(), token.encoding().primitiveType()),
            typeName,
            offset
        ));

        sb.append(String.format(
            indent + "    %1$s& %2$s(const %3$s::Value value) {\n" +
            indent + "        *((%4$s *)(m_buffer + m_offset + %5$d)) = %6$s(value);\n" +
            indent + "        return *this;\n" +
            indent + "    }\n",
            formatClassName(containingClassName),
            propertyName,
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
            propertyName
        ));

        sb.append(String.format(
            "\n" +
            indent + "    %1$s &%2$s() {\n" +
            indent + "        m_%2$s.wrap(m_buffer, m_offset + %3$d, m_actingVersion, m_bufferLength);\n" +
            indent + "        return m_%2$s;\n" +
            indent + "    }\n",
            bitsetName,
            propertyName,
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
            propertyName
        ));

        sb.append(String.format(
            "\n" +
            indent + "    %1$s& %2$s(void) {\n" +
            indent + "        m_%2$s.wrap(m_buffer, m_offset + %3$d, m_actingVersion, m_bufferLength);\n" +
            indent + "        return m_%2$s;\n" +
            indent + "    }\n",
            compositeName,
            propertyName,
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
                    return "SCHAR_MIN";
                case INT16:
                    return "SHRT_MIN";
                case INT32:
                    return "LONG_MIN";
                case INT64:
                    return "LLONG_MIN";
                case UINT8:
                    return "UCHAR_MAX";
                case UINT16:
                    return "USHRT_MAX";
                case UINT32:
                    return "ULONG_MAX";
                case UINT64:
                    return "ULLONG_MAX";
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
