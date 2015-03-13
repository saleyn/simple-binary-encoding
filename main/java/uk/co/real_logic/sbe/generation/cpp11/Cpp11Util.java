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
import uk.co.real_logic.sbe.ir.Token;

import java.nio.ByteOrder;
import java.util.*;

/**
 * Utilities for mapping between IR and the C++ language.
 */
public class Cpp11Util
{
    private static Map<PrimitiveType, String> typeNameByPrimitiveTypeMap = new EnumMap<>(PrimitiveType.class);

    static
    {
        typeNameByPrimitiveTypeMap.put(PrimitiveType.CHAR,   "char");
        typeNameByPrimitiveTypeMap.put(PrimitiveType.INT8,   "int8_t");
        typeNameByPrimitiveTypeMap.put(PrimitiveType.INT16,  "int16_t");
        typeNameByPrimitiveTypeMap.put(PrimitiveType.INT32,  "int32_t");
        typeNameByPrimitiveTypeMap.put(PrimitiveType.INT64,  "int64_t");
        typeNameByPrimitiveTypeMap.put(PrimitiveType.UINT8,  "uint8_t");
        typeNameByPrimitiveTypeMap.put(PrimitiveType.UINT16, "uint16_t");
        typeNameByPrimitiveTypeMap.put(PrimitiveType.UINT32, "uint32_t");
        typeNameByPrimitiveTypeMap.put(PrimitiveType.UINT64, "uint64_t");
        typeNameByPrimitiveTypeMap.put(PrimitiveType.FLOAT,  "float");
        typeNameByPrimitiveTypeMap.put(PrimitiveType.DOUBLE, "double");
    }

    /**
     * Map the name of a {@link uk.co.real_logic.sbe.PrimitiveType} to a C++11 primitive type name.
     *
     * @param token containing the primitive type to map.
     * @return the name of the Java primitive that most closely maps.
     */
    public static String cpp11TypeName(final Token token)
    {
        return cpp11TypeName(token.encoding().primitiveType(), token.arrayLength() > 1);
    }

    /**
     * Map the name of a {@link uk.co.real_logic.sbe.PrimitiveType} to a C++11 primitive type name.
     *
     * @param token containing the primitive type to map.
     * @param isConst if the value of this type is const
     * @return the name of the Java primitive that most closely maps.
     */
    public static String cpp11TypeName(final Token token, boolean isConst)
    {
        return cpp11TypeName(token.encoding().primitiveType(), token.arrayLength() > 1, isConst);
    }

    /**
     * Map the name of a {@link uk.co.real_logic.sbe.PrimitiveType} to a C++11 primitive type name.
     *
     * @param primitiveType to map.
     * @param isArray if the value of this type is an array
     * @return the name of the Java primitive that most closely maps.
     */
    public static String cpp11TypeName(final PrimitiveType primitiveType, boolean isArray)
    {
        return cpp11TypeName(primitiveType, isArray, false);
    }

    /**
     * Map the name of a {@link uk.co.real_logic.sbe.PrimitiveType} to a C++11 primitive type name.
     *
     * @param primitiveType to map.
     * @param isArray if the value of this type is an array
     * @param isConst if the value of this type is const
     * @return the name of the Java primitive that most closely maps.
     */
    public static String cpp11TypeName(final PrimitiveType primitiveType, boolean isArray, boolean isConst)
    {
        final String type = typeNameByPrimitiveTypeMap.get(primitiveType);

        // Non-const value
        if (!isConst)
        {
            return type + (isArray ? "*" : "");
        }

        // Const array value
        if (isArray)
        {
            return "const " + type + "*";
        }

        // Const non-array value
        return typeNameByPrimitiveTypeMap.get(primitiveType);
    }

    /**
     * Uppercase the first character of a given String.
     *
     * @param str to have the first character upper cased.
     * @return a new String with the first character in uppercase.
     */
    public static String toUpperFirstChar(final String str)
    {
        return Character.toUpperCase(str.charAt(0)) + str.substring(1);
    }

    /**
     * Lowercase the first character of a given String.
     *
     * @param str to have the first character upper cased.
     * @return a new String with the first character in uppercase.
     */
    public static String toLowerFirstChar(final String str)
    {
        return Character.toLowerCase(str.charAt(0)) + str.substring(1);
    }

    /**
     * Format a String as a property name.
     *
     * @param str to be formatted.
     * @return the string formatted as a property name.
     */
    public static String formatPropertyName(final String str)
    {
        return (str.length() > 1 && Character.isUpperCase(str.charAt(1)))
             ? str : toLowerFirstChar(str);
    }

    /**
     * Format a String as a class name.
     *
     * @param str to be formatted.
     * @return the string formatted as a class name.
     */
    public static String formatClassName(final String str)
    {
        return toUpperFirstChar(str);
    }

    /**
     * Return the Cpp11 formatted byte order encoding string to use for a given byte order and primitiveType
     *
     * @param byteOrder of the {@link uk.co.real_logic.sbe.ir.Token}
     * @param primitiveType of the {@link uk.co.real_logic.sbe.ir.Token}
     * @return the string formatted as the byte ordering encoding
     */
    public static String formatByteOrderEncoding(final ByteOrder byteOrder, final PrimitiveType primitiveType)
    {
        switch (primitiveType.size())
        {
            case 2:
                return "SBE_" + byteOrder + "_ENCODE_16";

            case 4:
                return "SBE_" + byteOrder + "_ENCODE_32";

            case 8:
                return "SBE_" + byteOrder + "_ENCODE_64";

            default:
                return "";
        }
    }

    public class Pair<L, R>
    {
        private L l;
        private R r;
        public Pair(L l, R r)
        {
            this.l = l;
            this.r = r;
        }
        public L    getL()
        {
            return l;
        }
        public R    getR()
        {
            return r;
        }
        public void setL(L l)
        {
            this.l = l;
        }
        public void setR(R r)
        {
            this.r = r;
        }
    }


    static enum FieldType
    {
        UNDEFINED, SIMPLE, COMPOSITE, ENUM, SET, GROUP
    }

    static class Node
    {
        public final FieldType      type;
        public final String         name;
        public final PrimitiveType  ctype;
        public final boolean        isArray;
        public final Token          token;

        public Node(Token token)
        {
            this(token.name(), token);
        }

        public Node(final String name, Token token)
        {
            switch (token.signal())
            {
                case ENCODING:        type = FieldType.SIMPLE;    break;
                case BEGIN_ENUM:      type = FieldType.ENUM;      break;
                case BEGIN_SET:       type = FieldType.SET;       break;
                case BEGIN_COMPOSITE: type = FieldType.COMPOSITE; break;
                case BEGIN_GROUP:     type = FieldType.GROUP;     break;
                default:              type = FieldType.UNDEFINED; break;
            }

            this.name    = name;
            this.ctype   = token.encoding().primitiveType();
            this.isArray = token.arrayLength() > 1;
            this.token   = token;
        }
    }

    static class NodeList extends ArrayList<Node>
    {
        public Node add(final String name, Token token)
        {
            Node node = new Node(name, token);
            super.add(node);
            return node;
        }
        public Node add(Token token)
        {
            return add(token.name(), token);
        }
    }


}
