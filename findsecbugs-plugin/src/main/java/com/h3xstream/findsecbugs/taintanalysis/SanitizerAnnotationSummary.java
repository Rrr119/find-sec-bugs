/**
 * Find Security Bugs
 * Copyright (c) Philippe Arteau, All rights reserved.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 3.0 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library.
 */
package com.h3xstream.findsecbugs.taintanalysis;

import com.h3xstream.findsecbugs.BCELUtil;
import edu.umd.cs.findbugs.ba.SignatureParser;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import org.apache.bcel.Repository;
import org.apache.bcel.classfile.AnnotationEntry;
import org.apache.bcel.classfile.ArrayElementValue;
import org.apache.bcel.classfile.ElementValue;
import org.apache.bcel.classfile.ElementValuePair;
import org.apache.bcel.classfile.EnumElementValue;
import org.apache.bcel.classfile.JavaClass;
import org.apache.bcel.classfile.Method;
import org.apache.bcel.classfile.SimpleElementValue;

/**
 * Converts sanitizer method annotations into ordinary taint summaries.
 */
final class SanitizerAnnotationSummary {

    private SanitizerAnnotationSummary() {
    }

    static TaintMethodConfig find(String className, String methodName, String signature) {
        try {
            JavaClass javaClass = Repository.lookupClass(className);
            Method method = findMethod(javaClass, methodName, signature);
            if (method == null) {
                return null;
            }
            for (AnnotationEntry annotation : method.getAnnotationEntries()) {
                if (CrossMethodTaintTracker.isSanitizerAnnotationType(annotation.getAnnotationType())) {
                    return toConfig(annotation, signature);
                }
            }
        } catch (ClassNotFoundException | LinkageError | RuntimeException ex) {
        }
        return null;
    }

    private static Method findMethod(JavaClass javaClass, String methodName, String signature) {
        Method method = findDeclaredMethod(javaClass, methodName, signature);
        if (method != null) {
            return method;
        }
        for (String parentName : BCELUtil.getParentClassNames(javaClass)) {
            try {
                Method parentMethod = findDeclaredMethod(Repository.lookupClass(parentName), methodName, signature);
                if (parentMethod != null) {
                    return parentMethod;
                }
            } catch (ClassNotFoundException | LinkageError ex) {
            }
        }
        return null;
    }

    private static Method findDeclaredMethod(JavaClass javaClass, String methodName, String signature) {
        if (javaClass == null) {
            return null;
        }
        for (Method method : javaClass.getMethods()) {
            if (methodName.equals(method.getName()) && signature.equals(method.getSignature())) {
                return method;
            }
        }
        return null;
    }

    private static TaintMethodConfig toConfig(AnnotationEntry annotation, String signature) {
        List<String> tags = new ArrayList<String>();
        int parameterIndex = 0;
        for (ElementValuePair pair : annotation.getElementValuePairs()) {
            String name = pair.getNameString();
            ElementValue value = pair.getValue();
            if ("parameterIndex".equals(name) && value instanceof SimpleElementValue) {
                parameterIndex = ((SimpleElementValue) value).getValueInt();
            } else if ("tags".equals(name) || "value".equals(name)) {
                addTags(value, tags);
            }
        }

        if (tags.isEmpty()) {
            return CrossMethodTaintTracker.safeConfig();
        }

        int stackIndex = parameterStackIndex(signature, parameterIndex);
        StringBuilder config = new StringBuilder().append(stackIndex).append('|');
        boolean first = true;
        for (String tag : tags) {
            String normalized = normalizeTag(tag);
            if (normalized == null) {
                continue;
            }
            if (!first) {
                config.append(',');
            }
            config.append('+').append(normalized);
            first = false;
        }
        if (first) {
            return CrossMethodTaintTracker.safeConfig();
        }
        try {
            return new TaintMethodConfig(true).load(config.toString());
        } catch (IOException ex) {
            return CrossMethodTaintTracker.safeConfig();
        }
    }

    private static void addTags(ElementValue value, List<String> tags) {
        if (value instanceof ArrayElementValue) {
            for (ElementValue element : ((ArrayElementValue) value).getElementValuesArray()) {
                addTag(element, tags);
            }
        } else {
            addTag(value, tags);
        }
    }

    private static void addTag(ElementValue value, List<String> tags) {
        if (value instanceof EnumElementValue) {
            tags.add(((EnumElementValue) value).getEnumValueString());
        } else if (value instanceof SimpleElementValue
                && value.getElementValueType() == ElementValue.STRING) {
            tags.add(((SimpleElementValue) value).getValueString());
        } else if (value != null) {
            String stringValue = value.stringifyValue();
            if (stringValue != null) {
                tags.add(stringValue);
            }
        }
    }

    private static int parameterStackIndex(String signature, int parameterIndex) {
        try {
            SignatureParser parser = new SignatureParser(signature);
            if (parameterIndex < 0 || parameterIndex >= parser.getNumParameters()) {
                return 0;
            }
            return parser.getSlotsFromTopOfStackForParameter(parameterIndex);
        } catch (RuntimeException ex) {
            return 0;
        }
    }

    private static String normalizeTag(String tag) {
        if (tag == null) {
            return null;
        }
        String normalized = tag.trim();
        int dot = normalized.lastIndexOf('.');
        if (dot >= 0) {
            normalized = normalized.substring(dot + 1);
        }
        try {
            return Taint.Tag.valueOf(normalized).name();
        } catch (IllegalArgumentException ex) {
            return null;
        }
    }
}
