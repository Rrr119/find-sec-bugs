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
import edu.umd.cs.findbugs.ba.AnalysisContext;
import edu.umd.cs.findbugs.classfile.ClassDescriptor;
import edu.umd.cs.findbugs.classfile.DescriptorFactory;
import edu.umd.cs.findbugs.classfile.Global;
import edu.umd.cs.findbugs.classfile.MethodDescriptor;
import edu.umd.cs.findbugs.util.ClassName;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.Collections;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.Set;
import java.util.concurrent.atomic.AtomicBoolean;
import org.apache.bcel.Repository;
import org.apache.bcel.classfile.JavaClass;
import org.apache.bcel.classfile.Method;

/**
 * Helpers for deriving method summaries on demand and recognizing sanitizer
 * annotations. The class is intentionally optional: existing detectors keep
 * their current constructors and abstract method signatures.
 */
public final class CrossMethodTaintTracker {

    public static final String SANITIZER_ANNOTATIONS_CONFIG = "sanitizer-annotations.txt";

    private static final AtomicBoolean ENABLED = new AtomicBoolean(
            !Boolean.getBoolean("findsecbugs.crossmethod.disabled"));

    private static final Set<String> SANITIZER_ANNOTATION_NAMES = Collections.synchronizedSet(new HashSet<String>());

    private static final Set<String> SANITIZER_METHODS = Collections.synchronizedSet(new HashSet<String>());

    private static final ThreadLocal<Set<String>> ACTIVE_SUMMARIES = new ThreadLocal<Set<String>>() {
        @Override
        protected Set<String> initialValue() {
            return new HashSet<String>();
        }
    };

    static {
        loadAnnotationNames();
        String extraAnnotations = System.getProperty("findsecbugs.sanitizer.annotations");
        if (extraAnnotations != null) {
            for (String name : extraAnnotations.split(",")) {
                registerSanitizerAnnotation(name);
            }
        }
        String extraMethods = System.getProperty("findsecbugs.sanitizer.methods");
        if (extraMethods != null) {
            for (String signature : extraMethods.split(",")) {
                registerSanitizerMethod(signature);
            }
        }
    }

    private CrossMethodTaintTracker() {
    }

    public static boolean isEnabled() {
        return ENABLED.get();
    }

    public static void setEnabled(boolean enabled) {
        ENABLED.set(enabled);
    }

    /**
     * Registers an annotation type as a sanitizer annotation.
     *
     * @param annotationName dotted or slashed fully qualified name
     */
    public static void registerSanitizerAnnotation(String annotationName) {
        if (annotationName == null) {
            return;
        }
        String normalized = normalizeName(annotationName);
        if (!normalized.isEmpty()) {
            SANITIZER_ANNOTATION_NAMES.add(normalized);
        }
    }

    /**
     * Registers a sanitizer method using its slashed FindSecBugs key, for
     * example {@code com/example/Html.clean(Ljava/lang/String;)Ljava/lang/String;}.
     */
    public static void registerSanitizerMethod(String methodSignature) {
        if (methodSignature == null) {
            return;
        }
        String normalized = methodSignature.trim().replace('.', '/');
        int argumentStart = normalized.indexOf('(');
        if (argumentStart > 0 && normalized.indexOf('.', argumentStart) < 0) {
            int lastSlashBeforeArgs = normalized.lastIndexOf('/', argumentStart);
            if (lastSlashBeforeArgs >= 0) {
                normalized = normalized.substring(0, lastSlashBeforeArgs) + '.'
                        + normalized.substring(lastSlashBeforeArgs + 1);
            }
        }
        if (!normalized.isEmpty()) {
            SANITIZER_METHODS.add(normalized);
        }
    }

    /**
     * Registers a sanitizer method using its JVM descriptor.
     */
    public static void registerSanitizerMethod(String className, String methodName, String signature) {
        if (className != null && methodName != null && signature != null) {
            SANITIZER_METHODS.add(buildKey(className, methodName, signature));
        }
    }

    public static boolean isSanitizerMethod(String className, String methodName, String signature) {
        return SANITIZER_METHODS.contains(buildKey(className, methodName, signature));
    }

    public static boolean isSanitizerAnnotationType(String annotationType) {
        if (annotationType == null) {
            return false;
        }
        String name = annotationType;
        if (name.startsWith("L") && name.endsWith(";")) {
            name = name.substring(1, name.length() - 1);
        }
        name = normalizeName(name);
        if (SANITIZER_ANNOTATION_NAMES.contains(name)) {
            return true;
        }
        int slash = name.lastIndexOf('/');
        String simpleName = slash < 0 ? name : name.substring(slash + 1);
        return "Sanitizer".equals(simpleName) || "Sanitize".equals(simpleName)
                || "Sanitized".equals(simpleName) || "TaintSanitizer".equals(simpleName);
    }

    static String buildKey(String className, String methodName, String signature) {
        return normalizeName(className) + "." + methodName + signature;
    }

    public static boolean resolveCallee(String className, String methodName, String signature,
            boolean isStatic, TaintConfig taintConfig) {
        if (!isEnabled() || taintConfig == null || className == null || methodName == null || signature == null) {
            return false;
        }
        if (className.startsWith("[")) {
            return false;
        }
        String key = buildKey(className, methodName, signature);
        if (taintConfig.containsKey(key)) {
            return true;
        }
        if (SANITIZER_METHODS.contains(key)) {
            taintConfig.put(key, safeConfig());
            return true;
        }
        if (!isApplicationClass(className)) {
            return false;
        }

        JavaClass ownerClass;
        Method method;
        try {
            JavaClass calleeClass = Repository.lookupClass(className);
            MethodLocation location = findMethod(calleeClass, methodName, signature);
            if (location == null || location.method.isAbstract() || location.method.isNative()) {
                return false;
            }
            ownerClass = location.owner;
            method = location.method;
        } catch (ClassNotFoundException | LinkageError ex) {
            return false;
        }

        MethodDescriptor descriptor = edu.umd.cs.findbugs.bcel.BCELUtil
                .getMethodDescriptor(ownerClass, method);
        String descriptorKey = BCELUtil.getSlashedClassName(ownerClass) + "."
                + methodName + signature;
        Set<String> active = ACTIVE_SUMMARIES.get();
        if (!active.add(descriptorKey)) {
            return false;
        }
        try {
            Global.getAnalysisCache().getMethodAnalysis(TaintDataflow.class, descriptor);
            return taintConfig.containsKey(descriptorKey) || taintConfig.containsKey(key);
        } catch (Exception | LinkageError ex) {
            return false;
        } finally {
            active.remove(descriptorKey);
        }
    }

    private static boolean isApplicationClass(String className) {
        AnalysisContext context = AnalysisContext.currentAnalysisContext();
        if (context == null) {
            return false;
        }
        try {
            String slashedName = ClassName.toSlashedClassName(className);
            ClassDescriptor descriptor = DescriptorFactory.instance().getClassDescriptor(slashedName);
            return context.isApplicationClass(descriptor);
        } catch (RuntimeException ex) {
            return false;
        }
    }

    private static MethodLocation findMethod(JavaClass javaClass, String methodName, String signature) {
        Method method = findDeclaredMethod(javaClass, methodName, signature);
        if (method != null) {
            return new MethodLocation(javaClass, method);
        }
        for (String parentName : BCELUtil.getParentClassNames(javaClass)) {
            try {
                JavaClass parent = Repository.lookupClass(parentName);
                Method parentMethod = findDeclaredMethod(parent, methodName, signature);
                if (parentMethod != null && !parentMethod.isAbstract()) {
                    return new MethodLocation(parent, parentMethod);
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

    static TaintMethodConfig safeConfig() {
        try {
            return new TaintMethodConfig(true).load("SAFE");
        } catch (IOException ex) {
            throw new IllegalStateException("Invalid built-in SAFE taint summary", ex);
        }
    }

    private static String normalizeName(String name) {
        String result = name.trim();
        if (result.startsWith("L") && result.endsWith(";") && result.length() > 2) {
            result = result.substring(1, result.length() - 1);
        }
        return result.replace('.', '/');
    }

    private static void loadAnnotationNames() {
        InputStream input = CrossMethodTaintTracker.class.getClassLoader()
                .getResourceAsStream(SANITIZER_ANNOTATIONS_CONFIG);
        if (input == null) {
            return;
        }
        Set<String> loaded = new LinkedHashSet<String>();
        try (BufferedReader reader = new BufferedReader(new InputStreamReader(input, StandardCharsets.UTF_8))) {
            String line;
            while ((line = reader.readLine()) != null) {
                String trimmed = line.trim();
                if (!trimmed.isEmpty() && !trimmed.startsWith("#")) {
                    loaded.add(normalizeName(trimmed));
                }
            }
        } catch (IOException ex) {
        }
        SANITIZER_ANNOTATION_NAMES.addAll(loaded);
    }

    private static final class MethodLocation {

        private final JavaClass owner;
        private final Method method;

        private MethodLocation(JavaClass owner, Method method) {
            this.owner = owner;
            this.method = method;
        }
    }
}
