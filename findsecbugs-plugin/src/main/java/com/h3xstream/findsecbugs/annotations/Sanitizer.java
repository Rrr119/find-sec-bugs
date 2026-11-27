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
package com.h3xstream.findsecbugs.annotations;

import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Marks a method or constructor as a taint sanitizer.
 *
 * <p>Without tag values, the return value is considered unconditionally safe.
 * Tag values can be used when a method only neutralizes one injection class,
 * for example {@code COMMAND_INJECTION_SAFE}.</p>
 */
@Documented
@Retention(RetentionPolicy.RUNTIME)
@Target({ElementType.METHOD, ElementType.CONSTRUCTOR})
public @interface Sanitizer {

    /**
     * Alias for {@link #tags()}, useful for concise {@code @Sanitizer("SQL_INJECTION_SAFE")}.
     */
    String[] value() default {};

    /**
     * Taint tags added to the sanitized parameter. An empty array means all taint is removed.
     */
    String[] tags() default {};

    /**
     * Zero-based formal parameter index whose value is sanitized.
     */
    int parameterIndex() default 0;
}
