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

import com.h3xstream.findbugs.test.BaseDetectorTest;
import com.h3xstream.findbugs.test.EasyBugReporter;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;

import static org.mockito.Mockito.atLeastOnce;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.verify;

public class CrossMethodTaintTrackingTest extends BaseDetectorTest {

    @BeforeClass
    public void registerConfiguredSanitizer() {
        CrossMethodTaintTracker.registerSanitizerMethod(
                "testcode/crossmethod/CrossMethodHelpers.configuredClean"
                        + "(Ljava/lang/String;)Ljava/lang/String;");
    }

    @Test
    public void detectsFlowsThroughApplicationMethods() throws Exception {
        String[] files = {
                getClassFilePath("testcode/crossmethod/CrossMethodInjection"),
                getClassFilePath("testcode/crossmethod/CrossMethodHelpers"),
                getClassFilePath("testcode/crossmethod/ExtendedCrossMethodHelpers"),
                getClassFilePath("testcode/crossmethod/CrossMethodSinkWrapper"),
                getClassFilePath("testcode/crossmethod/Sanitizer")
        };

        EasyBugReporter reporter = spy(new SecurityReporter());
        analyze(files, reporter);

        assertInjection(reporter, "CrossMethodInjection", "staticIdentity");
        assertInjection(reporter, "CrossMethodInjection", "genericWrapper");
        assertInjection(reporter, "CrossMethodInjection", "selectedArgumentWrapper");
        assertInjection(reporter, "CrossMethodInjection", "inheritedWrapper");
        assertInjection(reporter, "CrossMethodInjection", "instanceWrapper");
        assertInjection(reporter, "CrossMethodInjection", "multiLevelChain");
        assertInjection(reporter, "CrossMethodInjection", "formattedWrapper");

        assertInjection(reporter, "CrossMethodSinkWrapper", "runStatic");
        assertInjection(reporter, "CrossMethodSinkWrapper", "runInstance");

        verify(reporter, atLeastOnce()).doReportBug(
                bugDefinition()
                        .bugType("COMMAND_INJECTION")
                        .inClass("CrossMethodInjection")
                        .inMethod("staticIdentity")
                        .withPriority("High")
                        .build());
        verify(reporter, atLeastOnce()).doReportBug(
                bugDefinition()
                        .bugType("COMMAND_INJECTION")
                        .inClass("CrossMethodSinkWrapper")
                        .inMethod("runStatic")
                        .withPriority("High")
                        .build());

        verify(reporter, never()).doReportBug(
                bugDefinition()
                        .bugType("COMMAND_INJECTION")
                        .inClass("CrossMethodInjection")
                        .inMethod("annotatedSanitizerPreventsInjection")
                        .build());
        verify(reporter, never()).doReportBug(
                bugDefinition()
                        .bugType("COMMAND_INJECTION")
                        .inClass("CrossMethodInjection")
                        .inMethod("taggedSanitizerSuppressesCommandInjection")
                        .build());
        verify(reporter, never()).doReportBug(
                bugDefinition()
                        .bugType("COMMAND_INJECTION")
                        .inClass("CrossMethodInjection")
                        .inMethod("registeredSanitizerPreventsInjection")
                        .build());
    }

    private void assertInjection(EasyBugReporter reporter, String className, String methodName) {
        verify(reporter, atLeastOnce()).doReportBug(
                bugDefinition()
                        .bugType("COMMAND_INJECTION")
                        .inClass(className)
                        .inMethod(methodName)
                        .build());
    }
}
