# Cross-method taint tracking

Find Security Bugs derives taint summaries for application methods while the
existing `AbstractTaintDetector` / `BasicInjectionDetector` detectors run.
When an unconfigured application method is called, its bytecode is analyzed on
demand, so wrappers, forwarding methods, generic identities and inherited
summaries propagate taint without adding one sink configuration per project
method.

The extension is compatibility-only:

- Existing detector constructors and abstract methods are unchanged.
- Detectors extending `BasicInjectionDetector` receive the more precise
  `TaintFrame` automatically.
- Detectors implemented as pure instruction or class-name matchers do not use
  the new summary resolver and therefore keep their previous matching behavior.

## Sanitizer annotation

Annotate a cleansing function with:

```java
import com.h3xstream.findsecbugs.annotations.Sanitizer;

public final class HtmlEncoder {
    @Sanitizer
    public static String encode(String value) {
        return value == null ? null : value.replaceAll("[<>\"']", "");
    }
}
```

A bare `@Sanitizer` makes the return value safe for all injection families.
When a method only neutralizes one sink type, name the taint tag:

```java
@Sanitizer(tags = "COMMAND_INJECTION_SAFE")
public static String shellEscape(String value) {
    // ...
}
```

The annotation has `CLASS` retention. Custom annotations whose simple name is
`Sanitizer`, `Sanitize`, `Sanitized`, or `TaintSanitizer` are also recognized.
Additional annotation type names can be listed in
`sanitizer-annotations.txt` or registered with
`CrossMethodTaintTracker.registerSanitizerAnnotation(String)`.

Methods can also be registered without an annotation:

```java
CrossMethodTaintTracker.registerSanitizerMethod(
        "com/example/CommandUtil.escape",
        "(Ljava/lang/String;)Ljava/lang/String;");
```

For CI configuration, comma-separated annotation and method lists can be passed
with `findsecbugs.sanitizer.annotations` and
`findsecbugs.sanitizer.methods`. Set
`findsecbugs.crossmethod.disabled=true` to turn off on-demand summary resolution.
