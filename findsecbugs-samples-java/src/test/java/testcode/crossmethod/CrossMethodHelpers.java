package testcode.crossmethod;

public class CrossMethodHelpers {

    public static String identity(String value) {
        return value;
    }

    public static <T> T genericIdentity(T value) {
        return value;
    }

    public static String selectSecond(String first, String second) {
        return second;
    }

    public String appendSuffix(String value) {
        return value + "-suffix";
    }

    public static String chain(String value) {
        return first(value);
    }

    private static String first(String value) {
        return second(value);
    }

    static String second(String value) {
        return identity(value);
    }

    public static String formatCommand(String value) {
        return String.format("tool --arg %s", value);
    }

    @Sanitizer
    public static String annotatedClean(String value) {
        return value.replaceAll("[^a-zA-Z0-9_-]", "");
    }

    @Sanitizer(tags = "COMMAND_INJECTION_SAFE")
    public static String taggedClean(String value) {
        return value.replaceAll("[;&|`$()<>]", "");
    }

    public static String configuredClean(String value) {
        return value.replaceAll("[^a-zA-Z0-9_-]", "");
    }
}
