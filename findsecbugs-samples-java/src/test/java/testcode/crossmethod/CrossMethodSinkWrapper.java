package testcode.crossmethod;

import java.io.IOException;

public class CrossMethodSinkWrapper {

    public static void runStatic(String command) throws IOException {
        Runtime.getRuntime().exec(command);
    }

    public void runInstance(String command) throws IOException {
        Runtime.getRuntime().exec(command);
    }
}
