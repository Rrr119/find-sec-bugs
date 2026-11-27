package testcode.crossmethod;

import javax.servlet.http.HttpServletRequest;

public class CrossMethodInjection {

    public void staticIdentity(HttpServletRequest request) throws Exception {
        String command = CrossMethodHelpers.identity(request.getParameter("command"));
        Runtime.getRuntime().exec(command);
    }

    public void genericWrapper(HttpServletRequest request) throws Exception {
        String command = CrossMethodHelpers.genericIdentity(request.getParameter("command"));
        Runtime.getRuntime().exec(command);
    }

    public void selectedArgumentWrapper(HttpServletRequest request) throws Exception {
        String command = CrossMethodHelpers.selectSecond("safe", request.getParameter("command"));
        Runtime.getRuntime().exec(command);
    }

    public void inheritedWrapper(HttpServletRequest request) throws Exception {
        String command = new ExtendedCrossMethodHelpers().appendSuffix(request.getParameter("command"));
        Runtime.getRuntime().exec(command);
    }

    public void instanceWrapper(HttpServletRequest request) throws Exception {
        String command = new CrossMethodHelpers().appendSuffix(request.getParameter("command"));
        Runtime.getRuntime().exec(command);
    }

    public void multiLevelChain(HttpServletRequest request) throws Exception {
        String command = CrossMethodHelpers.chain(request.getParameter("command"));
        Runtime.getRuntime().exec(command);
    }

    public void formattedWrapper(HttpServletRequest request) throws Exception {
        String command = CrossMethodHelpers.formatCommand(request.getParameter("command"));
        Runtime.getRuntime().exec(command);
    }

    public void staticSinkWrapper(HttpServletRequest request) throws Exception {
        CrossMethodSinkWrapper.runStatic(request.getParameter("command"));
    }

    public void instanceSinkWrapper(HttpServletRequest request) throws Exception {
        new CrossMethodSinkWrapper().runInstance(request.getParameter("command"));
    }

    public void annotatedSanitizerPreventsInjection(HttpServletRequest request) throws Exception {
        String command = CrossMethodHelpers.annotatedClean(request.getParameter("command"));
        Runtime.getRuntime().exec(command);
    }

    public void taggedSanitizerSuppressesCommandInjection(HttpServletRequest request) throws Exception {
        String command = CrossMethodHelpers.taggedClean(request.getParameter("command"));
        Runtime.getRuntime().exec(command);
    }

    public void registeredSanitizerPreventsInjection(HttpServletRequest request) throws Exception {
        String command = CrossMethodHelpers.configuredClean(request.getParameter("command"));
        Runtime.getRuntime().exec(command);
    }
}
