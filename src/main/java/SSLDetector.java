
import soot.*;
import soot.jimple.*;
import soot.jimple.internal.JAssignStmt;
import soot.jimple.internal.JCastExpr;
import soot.jimple.internal.JInvokeStmt;
import soot.toolkits.graph.*;
import soot.util.Chain;
import soot.tagkit.LineNumberTag;
import soot.tagkit.Tag;

import java.io.*;
import java.util.*;
import java.util.concurrent.*;

import soot.jimple.toolkits.callgraph.CallGraph;
import soot.jimple.toolkits.callgraph.Edge;

public class SSLDetector {
    private static final String X509_TRUST_MANAGER = "javax.net.ssl.X509TrustManager";
    private static final String HOSTNAME_VERIFIER = "javax.net.ssl.HostnameVerifier";
    private static final String SSL_CONTEXT = "javax.net.ssl.SSLContext";
    private static final String SSL_SOCKET_FACTORY = "javax.net.ssl.SSLSocketFactory";
    private static final Set<String> WEAK_PROTOCOLS = new HashSet<>(Arrays.asList(
            "SSL", "SSLV2", "SSLV3", "TLSV1", "TLSV1.1"
    ));
    private static final Set<SootClass> analyzedClasses = Collections.synchronizedSet(new HashSet<>());
    private static final Set<Value> analyzedTrustManagerInstances = Collections.synchronizedSet(new HashSet<>());
    private static final Set<String> TARGET_CLASSES = new HashSet<>(Arrays.asList(
            "javax.net.ssl.SSLContext", "javax.net.ssl.SSLSocketFactory"
    ));

    public static List<String> detect(BlockingQueue<SootMethod> methodQueue) {
        System.out.println("SSLDetector Detecting...");
        List<String> vulnerabilities = Collections.synchronizedList(new ArrayList<>());
        vulnerabilities.add("=== SSLDetector Vulnerability Report ===");
        analyzedTrustManagerInstances.clear();
        ExecutorService executor = Executors.newFixedThreadPool(5);
        List<CompletableFuture<Void>> futures = new ArrayList<>();

        while (!methodQueue.isEmpty()) {
            SootMethod method = methodQueue.poll();
            if (method != null) {
                CompletableFuture<Void> future = CompletableFuture.runAsync(() -> {
                    try {
                        analyzeMethod(method, vulnerabilities);
                    } catch (InterruptedException e) {
                        System.err.println("Task interrupted: " + method.getSignature() + ": " + e.getMessage());
                        Thread.currentThread().interrupt(); // 恢复中断状态
                    } catch (Exception e) {
                        System.err.println("Error: " + method.getSignature() + ": " + e.getMessage());
                    }
                }, executor).orTimeout(5, TimeUnit.SECONDS).exceptionally(e -> {
                    // 实时打印超时
                    if (e.getCause() instanceof TimeoutException) {
                        System.err.println("Timeout: " + method.getSignature() + " after 5 seconds");
                    }
                    return null;
                });
                futures.add(future);
            }
        }

        // 等待任务完成或超时
        CompletableFuture.allOf(futures.toArray(new CompletableFuture[0])).whenComplete((result, throwable) -> {
            futures.forEach(f -> f.cancel(true)); // 取消未完成任务
            executor.shutdownNow(); // 强制终止线程池
            try {
                if (!executor.awaitTermination(5, TimeUnit.SECONDS)) {
                    System.err.println("Executor forced shutdown");
                }
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        }).join();

        vulnerabilities.add("=== End of Report ===");
        return vulnerabilities;
    }

    private static void analyzeMethod(SootMethod method, List<String> vulnerabilities) throws InterruptedException {

        SootClass sootClass = method.getDeclaringClass();
        Body body = SootAnalysisWorker.getMethodBody(method);
        if (body == null) {
            System.out.println("No body for method: " + method.getSignature());
            return;
        }

        synchronized (analyzedClasses) {
            if (implementsInterface(sootClass, X509_TRUST_MANAGER)) {
                analyzeTrustManager(sootClass, vulnerabilities);
            } else if (implementsInterface(sootClass, HOSTNAME_VERIFIER)) {
                analyzeHostnameVerifier(sootClass, vulnerabilities);
            }
        }

        analyzeSSLContextUsage(method, body, vulnerabilities);
        analyzeSSLSocketFactoryUsage(method, body, vulnerabilities);
    }

    private static boolean implementsInterface(SootClass sootClass, String interfaceName) {
        SootClass currentClass = sootClass;
        while (currentClass != null) {
            for (SootClass iface : currentClass.getInterfaces()) {
                if (iface.getName().equals(interfaceName)) {
                    return true;
                }
                if (implementsInterface(iface, interfaceName)) {
                    return true;
                }
            }
            if (currentClass.hasSuperclass()) {
                currentClass = currentClass.getSuperclass();
            } else {
                break;
            }
        }
        return false;
    }

    private static void analyzeTrustManager(SootClass sootClass, List<String> vulnerabilities) {
        if (analyzedClasses.contains(sootClass)) {
            return;
        }
        analyzedClasses.add(sootClass);
        String[] methodsToCheck = {
                "void checkClientTrusted(java.security.cert.X509Certificate[],java.lang.String)",
                "void checkServerTrusted(java.security.cert.X509Certificate[],java.lang.String)",
                "java.security.cert.X509Certificate[] getAcceptedIssuers()"
        };

        for (String methodSig : methodsToCheck) {
            SootMethod method = sootClass.getMethodUnsafe(methodSig);
            if (method != null && method.isConcrete()) {
                Body body = SootAnalysisWorker.getMethodBody(method);
                if (body == null) continue;
                UnitGraph graph = new BriefUnitGraph(body);
                HardCodeDetector.HardcodeFlowAnalysis analysis = new HardCodeDetector.HardcodeFlowAnalysis(graph);
                String location = getSourceLine(method);

                if (methodSig.contains("checkClientTrusted") || methodSig.contains("checkServerTrusted")) {
                    if (body.getUnits().size() <= 1) {
                        reportVulnerability(method, "Empty TrustManager check method detected", location, vulnerabilities);
                    } else if (!hasThrowStmt(body)) {
                        reportVulnerability(method, "TrustManager does not throw exception on invalid certificates", location, vulnerabilities);
                    }
                } else if (methodSig.contains("getAcceptedIssuers")) {
                    Value returnValue = getReturnValue(body);
                    if (returnValue instanceof NullConstant) {
                        reportVulnerability(method, "TrustManager returns null accepted issuers", location, vulnerabilities);
                    } else if (returnValue instanceof ArrayRef && isEmptyArray(body, returnValue, analysis)) {
                        reportVulnerability(method, "TrustManager returns empty accepted issuers", location, vulnerabilities);
                    }
                }
            }
        }
    }

    private static void analyzeHostnameVerifier(SootClass sootClass, List<String> vulnerabilities) {
        if (analyzedClasses.contains(sootClass)) {
            return;
        }
        analyzedClasses.add(sootClass);
        SootMethod verifyMethod = sootClass.getMethodUnsafe("boolean verify(java.lang.String,javax.net.ssl.SSLSession)");
        if (verifyMethod != null && verifyMethod.isConcrete()) {
            Body body = SootAnalysisWorker.getMethodBody(verifyMethod);
            if (body == null) return;
            UnitGraph graph = new BriefUnitGraph(body);
            HardCodeDetector.HardcodeFlowAnalysis analysis = new HardCodeDetector.HardcodeFlowAnalysis(graph);
            String location = getSourceLine(verifyMethod);

            if (alwaysReturnsTrue(body)) {
                reportVulnerability(verifyMethod, "HostnameVerifier always returns true", location, vulnerabilities);
            }
        }
    }

    private static void analyzeSSLContextUsage(SootMethod method, Body body, List<String> vulnerabilities) {

        if (containsTargetAPI(method)) {
            HardCodeDetector.HardcodeFlowAnalysis analysis = new HardCodeDetector.HardcodeFlowAnalysis(new BriefUnitGraph(body));
            for (Unit unit : body.getUnits()) {
                if (unit instanceof InvokeStmt) {
                    InvokeExpr invokeExpr = ((InvokeStmt) unit).getInvokeExpr();
                    if (invokeExpr != null && invokeExpr.getMethod().getDeclaringClass().getName().equals(SSL_CONTEXT)) {
                        String location = getSourceLine(unit);
                        SootMethod invokedMethod = invokeExpr.getMethod();

                        if (invokedMethod.getName().equals("getInstance")) {
                            checkWeakProtocol(invokeExpr, method, analysis, location, vulnerabilities);
                        } else if (invokedMethod.getName().equals("init")) {
                            checkNullTrustManager(invokeExpr, method, location, vulnerabilities);
                        }
                    }
                } else if (unit instanceof AssignStmt) {
                    AssignStmt assignStmt = (AssignStmt) unit;
                    Value rightOp = assignStmt.getRightOp();
                    if (rightOp instanceof InvokeExpr) {
                        InvokeExpr invokeExpr = (InvokeExpr) rightOp;
                        SootMethod invokedMethod = invokeExpr.getMethod();
                        String location = getSourceLine(unit);
                        if (invokedMethod.getDeclaringClass().getName().equals(SSL_CONTEXT) &&
                                invokedMethod.getName().equals("getInstance")) {
                            checkWeakProtocol(invokeExpr, method, analysis, location, vulnerabilities);
                        }
                    }
                }
            }
        }

    }

    private static void analyzeSSLSocketFactoryUsage(SootMethod method, Body body, List<String> vulnerabilities) {

        if (containsTargetAPI(method)) {
            for (Unit unit : body.getUnits()) {
                if (unit instanceof JAssignStmt) {
                    JAssignStmt assignStmt = (JAssignStmt) unit;
                    if (assignStmt.getRightOp() instanceof InvokeExpr) {
                        InvokeExpr invokeExpr = (InvokeExpr) assignStmt.getRightOp();
                        SootMethod invokedMethod = invokeExpr.getMethod();
                        if (invokedMethod.getDeclaringClass().getName().equals(SSL_SOCKET_FACTORY) &&
                                invokedMethod.getName().equals("getDefault")) {
                            String location = getSourceLine(unit);
                            reportVulnerability(method, "Using default SSLSocketFactory without custom configuration", location, vulnerabilities);
                        }
                    }
                }
            }
        }

    }

    private static boolean containsTargetAPI(SootMethod method) {
        Body body = SootAnalysisWorker.getMethodBody(method);
        if (body == null) return false;

        for (Unit unit : body.getUnits()) {
            InvokeExpr invokeExpr = null;
            if (unit instanceof InvokeStmt) {
                invokeExpr = ((InvokeStmt) unit).getInvokeExpr();
            } else if (unit instanceof AssignStmt) {
                Value rightOp = ((AssignStmt) unit).getRightOp();
                if (rightOp instanceof InvokeExpr) {
                    invokeExpr = (InvokeExpr) rightOp;
                }
            }
            if (invokeExpr != null && TARGET_CLASSES.contains(invokeExpr.getMethod().getDeclaringClass().getName())) {
                return true;
            }
        }
        return false;
    }

    private static void checkWeakProtocol(InvokeExpr invokeExpr, SootMethod method, HardCodeDetector.HardcodeFlowAnalysis analysis,
                                          String location, List<String> vulnerabilities) {
        Value protocolArg = invokeExpr.getArg(0);
        Map<Object, HardCodeDetector.Condition> possibleValues = analysis.getPossibleValuesWithConditions(protocolArg);
        for (Map.Entry<Object, HardCodeDetector.Condition> entry : possibleValues.entrySet()) {
            if (!entry.getValue().isReachable()) continue;
            String protocol = entry.getKey() != null ? entry.getKey().toString() : "unknown";
            protocol = protocol.trim().replaceAll("[\"']", "");
            String np = protocol.toUpperCase();
            if (WEAK_PROTOCOLS.contains(np)) {
                reportVulnerability(method, "Weak SSL/TLS protocol used: " + protocol, location, vulnerabilities);
            }
        }
    }

    public static void checkNullTrustManager(InvokeExpr invokeExpr, SootMethod method, String location, List<String> vulnerabilities) {
        SootClass sootClass = invokeExpr.getMethod().getDeclaringClass();
        if (analyzedClasses.contains(sootClass)) {
            return;
        }
        analyzedClasses.add(sootClass);
        Value trustManagerArg = invokeExpr.getArg(1);

        if (trustManagerArg instanceof NullConstant) {
            reportVulnerability(method, "SSLContext initialized with null TrustManager", location, vulnerabilities);
            return;
        }

        if (!(trustManagerArg.getType() instanceof ArrayType)) {
            System.out.println("Warning: TrustManager arg is not an array: " + trustManagerArg.getType());
            return;
        }

        ArrayType arrayType = (ArrayType) trustManagerArg.getType();
        Type baseType = arrayType.getElementType();
        Set<SootClass> dynamicallyAnalyzedClasses = new HashSet<>();

        findArrayElementTypes(method, trustManagerArg, vulnerabilities, location, dynamicallyAnalyzedClasses);

        if (baseType instanceof RefType && !dynamicallyAnalyzedClasses.contains(((RefType) baseType).getSootClass())) {
            SootClass tmClass = ((RefType) baseType).getSootClass();
            if (implementsInterface(tmClass, X509_TRUST_MANAGER) && !analyzedClasses.contains(tmClass)) {
                analyzeTrustManager(tmClass, vulnerabilities);
                analyzedClasses.add(tmClass);
            }
        }
    }

    private static void findArrayElementTypes(SootMethod method, Value array, List<String> vulnerabilities, String location,
                                              Set<SootClass> dynamicallyAnalyzedClasses) {
        Body body = SootAnalysisWorker.getMethodBody(method);
        if (body == null) {
            System.out.println("Warning: No body for method: " + method.getSignature());
            return;
        }

        Set<Value> relatedArrays = new HashSet<>();
        relatedArrays.add(array);

        for (Unit unit : body.getUnits()) {
            if (unit instanceof JAssignStmt) {
                JAssignStmt assignStmt = (JAssignStmt) unit;
                Value leftOp = assignStmt.getLeftOp();
                Value rightOp = assignStmt.getRightOp();
                if (leftOp.equals(array)) {
                    Value alias = rightOp instanceof JCastExpr ? ((JCastExpr) rightOp).getOp() : rightOp;
                    relatedArrays.add(alias);
                }
            }
        }

        boolean foundAssignment = false;
        for (Unit unit : body.getUnits()) {
            if (unit instanceof JAssignStmt) {
                JAssignStmt assignStmt = (JAssignStmt) unit;
                Value leftOp = assignStmt.getLeftOp();
                if (leftOp instanceof ArrayRef) {
                    ArrayRef arrayRef = (ArrayRef) leftOp;
                    Value base = arrayRef.getBase();
                    if (relatedArrays.contains(base)) {
                        foundAssignment = true;
                        Value element = assignStmt.getRightOp();
                        if (element.getType() instanceof RefType && !analyzedTrustManagerInstances.contains(element)) {
                            SootClass elementClass = ((RefType) element.getType()).getSootClass();
                            if (implementsInterface(elementClass, X509_TRUST_MANAGER) && !analyzedClasses.contains(elementClass)) {
                                analyzeTrustManager(elementClass, vulnerabilities);
                                analyzedClasses.add(elementClass);
                                dynamicallyAnalyzedClasses.add(elementClass);
                            }
                            analyzedTrustManagerInstances.add(element);
                        } else if (element instanceof NullConstant) {
                            reportVulnerability(method, "TrustManager array contains null element", location, vulnerabilities);
                        }
                    }
                }
            }
        }

        if (!foundAssignment && array instanceof StaticFieldRef) {
            SootField field = ((StaticFieldRef) array).getField();
            SootClass declaringClass = field.getDeclaringClass();
            try {
                SootMethod clinit = declaringClass.getMethodByNameUnsafe("<clinit>");
                if (clinit == null || SootAnalysisWorker.getMethodBody(clinit) == null) {
                    System.out.println("Warning: No <clinit> or body for " + declaringClass.getName());
                    return;
                }
                Body clinitBody = SootAnalysisWorker.getMethodBody(clinit);
                Set<Value> clinitArrays = new HashSet<>();
                for (Unit unit : clinitBody.getUnits()) {
                    if (unit instanceof JAssignStmt) {
                        JAssignStmt assignStmt = (JAssignStmt) unit;
                        Value leftOp = assignStmt.getLeftOp();
                        Value rightOp = assignStmt.getRightOp();
                        if (leftOp instanceof StaticFieldRef && ((StaticFieldRef) leftOp).getField().equals(field)) {
                            clinitArrays.add(rightOp);
                        }
                    }
                }
                for (Unit unit : clinitBody.getUnits()) {
                    if (unit instanceof JAssignStmt) {
                        JAssignStmt assignStmt = (JAssignStmt) unit;
                        if (assignStmt.getLeftOp() instanceof ArrayRef) {
                            ArrayRef arrayRef = (ArrayRef) assignStmt.getLeftOp();
                            if (clinitArrays.contains(arrayRef.getBase())) {
                                Value element = assignStmt.getRightOp();
                                if (element.getType() instanceof RefType && !analyzedTrustManagerInstances.contains(element)) {
                                    SootClass elementClass = ((RefType) element.getType()).getSootClass();
                                    if (implementsInterface(elementClass, X509_TRUST_MANAGER) && !analyzedClasses.contains(elementClass)) {
                                        analyzeTrustManager(elementClass, vulnerabilities);
                                        analyzedClasses.add(elementClass);
                                        dynamicallyAnalyzedClasses.add(elementClass);
                                        foundAssignment = true;
                                    }
                                    analyzedTrustManagerInstances.add(element);
                                }
                            }
                        }
                    }
                }
            } catch (Exception e) {
                System.out.println("Warning: Could not analyze <clinit> for field " + field.getSignature());
            }
        }

        if (!foundAssignment) {
            System.out.println("No assignments found for TrustManager array: " + array);
        }
    }

    private static boolean hasThrowStmt(Body body) {
        for (Unit unit : body.getUnits()) {
            if (unit instanceof ThrowStmt) {
                return true;
            }
        }
        return false;
    }

    private static Value getReturnValue(Body body) {
        for (Unit unit : body.getUnits()) {
            if (unit instanceof ReturnStmt) {
                return ((ReturnStmt) unit).getOp();
            }
        }
        return null;
    }

    private static boolean isEmptyArray(Body body, Value arrayRef, HardCodeDetector.HardcodeFlowAnalysis analysis) {
        Map<Object, HardCodeDetector.Condition> values = analysis.getPossibleValuesWithConditions(arrayRef);
        for (Map.Entry<Object, HardCodeDetector.Condition> entry : values.entrySet()) {
            if (!entry.getValue().isReachable()) continue;
            if (entry.getKey() instanceof String && entry.getKey().toString().contains("[0]")) {
                return true;
            }
        }
        return false;
    }

    private static boolean alwaysReturnsTrue(Body body) {
        for (Unit unit : body.getUnits()) {
            if (unit instanceof ReturnStmt) {
                Value returnValue = ((ReturnStmt) unit).getOp();
                if (returnValue instanceof IntConstant && ((IntConstant) returnValue).value != 1) {
                    return false;
                }
            }
        }
        return true;
    }

    private static String getSourceLine(Unit unit) {
        Tag lineTag = unit.getTag("LineNumberTag");
        if (lineTag != null) {
            return "line " + ((LineNumberTag) lineTag).getLineNumber();
        }
        int javaLine = unit.getJavaSourceStartLineNumber();
        return javaLine != -1 ? "line " + javaLine : "unknown line";
    }

    private static String getSourceLine(SootMethod method) {
        return "method " + method.getSignature();
    }

    private static void reportVulnerability(SootMethod method, String message, String location, List<String> vulnerabilities) {
        String report = String.format("[Vulnerability] %s in %s at %s", message, method.getSignature(), location);
        vulnerabilities.add(report);
    }
}
