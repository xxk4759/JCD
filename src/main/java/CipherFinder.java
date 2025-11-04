import soot.*;
import soot.jimple.*;
import java.io.*;
import java.util.*;
import java.util.concurrent.*;

import soot.jimple.toolkits.callgraph.CallGraph;
import soot.jimple.toolkits.callgraph.Edge;
import soot.toolkits.graph.*;

public class CipherFinder {
    private static final Set<String> WEAK_CIPHERS = new HashSet<>(Arrays.asList("DES", "DESEDE", "RC2", "RC4", "IDEA", "BLOWFISH"));
    private static final Set<String> WEAK_HASHES = new HashSet<>(Arrays.asList("MD5", "MD2", "MD4", "SHA-1","SHA1"));
    private static final Set<String> WEAK_SIGNATURES = new HashSet<>(Arrays.asList("MD5WITHRSA", "SHA1WITHRSA", "MD2WITHRSA"));
    private static final Set<String> BLOCK_CIPHERS = new HashSet<>(Arrays.asList("AES", "DES", "DESEDE", "BLOWFISH", "RC2", "CAMELLIA"));//默认ECB
    private static final Set<String> NON_AEAD_MODES = new HashSet<>(Arrays.asList("CBC", "CFB", "OFB", "PCBC"));
    private static final Set<String> BLOCK_MODES = new HashSet<>(Arrays.asList("CBC", "ECB","RSA")); // 需要填充的块模式
    private static final Set<String> WEAK_PADDINGS = new HashSet<>(Arrays.asList("NOPADDING", "ZEROPADDING","PKCS1PADDING")); // 弱填充模式
    private static final Set<String> TARGET_CLASSES = new HashSet<>(Arrays.asList(
            "javax.crypto.Cipher", "java.security.Signature", "java.util.Random",
            "java.lang.Math", "java.security.MessageDigest", "javax.crypto.KeyGenerator",
            "java.security.KeyPairGenerator"
    ));

    public static List<String> detect(BlockingQueue<SootMethod> methodQueue) {
        System.out.println("CipherFinder Detecting...");
        List<String> vulnerabilities = Collections.synchronizedList(new ArrayList<>());
        vulnerabilities.add("=== CipherFinder Vulnerability Report ===");

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

        Body body = SootAnalysisWorker.getMethodBody(method);
        if (body == null) return;

        if (containsTargetAPI(method)) {
            checkForCryptoIssues(body, method, vulnerabilities);
        }
    }

    private static boolean containsTargetAPI(SootMethod method) {
        try {
            Body body = method.retrieveActiveBody();
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
        } catch (Exception e) {
            // 忽略无法获取方法体的异常
        }
        return false;
    }

    private static void checkForCryptoIssues(Body body, SootMethod method, List<String> vulnerabilities) {
        HardCodeDetector.HardcodeFlowAnalysis analysis = new HardCodeDetector.HardcodeFlowAnalysis(new BriefUnitGraph(body));
        Map<String, List<Unit>> keyUsageUnits = new HashMap<>();
        Map<Unit, String> cipherAlgorithms = new HashMap<>();
        Map<String, List<Unit>> nonceUsageUnits = new HashMap<>();
        Map<Value, String> keyGenAlgorithms = new HashMap<>(); //keyganerator.getinstance

        for (Unit unit : body.getUnits()) {
            if (unit instanceof AssignStmt) {
                AssignStmt assignStmt = (AssignStmt) unit;
                Value rightOp = assignStmt.getRightOp();
                if (rightOp instanceof InvokeExpr) {
                    InvokeExpr invokeExpr = (InvokeExpr) rightOp;
                    SootMethod invokedMethod = invokeExpr.getMethod();

                    String location = unit.getJavaSourceStartLineNumber() != -1
                            ? "line " + unit.getJavaSourceStartLineNumber()
                            : "unknown location";

                    // Cipher.getInstance
                    if (invokedMethod.getDeclaringClass().getName().equals("javax.crypto.Cipher") &&
                            invokedMethod.getName().equals("getInstance")) {
                        Value modeArg = invokeExpr.getArg(0);
                        Map<Object, HardCodeDetector.Condition> possibleModes = analysis.getPossibleValuesWithConditions(modeArg);
                        for (Map.Entry<Object, HardCodeDetector.Condition> entry : possibleModes.entrySet()) {
                            if (!entry.getValue().isReachable()) continue;
                            String mode = entry.getKey() != null ? entry.getKey().toString() : "unknown";
                            String normalizedMode = mode.toUpperCase();

                            if (BLOCK_CIPHERS.contains(normalizedMode) || normalizedMode.contains("ECB")) {
                                String ecbMessage = BLOCK_CIPHERS.contains(normalizedMode) ?
                                        "Detected default ECB mode for " + normalizedMode + ", recommend CBC with secure padding" :
                                        "Detected explicit ECB mode, not recommended";
                                HardCodeDetector.reportVulnerability(method, unit, ecbMessage, location, vulnerabilities);
                            }
                            String cipher = mode.split("/")[0].trim().replaceAll("[\"']", "").toUpperCase();
                            cipherAlgorithms.put(unit, cipher);
                            if (WEAK_CIPHERS.contains(cipher)) {
                                HardCodeDetector.reportVulnerability(method, unit, "Detected weak cipher: " + cipher, location, vulnerabilities);
                            }

                            String[] modeParts = mode.toUpperCase().split("/");
                            if (modeParts.length > 1 && NON_AEAD_MODES.contains(modeParts[1])) {
                                boolean hasIntegrity = checkIntegrityProtection(body);
                                if (!hasIntegrity) {
                                    cipher = modeParts[0].trim().replaceAll("[\"']", "");
                                    HardCodeDetector.reportVulnerability(method, unit,
                                            "Detected encryption without integrity protection for " + cipher + ", recommend GCM or HMAC",
                                            location, vulnerabilities);
                                }
                            }
                            //  弱填充模式
                            if (modeParts.length > 2 && modeParts[2] != null) {
                                if (WEAK_PADDINGS.contains(modeParts[2]) && BLOCK_MODES.contains(modeParts[1])) {
                                    String message = "Detected weak padding mode " + modeParts[2] + " for " + modeParts[1] + ", recommend PKCS5Padding";
                                    HardCodeDetector.reportVulnerability(method, unit, message, location, vulnerabilities);
                                }
                            }

                        }
                    }

                    //  弱签名算法
                    if (invokedMethod.getDeclaringClass().getName().equals("java.security.Signature") &&
                            invokedMethod.getName().equals("getInstance")) {
                        Value sigArg = invokeExpr.getArg(0);
                        Map<Object, HardCodeDetector.Condition> possibleSigs = analysis.getPossibleValuesWithConditions(sigArg);
                        for (Map.Entry<Object, HardCodeDetector.Condition> entry : possibleSigs.entrySet()) {
                            if (!entry.getValue().isReachable()) continue;
                            String sig = entry.getKey() != null ? entry.getKey().toString() : "unknown";
                            String usig = sig.toUpperCase();
                            if (WEAK_SIGNATURES.contains(usig)) {
                                HardCodeDetector.reportVulnerability(method, unit,
                                        "Detected weak signature algorithm: " + sig + ", recommend SHA256withRSA",
                                        location, vulnerabilities);
                            }
                        }
                    }

                    // 伪随机数生成器
                    if (invokedMethod.getDeclaringClass().getName().equals("java.util.Random") ||
                            (invokedMethod.getDeclaringClass().getName().equals("java.lang.Math") &&
                                    invokedMethod.getName().equals("random"))&&
                                    !invokeExpr.getMethod().getDeclaringClass().getName().equals("java.security.SecureRandom")) {
                        HardCodeDetector.reportVulnerability(method, unit,
                                "Detected insecure random number generator: " + invokedMethod.getName(), location, vulnerabilities);
                    }

                    // MessageDigest.getInstance
                    if (invokedMethod.getDeclaringClass().getName().equals("java.security.MessageDigest") &&
                            invokedMethod.getName().equals("getInstance")) {
                        Value hashArg = invokeExpr.getArg(0);
                        Map<Object, HardCodeDetector.Condition> possibleHashes = analysis.getPossibleValuesWithConditions(hashArg);
                        for (Map.Entry<Object, HardCodeDetector.Condition> entry : possibleHashes.entrySet()) {
                            if (!entry.getValue().isReachable()) continue;
                            String mode = entry.getKey() != null ? entry.getKey().toString() : "unknown";
                            String hash = mode.split("/")[0].trim().replaceAll("[\"']", "");
                            if (WEAK_HASHES.contains(hash)) {
                                HardCodeDetector.reportVulnerability(method, unit, "Detected weak hash function: " + hash, location, vulnerabilities);
                            }
                        }
                    }

                    if ((invokedMethod.getDeclaringClass().getName().equals("javax.crypto.KeyGenerator") &&
                            invokedMethod.getName().equals("getInstance")) || (invokedMethod.getDeclaringClass().getName().equals("java.security.KeyPairGenerator") &&
                            invokedMethod.getName().equals("getInstance"))) {
                        Value keyGenVar = assignStmt.getLeftOp();
                        Value algArg = invokeExpr.getArg(0);
                        Map<Object, HardCodeDetector.Condition> algValues = analysis.getPossibleValuesWithConditions(algArg);
                        for (Map.Entry<Object, HardCodeDetector.Condition> entry : algValues.entrySet()) {
                            if (entry.getValue().isReachable() && entry.getKey() != null) {
                                keyGenAlgorithms.put(keyGenVar, entry.getKey().toString().toUpperCase());
                            }
                        }
                    }
                }
            }
            else if (unit instanceof InvokeStmt) {
                String location = unit.getJavaSourceStartLineNumber() != -1
                        ? "line " + unit.getJavaSourceStartLineNumber()
                        : "unknown location";
                InvokeExpr invokeExpr = ((InvokeStmt) unit).getInvokeExpr();
                SootMethod invokedMethod = invokeExpr.getMethod();
                String className = invokedMethod.getDeclaringClass().getName();
                String methodName = invokedMethod.getName();

                //  弱签名算法
                if (className.equals("java.security.Signature") &&
                        methodName.equals("getInstance")) {
                    Value sigArg = invokeExpr.getArg(0);
                    Map<Object, HardCodeDetector.Condition> possibleSigs = analysis.getPossibleValuesWithConditions(sigArg);
                    for (Map.Entry<Object, HardCodeDetector.Condition> entry : possibleSigs.entrySet()) {
                        if (!entry.getValue().isReachable()) continue;
                        String sig = entry.getKey() != null ? entry.getKey().toString() : "unknown";
                        String usig = sig.toUpperCase();
                        if (WEAK_SIGNATURES.contains(usig)) {
                            HardCodeDetector.reportVulnerability(method, unit,
                                    "Detected weak signature algorithm: " + sig + ", recommend SHA256withRSA",
                                    location, vulnerabilities);
                        }
                    }
                }

                // MessageDigest.getInstance
                if (className.equals("java.security.MessageDigest") &&
                        methodName.equals("getInstance")) {
                    Value hashArg = invokeExpr.getArg(0);
                    Map<Object, HardCodeDetector.Condition> possibleHashes = analysis.getPossibleValuesWithConditions(hashArg);
                    for (Map.Entry<Object, HardCodeDetector.Condition> entry : possibleHashes.entrySet()) {
                        if (!entry.getValue().isReachable()) continue;
                        String mode = entry.getKey() != null ? entry.getKey().toString() : "unknown";
                        String hash = mode.split("/")[0].trim().replaceAll("[\"']", "");
                        if (WEAK_HASHES.contains(hash)) {
                            HardCodeDetector.reportVulnerability(method, unit, "Detected weak hash function: " + hash, location, vulnerabilities);
                        }
                    }
                }

                if (className.equals("java.util.Random") && methodName.equals("<init>")) {
                    if (!invokeExpr.getMethod().getDeclaringClass().hasSuperclass() ||
                            !invokeExpr.getMethod().getDeclaringClass().getSuperclass().getName().equals("java.security.SecureRandom")) {
                        HardCodeDetector.reportVulnerability(method, unit,
                                "Detected insecure random number generator: " + invokedMethod.getName(),
                                location, vulnerabilities);
                    }

                }

                if ((className.equals("javax.crypto.KeyGenerator") && methodName.equals("init")) ||
                        (className.equals("java.security.KeyPairGenerator") && methodName.equals("initialize"))) {
                    Value keyGenVar = invokeExpr.getUseBoxes().stream()
                            .filter(box -> box.getValue() instanceof Local)
                            .map(ValueBox::getValue)
                            .findFirst().orElse(null);
                    if (keyGenVar != null && keyGenAlgorithms.containsKey(keyGenVar)) {
                        String algorithm = keyGenAlgorithms.get(keyGenVar);
                        Value arg = invokeExpr.getArg(0);
                        Map<Object, HardCodeDetector.Condition> values = analysis.getPossibleValuesWithConditions(arg);
                        for (Map.Entry<Object, HardCodeDetector.Condition> entry : values.entrySet()) {
                            if (entry.getKey() instanceof Integer && entry.getValue().isReachable()) {
                                int keySize = (Integer) entry.getKey();
                                checkKeySize(method, unit, algorithm, keySize, location, vulnerabilities);
                            }
                        }
                    }
                }

                //密钥长度检测
                if (className.equals("javax.crypto.Cipher") && methodName.equals("init")) {
                    if (invokeExpr.getArgCount() > 1) {
                        Value keyArg = invokeExpr.getArg(1); // Key

                        //密钥重用检测
                        if (invokeExpr.getArgCount() > 2) {
                            Value paramArg = invokeExpr.getArg(2);
                            String nonceSource = paramArg.toString();
                            String mode = findCipherMode(body, unit, analysis);
                            if (nonceSource != null) {
                                String key = nonceSource + "@" + mode;
                                nonceUsageUnits.computeIfAbsent(key, k -> new ArrayList<>()).add(unit);
                            }
                        }
                        //  密钥重用
                        String keySource = keyArg.toString();
                        String mode = findCipherMode(body, unit, analysis);
                        if (keySource != null) {
                            String key = keySource + "@" + mode;
                            keyUsageUnits.computeIfAbsent(key, k -> new ArrayList<>()).add(unit);
                        }
                    }
                }
            }
        }
        // 报告密钥重用
        for (Map.Entry<String, List<Unit>> entry : keyUsageUnits.entrySet()) {
            List<Unit> units = entry.getValue();
            if (units.size() > 1) {
                Unit lastUnit = units.get(units.size() - 1);
                String location = lastUnit.getJavaSourceStartLineNumber() != -1
                        ? "line " + lastUnit.getJavaSourceStartLineNumber()
                        : method.getSignature();
                String[] key = entry.getKey().split("@");
                String mode = key[1];
                String message = "Detected key reuse in " + mode + " mode (" + units.size() + " times), recommend key rotation";
                HardCodeDetector.reportVulnerability(method, lastUnit, message, location, vulnerabilities);
            }
        }

        // 报告 nonce/IV 重用
        for (Map.Entry<String, List<Unit>> entry : nonceUsageUnits.entrySet()) {
            List<Unit> units = entry.getValue();
            if (units.size() > 1) {
                Unit lastUnit = units.get(units.size() - 1);
                String location = lastUnit.getJavaSourceStartLineNumber() != -1
                        ? "line " + lastUnit.getJavaSourceStartLineNumber()
                        : method.getSignature();
                String mode = entry.getKey().split("@")[1];
                String message = "Detected nonce/IV reuse in " + mode + " mode (" + units.size() + " times), recommend unique nonce/IV";
                HardCodeDetector.reportVulnerability(method, lastUnit, message, location, vulnerabilities);
            }
        }

    }

    private static boolean checkIntegrityProtection(Body body) {
        for (Unit unit : body.getUnits()) {
            if (unit instanceof AssignStmt) {
                Value rightOp = ((AssignStmt) unit).getRightOp();
                if (rightOp instanceof InvokeExpr) {
                    SootMethod invoked = ((InvokeExpr) rightOp).getMethod();
                    if (invoked.getDeclaringClass().getName().equals("javax.crypto.Mac") &&
                            invoked.getName().equals("getInstance")) {
                        Value macArg = ((InvokeExpr) rightOp).getArg(0);
                        Map<Object, HardCodeDetector.Condition> possibleMacs = new HardCodeDetector.HardcodeFlowAnalysis(new BriefUnitGraph(body))
                                .getPossibleValuesWithConditions(macArg);
                        for (Map.Entry<Object, HardCodeDetector.Condition> entry : possibleMacs.entrySet()) {
                            if (!entry.getValue().isReachable()) continue;
                            String mac = entry.getKey() != null ? entry.getKey().toString() : "unknown";
                            if (mac.contains("Hmac")) {
                                return true;
                            }
                        }
                    }
                }
            }
        }
        return false;
    }

    private static void checkKeySize(SootMethod method, Unit unit, String algorithm, int keySize, String location, List<String> vulnerabilities) {
        if (algorithm.equals("AES") && keySize < 128) {
            HardCodeDetector.reportVulnerability(method, unit,
                    "AES key size " + keySize + " bits, recommend 128+", location, vulnerabilities);
        } else if (algorithm.equals("DES") && keySize != 64) {
            HardCodeDetector.reportVulnerability(method, unit,
                    "DES key size " + keySize + " bits, expected 64 bits", location, vulnerabilities);
        } else if (algorithm.equals("BLOWFISH") && keySize < 128) {
            HardCodeDetector.reportVulnerability(method, unit,
                    "Blowfish key size " + keySize + " bits, recommend 128+", location, vulnerabilities);
        } else if (algorithm.equals("RSA") && keySize < 2048) {
            HardCodeDetector.reportVulnerability(method, unit,
                    "RSA key size " + keySize + " bits, recommend 2048+", location, vulnerabilities);
        }
    }

    private static Unit findCipherGetInstanceUnit(Body body, Unit initUnit, HardCodeDetector.HardcodeFlowAnalysis analysis) {
        if (!(initUnit instanceof InvokeStmt)) return null;
        InvokeStmt invokeStmt = (InvokeStmt) initUnit;
        InvokeExpr invokeExpr = invokeStmt.getInvokeExpr();
        if (!(invokeExpr instanceof InstanceInvokeExpr)) return null;

        // 获取 Cipher.init 的 base（Cipher 对象）
        InstanceInvokeExpr instanceInvoke = (InstanceInvokeExpr) invokeExpr;
        Value cipherVar = instanceInvoke.getBase();

        // 回溯 cipherVar 的定义
        for (Unit unit : body.getUnits()) {
            if (unit instanceof AssignStmt) {
                AssignStmt assignStmt = (AssignStmt) unit;
                if (assignStmt.getLeftOp().equals(cipherVar) && assignStmt.getRightOp() instanceof InvokeExpr) {
                    InvokeExpr rightInvoke = (InvokeExpr) assignStmt.getRightOp();
                    if (rightInvoke.getMethod().getName().equals("getInstance") &&
                            rightInvoke.getMethod().getDeclaringClass().getName().equals("javax.crypto.Cipher")) {
                        return unit; // 找到对应的 getInstance
                    }
                }
            }
            if (unit == initUnit) break; // 确保只检查 init 前的单位
        }
        return null;
    }

    private static String findCipherMode(Body body, Unit unit, HardCodeDetector.HardcodeFlowAnalysis analysis) {
        Unit cipherUnit = findCipherGetInstanceUnit(body, unit, analysis);
        if (cipherUnit != null && cipherUnit instanceof AssignStmt) {
            InvokeExpr invokeExpr = (InvokeExpr) ((AssignStmt) cipherUnit).getRightOp();
            Value modeArg = invokeExpr.getArg(0);
            Map<Object, HardCodeDetector.Condition> possibleModes = analysis.getPossibleValuesWithConditions(modeArg);
            for (Map.Entry<Object, HardCodeDetector.Condition> entry : possibleModes.entrySet()) {
                if (entry.getValue().isReachable() && entry.getKey() != null) {
                    String mode = entry.getKey().toString().toUpperCase().replaceAll("[\"']", "");
                    String[] modeParts = mode.split("/");
                    if (modeParts.length >= 2) {
                        return modeParts[1];
                    }
                }
            }
        }
        return "UNKNOWN";
    }
}