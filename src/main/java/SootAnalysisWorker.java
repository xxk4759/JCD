import soot.jimple.toolkits.callgraph.CallGraph;
import soot.*;
import soot.options.Options;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

public class SootAnalysisWorker {
    private static final Map<SootMethod, Body> methodBodyCache = new ConcurrentHashMap<>();
    private static CallGraph callGraph;

    public static void initialize(List<SootClass> classes) {
        // 配置 Soot 优化

        Options.v().set_allow_phantom_refs(true);
        Options.v().set_prepend_classpath(true);
        Scene.v().loadNecessaryClasses();

        // 构建调用图
        PackManager.v().getPack("cg").apply();
        callGraph = Scene.v().getCallGraph();

        // 单线程预加载方法体
        for (SootClass sootClass : classes) {
            try {
                System.out.println("Preloading class: " + sootClass.getName());
                for (SootMethod method : sootClass.getMethods()) {
                    if (method.isConcrete()) {
                        try {
                            Body body = method.retrieveActiveBody();
                            methodBodyCache.put(method, body);
                        } catch (Exception e) {
                            System.err.println("Failed to preload body for " + method.getSignature() + ": " + e.getMessage());
                        }
                    }
                }
            } catch (Exception e) {
                System.err.println("Failed to preload class: " + sootClass.getName() + ": " + e.getMessage());
            }
        }
        System.out.println("Preloaded " + methodBodyCache.size() + " method bodies");
    }

    public static Body getMethodBody(SootMethod method) {
        return methodBodyCache.get(method);
    }

    public static CallGraph getCallGraph() {
        return callGraph;
    }

    public static void clearCache() {
        methodBodyCache.clear();
        callGraph = null;
    }
}
