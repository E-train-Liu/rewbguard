package dk.brics.automaton;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.PrintStream;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.net.URISyntaxException;
import java.net.URL;
import java.nio.channels.ReadPendingException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyStore.LoadStoreParameter;
import java.sql.SQLException;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.concurrent.TimeoutException;
import java.util.function.Consumer;
import java.util.function.Supplier;
import java.util.logging.Logger;
import java.util.regex.Matcher;
import java.util.regex.Pattern;


public class AnalyzeRegExp {
    static final long DETECT_IDA_TIMEOUT_NS = 1L * 60L * 1000_000_000L; // 1 minute

    // public static class PCREData {
    //     public PCREData() {}
    //     public PCREData(String pattern, String flags) {
    //         this.pattern = pattern;
    //         this.flags = flags;
    //     }
    //     String pattern;
    //     String flags;
    // }

    /* public static void main(String[] args) throws IOException, URISyntaxException {
        // Path classDir = Paths.get(AnalyzeRegExp.class.getResource("").toURI());

        MainArgs mainArgs = parseMainArgs(args);

        ArrayList<String> patterns = loadPatternsByMainArgs(mainArgs);
        
        int compileError = 0, stringUnmatch = 0;
        int removeAnchor = 0, convertError = 0;
        PrintStream compConvPS = new PrintStream(classDir.resolve("compconv.toml").toFile(), StandardCharsets.UTF_8);
        RegExp[] regexs = new RegExp[patterns.size()];
        Automaton[] autos = new Automaton[patterns.size()];
        for (int i = 0, len = patterns.size(); i < len; ++i) {
            String pattern = patterns.get(i);
            // System.out.print(i + ": /" + pattern + "/\n");
            compConvPS.print("[" + i + "]\n");
            compConvPS.print("pattern = " + DataLoadSave.toToalString(pattern) + '\n');
            RegExp regex = null;
            Automaton auto = null;
            try {
                regex = new RegExp(pattern, RegExp.NONE);
                String regexStr = regex.toString();
                if (!pattern.equals(regexStr)) {
                    ++stringUnmatch;
                    compConvPS.print("unmatchString = " + DataLoadSave.toToalString(regexStr) + '\n');
                }
                auto = regex.toAutomaton(false);
            } catch (IllegalArgumentException iae) {
                ++compileError;
                compConvPS.print("compileError = '''\n");
                iae.printStackTrace(compConvPS);
                compConvPS.print("'''\n");
            } catch (UnsupportedOperationException uoe1) {
                regex = removeAnchor(regex);
                try {
                    auto = regex.toAutomaton(false);
                    ++removeAnchor;
                    compConvPS.print("removeAnchor = true\n");
                } catch (UnsupportedOperationException uoe2) {
                    ++convertError;
                    compConvPS.print("convertError = '''\n");
                    uoe2.printStackTrace(compConvPS);
                    compConvPS.print("'''\n");
                }
            }
            regexs[i] = regex;
            if (auto != null) {
                autos[i] = auto;
                // compConvPS.print("automaton = '''\n" + auto.toDot() + "'''\n");
            }
            compConvPS.print('\n');
        }
        compConvPS.close();
        System.out.print(
            "\n" +
            "compileError = " + compileError + "\n" +
            "stringUnmatch = " + stringUnmatch + "\n" +
            "removeAnchor = " + removeAnchor + "\n" +
            "convertError = " + convertError + "\n\n"
        );

        StringBuilder cbSB = new StringBuilder();
        cbSB.append("index\tpattern\tcapture\tbackref\tstarInCapture\tbackrefInCapture\tbackrefInBridge\n");
        int total = 0, capture = 0, backref = 0, starInCapture = 0, backrefInCapture = 0, backrefInBridge = 0;
        for (int i = 0; i < regexs.length; ++i) {
            RegExp regex = regexs[i];
            if (regex == null)
                continue;
            CaptureBackrefAnalysis cba = analyzeCaptureBackref(regex);
            total += 1;
            capture += cba.capture ? 1 : 0;
            backref += cba.backref ? 1 : 0;
            starInCapture += cba.starInCapture ? 1 : 0;
            backrefInCapture += cba.backrefInCapture ? 1 : 0;
            backrefInBridge += cba.backrefInBridge ? 1 : 0;
            cbSB
                .append(i).append('\t')
                .append(cba.capture ? '1' : '0').append('\t')
                .append(cba.backref ? '1' : '0').append('\t')
                .append(cba.starInCapture ? '1' : '0').append('\t')
                .append(cba.backrefInCapture ? '1' : '0').append('\t')
                .append(cba.backrefInBridge ? '1' : '0').append('\n');
        }
        Files.writeString(classDir.resolve("capture-backref.txt"), cbSB, StandardCharsets.UTF_8);
        cbSB = null;
        System.out.print(
            "\n" +
            "capture: " + capture + "\n" +
            "backref: " + backref + "\n" +
            "backref in capture: " + backrefInCapture + "\n" + 
            "star in capture: " + starInCapture + "\n" + 
            "backref in bridge: " + backrefInBridge + "\n\n"
        );
        

        int Vulnerable = 0, detectError = 0;
        PrintStream detectPS = new PrintStream(classDir.resolve("detect.toml").toFile(), StandardCharsets.UTF_8);
        for (int i = 0; i < autos.length; ++i) {
            String pattern = patterns.get(i);
            Automaton auto = autos[i];
            // System.out.print(i + ": /" + pattern + "/\n");
            if (auto == null)
                continue;
            detectPS.print(
                "[" + i + "]\n" +
                "pattern = " + DataLoadSave.toToalString(pattern) + '\n'
            );
            try {
                Automaton attackAuto = PDABackrefDetector.getAttackAutomaton(auto);
                if (!attackAuto.isEmpty()) {
                    detectPS.print("attackAuto = " + DataLoadSave.toToalString('\n' + attackAuto.toDot()) + '\n');
                    ++Vulnerable;
                }
            } catch (UnsupportedOperationException uoe) {
                detectPS.print("detectError = '''\n");
                uoe.printStackTrace(detectPS);
                detectPS.print("'''\n");
                ++detectError;
            }
            detectPS.print('\n');
        }
        detectPS.close();
        System.out.println(
            "\n" + 
            "Vulnerable = " + Vulnerable + "\n" +
            "detect error = " + detectError + "\n\n"
        );
    } */

    public static void main(String[] args) throws IOException, URISyntaxException, SQLException {
        // Path classDir = Paths.get(AnalyzeRegExp.class.getResource("").toURI());

        MainArg mainArg = parseMainArgs(args);
        Path inputPath = Path.of(mainArg.input);
        ArrayList<RPattern> rpatterns = null;
        switch (mainArg.inputKind) {
            case SNORT_RULES:
                rpatterns = DataLoadSave.loadSnortRulesPattern(inputPath);
                break;
            case SNORT_RULES_DIR:
                rpatterns = DataLoadSave.loadSnortRulesDirPattern(inputPath);
                break;
            case JSON:
                rpatterns = DataLoadSave.loadJsonPattern(inputPath);
                break;
            case SQL_COLUMN:
                rpatterns = DataLoadSave.loadSqlColumnPatternRaw(mainArg.input);
                break;
        }
        PrintStream reportPS = null, atkrePS = null;
        try {
            if (mainArg.outputReport != null)
                reportPS = new PrintStream(mainArg.outputReport, StandardCharsets.UTF_8);
            if (mainArg.outputAtkre != null) 
                atkrePS = new PrintStream(mainArg.outputAtkre, StandardCharsets.UTF_8);
            analyzeRegexAutomatons(rpatterns, reportPS, atkrePS);
        } finally {
            if (reportPS != null)
                reportPS.close();
            if (atkrePS != null)
                atkrePS.close();
        }
    }

    private static class MainArg {
        static enum InputKind {
            SNORT_RULES,
            SNORT_RULES_DIR,
            JSON,
            SQL_COLUMN
        }
        InputKind inputKind;
        String input;
        String outputReport;
        String outputAtkre;
    }

    private static MainArg parseMainArgs(String[] args) {
        MainArg mainArg = new MainArg();
        int status = 0;
        for (String arg : args) {
            if (status == 0) {
                if (arg.equals("--snort") || arg.equals("-s")) {
                    mainArg.inputKind = MainArg.InputKind.SNORT_RULES;
                    status = 1;
                } else if (arg.equals("--snortdir") || arg.equals("-S")) {
                    mainArg.inputKind = MainArg.InputKind.SNORT_RULES_DIR;
                    status = 1;
                } else if (arg.equals("--json") || arg.equals("-j")) {
                    mainArg.inputKind = MainArg.InputKind.JSON;
                    status = 1;
                } else if (arg.equals("--sql") || arg.equals("-q")) {
                    mainArg.inputKind = MainArg.InputKind.SQL_COLUMN;
                    status = 1;
                } else if (arg.equals("--report") || arg.equals("-r"))
                    status = 2;
                else if (arg.equals("--atkre") || arg.equals("-a"))
                    status = 3;
                else {
                    System.err.println(AnalyzeRegExp.class.getName() + ": unknown argument " + arg);
                    System.exit(1);
                }
                if (status == 1 && mainArg.input != null)
                    System.err.println(AnalyzeRegExp.class.getName() + ": invalid argument, any of -sSjq should only appear once");
            } else if (status == 1) {
                mainArg.input = arg;
                status = 0;
            } else if (status == 2) {
                mainArg.outputReport = arg;
                status = 0;
            } else if (status == 3) {
                mainArg.outputAtkre = arg;
                status = 0;
            }
        }
        if (mainArg.input == null) {
            System.err.println(AnalyzeRegExp.class.getName() + ": no input provided");
            System.exit(1);
        }
        return mainArg;
    }

    static class RegexAutomatonAnalyzeResult {
        RPattern rpattern;
        Throwable limitError;
        IllegalArgumentException compileError;
        boolean capture;
        boolean backref;
        boolean starInCapture;
        boolean backrefInCapture;
        boolean backrefInBridge;
        boolean removeAnchor;
        UnsupportedOperationException convertError;
        UnsupportedOperationException detectError0;
        AttackAutomaton attackAuto0;
        long detectTimeNs0;
        UnsupportedOperationException detectError1;
        AttackAutomaton attackAuto1;
        long detectTimeNs1;
        UnsupportedOperationException detectError2;
        AttackAutomaton attackAuto2;
        long detectTimeNs2;
        UnsupportedOperationException detectError3;
        AttackAutomaton attackAuto3;
        long detectTimeNs3;
        // Automaton attackAuto;
    }

    static void analyzeRegexAutomatons(
        List<RPattern> rpatterns,
        PrintStream reportPS,
        PrintStream atkrePS
    ) {
        int totalOriginPatterns = rpatterns.size();
        rpatterns = DataLoadSave.mergeRepeatRPattern(rpatterns);
        int totalUniquePatterns = rpatterns.size();
        // System.out.print(
        //     "totalOriginPatterns = " + totalOriginPatterns + "\n" +
        //     "totalUniquePatterns = " + totalUniquePatterns + "\n"
        // );

        int totalLimitError = 0;
        int totalCompileError = 0;
        int totalCapture = 0, totalBackref = 0;
        int totalStarInCapture = 0, totalBackrefInCapture = 0, totalBackrefInBridge = 0;
        int totalRemoveAnchor = 0, totalConvertError = 0;
        int totalVulnerable0 = 0, totalVulnerable1 = 0, totalVulnerable2 = 0, totalVulnerable3 = 0;
        int totalDetectError = 0, totalVulnerable = 0;
        long totalDetectTimeNs = 0;
        int i = 0;
        for (RPattern rpattern : rpatterns) {
            // FIXME
            // if (rpattern.pattern.equals("echo \"public static void main(String[] args) { \" | sed -r 's/((public|static|private|protected|\\s)*(void|int|String|double|float|\\s)+\\w+\\([^)]*\\)\\s*)/\\1throws java.lang.Exception / g'"))
            //     pattern = "echo \"public static void main(String\\[\\] args) { \" | sed -r 's/((public|static|private|protected|\\s)*(void|int|String|double|float|\\s)+\\w+\\([^)]*\\)\\s*)/\\1throws java.lang.Exception / g'";
            // FIXME
            // if (rpattern.pattern.equals("^Accept\\x2dCharset\\x3a\\s*?([^\\x3b\\x3d\\x2c]{1,36}\\s*?[\\x2d\\x3b\\x3d\\x2c]\\s*?)*[^\\x2d\\x3b\\x2c\\x3d\\n]{37}"))
            //     rpattern.pattern = "^Accept\\x2dCharset\\x3a\\s*?([^\\x3b\\x3d\\x2c]{1,36}\\s*?[\\x2d\\x3b\\x3d\\x2c]\\s*?)[^\\x2d\\x3b\\x2c\\x3d\\n]{37}";
            // else if (rpattern.pattern.equals("(^P\\x3B[^\\x3B]*\\x0D\\x0A){200}"))
            //     rpattern.pattern = "(^P\\x3B[^\\x3B]*\\x0D\\x0A)+";
            // else if (rpattern.pattern.equals("([\\w\\x25]+=[\\w\\x25]*&){500}"))
            //     rpattern.pattern = "([\\w\\x25]+=[\\w\\x25]*&)+";
            // else if (rpattern.pattern.equals("<[^>]*?style\\s*[>=].{1,1024}margin\\s*\\x3a\\s*[^\\x3b\\x7d]*?-\\d+.*?[\\x7b\\x3b]"))
            //     rpattern.pattern = "<[^>]*?style\\s*[>=].+margin\\s*\\x3a\\s*[^\\x3b\\x7d]*?-\\d+.*?[\\x7b\\x3b]";
            // ([\w\x25]+=[\w\x25]*&){500}
            // FIXME
            rpattern.pattern = rpattern.pattern.replace("[]", "\\[\\]");
            System.err.print(i + ": " + rpattern.toString() + '\n');
            
            RegexAutomatonAnalyzeResult result = analyzeRegexAutomaton(rpattern);
            if (result.limitError != null     ) ++totalLimitError      ;
            if (result.compileError != null   ) ++totalCompileError    ;
            if (result.capture                ) ++totalCapture         ;
            if (result.backref                ) ++totalBackref         ;
            if (result.starInCapture          ) ++totalStarInCapture   ;
            if (result.backrefInCapture       ) ++totalBackrefInCapture;
            if (result.backrefInBridge        ) ++totalBackrefInBridge ;
            if (result.removeAnchor           ) ++totalRemoveAnchor    ;
            if (result.convertError != null   ) ++totalConvertError    ;
            if (result.attackAuto0 != null    ) ++totalVulnerable0     ;
            if (result.attackAuto1 != null    ) ++totalVulnerable1     ;
            if (result.attackAuto2 != null    ) ++totalVulnerable2     ;
            if (result.attackAuto3 != null    ) ++totalVulnerable3     ;
            if (result.detectError0!= null || result.detectError1 != null 
            || result.detectError2 != null || result.detectError3 != null)
                ++totalDetectError;
            if (result.attackAuto0 != null || result.attackAuto1 != null 
            || result.attackAuto2 != null || result.attackAuto3 != null)
                ++totalVulnerable;
            totalDetectTimeNs += 
                result.detectTimeNs0 + result.detectTimeNs1 + 
                result.detectTimeNs2 + result.detectTimeNs3;
            if (reportPS != null)
                printAnalyzeAsReport(result, i, reportPS);
            if (atkrePS != null)
                printAnalyzeAsAtkre(result, atkrePS);
            
            ++i;
        }
        String total =
            "totalOriginPatterns = " + totalOriginPatterns +
            "\ntotalUniquePatterns = " + totalUniquePatterns + 
            "\ntotalLimitError = " + totalLimitError +
            "\ntotalCompileError = " + totalCompileError +
            "\ntotalCapture = " + totalCapture +
            "\ntotalBackref = " + totalBackref + 
            "\ntotalStarInCapture = " + totalStarInCapture +
            "\ntotalBackrefInCapture = " + totalBackrefInCapture +
            "\ntotalBackrefInBridge = " + totalBackrefInBridge + 
            "\ntotalRemoveAnchor = " + totalRemoveAnchor +
            "\ntotalConvertError = " + totalConvertError +
            "\ntotalVulnerable0 = " + totalVulnerable0 +
            "\ntotalVulnerable1 = " + totalVulnerable1 +
            "\ntotalVulnerable2 = " + totalVulnerable2 +
            "\ntotalVulnerable3 = " + totalVulnerable3 +
            "\ntotalDetectError = " + totalDetectError +
            "\ntotalVulnerable = " + totalVulnerable + 
            "\ntotalDetectTimeNs = " + totalDetectTimeNs +
            '\n';
        if (reportPS != null) {
            reportPS.print("\n[total]\n");
            reportPS.print(total);
            reportPS.close();
        }
        System.out.print('\n');
        System.out.print(total);
    }

    static RegexAutomatonAnalyzeResult analyzeRegexAutomaton(RPattern rpattern) {
        RegexAutomatonAnalyzeResult result = new RegexAutomatonAnalyzeResult();
        RegExp regex = null;
        Automaton auto = null;
        result.rpattern = rpattern;
        try{
            try {
                // FIXME consider flags
                regex = new RegExp(rpattern.pattern, RegExp.NONE);
                String regexStr = regex.toString();
            } catch (IllegalArgumentException compErr) {
                result.compileError = compErr;
                return result;
            }
            CaptureBackrefAnalysis cba = analyzeCaptureBackref(regex);
            result.capture = cba.capture;
            result.backref = cba.backref;
            result.starInCapture = cba.starInCapture;
            result.backrefInCapture = cba.backrefInCapture;
            result.backrefInBridge = cba.backrefInBridge;
            try {
                auto = regex.toAutomaton(false);
            } catch (UnsupportedOperationException cvtErr1) {
                regex = removeAnchor(regex);
                try {
                    auto = regex.toAutomaton(false);
                    result.removeAnchor = true;
                } catch (UnsupportedOperationException cvtErr2) {
                    result.convertError = cvtErr2;
                    return result;
                }
            }
            long startTime = System.nanoTime();
            try {
                result.attackAuto0 = SuperlinearDetector.detectOneIDAWithTimeout(auto, DETECT_IDA_TIMEOUT_NS);
            } catch (TimeoutException | InterruptedException timeoItrpErr0) {
                result.limitError = timeoItrpErr0;
            } catch (UnsupportedOperationException detErr0) {
                result.detectError0 = detErr0;
            }
            result.detectTimeNs0 = System.nanoTime() - startTime;
            startTime = System.nanoTime();
            try {
                result.attackAuto1 = SuperlinearDetector.detectOneBackrefToOverlapLoop(auto);
            } catch (UnsupportedOperationException detErr1) {
                result.detectError1 = detErr1;
            }
            result.detectTimeNs1 = System.nanoTime() - startTime;
            startTime = System.nanoTime();
            try {
                result.attackAuto2 = SuperlinearDetector.detectOneOverlapLoopBeforeBackrefToLoop(auto);
            } catch (UnsupportedOperationException detErr2) {
                result.detectError2 = detErr2;
            }
            result.detectTimeNs2 = System.nanoTime() - startTime;
            startTime = System.nanoTime();
            try {
                result.attackAuto3 = SuperlinearDetector.detectOneBackrefToLoopAndOverlapLoop(auto);
            } catch (UnsupportedOperationException detErr3) {
                result.detectError3 = detErr3;
            }
            result.detectTimeNs3 = System.nanoTime() - startTime;
        } catch (OutOfMemoryError oomErr) {
            result.limitError = oomErr;
        } catch (StackOverflowError stkOvflErr) {
            result.limitError = stkOvflErr;
        }
        return result;
    }

    /*
    static void printAnalyzeAsReport(RegexAutomatonAnalyzeResult result, int index, PrintStream out) {
        if (
            result.limitError == null &&   
            result.compileError == null && result.convertError == null &&
            !result.backref &&
            result.detectError0 == null && result.attackAuto0 == null &&
            result.detectError1 == null && result.attackAuto1 == null &&
            result.detectError2 == null && result.attackAuto2 == null &&
            result.detectError3 == null && result.attackAuto3 == null
        )
            return;
    
        out.print("\n# " + index + "\n");
        out.print("[[notes]]\n");
        out.print("pattern = " + DataLoadSave.toTomlString(result.rpattern.pattern) + '\n');
        // if (result.rpattern.flags != null)
        //    out.print("flags = " + DataLoadSave.toTomlString(result.rpattern.flags) + '\n');
        
        if (result.limitError != null) {
            out.print("limitError = '''\n");
            result.limitError.printStackTrace(out);
            out.print("'''\n");
            return;
        }
        if (result.compileError != null) {
            out.print("compileError = '''\n");
            result.compileError.printStackTrace(out);
            out.print("'''\n");
            return;
        }
        if (result.backref)
            out.print(
                "capture = " + result.capture +
                "\nbackref = true" +
                "\nstarInCapture = " + result.starInCapture +
                "\nbackrefInCapture = " + result.backrefInCapture +
                "\nbackrefInBridge = " + result.backrefInBridge + "\n"
            );
        if (result.convertError != null) {
            out.print("convertError = '''\n");
            result.convertError.printStackTrace(out);
            out.print("'''\n");
            return;
        }
        if (
            result.detectError0 != null || result.attackAuto0 != null ||
            result.detectError1 != null || result.attackAuto1 != null ||
            result.detectError2 != null || result.attackAuto2 != null ||
            result.detectError3 != null || result.attackAuto3 != null
        )
            out.print("removeAnchor = " + result.removeAnchor + "\n");
        else 
            return;
        for (int i = 0; i <= 3; ++i) {
            UnsupportedOperationException detectError = null;
            AttackAutomaton attackAuto = null;
            if (i == 0) {
                detectError = result.detectError0;
                attackAuto = result.attackAuto0;
            } else if (i == 1) {
                detectError = result.detectError1;
                attackAuto = result.attackAuto1;
            } else if (i == 2) {
                detectError = result.detectError2;
                attackAuto = result.attackAuto2;
            } else {
                detectError = result.detectError3;
                attackAuto = result.attackAuto3;
            }
            if (detectError != null) {
                out.print("detectError" + i + " = '''\n");
                detectError.printStackTrace(out);
                out.print("'''\n");
            } else
                out.print("vulnerable" + i + " = " + (attackAuto != null) + '\n');
        }
        // if (result.attackAuto != null) {
        //     out.print("attackAuto = '''\n" + result.attackAuto.toDot() + "'''\n");
        // }
        if (result.rpattern.source != null)
            out.print("source = " + DataLoadSave.toTomlString(result.rpattern.source) + '\n');
    }
    */

    static void printAnalyzeAsReport(RegexAutomatonAnalyzeResult result, int index, PrintStream out) {
        out.print(
            "\n#" + index +
            "\n[[note]]\npattern = " + DataLoadSave.toTomlString(result.rpattern.pattern) + 
            '\n'
        );
        if (result.limitError != null) {
            out.print("limitError = '''\n");
            result.limitError.printStackTrace(out);
            out.print("'''\n");
            return;
        }
        if (result.compileError != null) {
            out.print("compileError = '''\n");
            result.compileError.printStackTrace(out);
            out.print("'''\n");
            return;
        }
        out.print(
            "capture = " + result.capture +
            "\nbackref = " + result.backref +
            "\nstarInCapture = " + result.starInCapture +
            "\nbackrefInCapture = " + result.backrefInCapture +
            "\nbackrefInBridge = " + result.backrefInBridge +
            "\nremoveAnchor = " + result.removeAnchor +
            '\n'
        );
        if (result.convertError != null) {
            out.print("convertError = '''\n");
            result.convertError.printStackTrace(out);
            out.print("'''\n");
            return;
        }
        for (int i = 0; i <= 3; ++i) {
            UnsupportedOperationException detectError = null;
            AttackAutomaton attackAuto = null;
            long detectTimeNs = 0;
            if (i == 0) {
                detectError = result.detectError0;
                attackAuto = result.attackAuto0;
                detectTimeNs = result.detectTimeNs0;
            } else if (i == 1) {
                detectError = result.detectError1;
                attackAuto = result.attackAuto1;
                detectTimeNs = result.detectTimeNs1;
            } else if (i == 2) {
                detectError = result.detectError2;
                attackAuto = result.attackAuto2;
                detectTimeNs = result.detectTimeNs2;
            } else {
                detectError = result.detectError3;
                attackAuto = result.attackAuto3;
                detectTimeNs = result.detectTimeNs3;
            }
            if (detectError != null) {
                out.print("detectError" + i + " = '''\n");
                detectError.printStackTrace(out);
                out.print("'''\n");
            } else
                out.print("vulnerable" + i + " = " + (attackAuto != null) + '\n');
            out.print("detectTimeNs" + i + " = " + detectTimeNs + '\n');
        }
        if (result.rpattern.source != null)
            out.print("source = " + DataLoadSave.toTomlString(result.rpattern.source) + '\n');
    }

    static void printAnalyzeAsAtkre(RegexAutomatonAnalyzeResult result, PrintStream out) {
        for (int i = 0; i <= 3; ++i) {
            AttackAutomaton attackAuto =
                i == 0 ? result.attackAuto0 :
                i == 1 ? result.attackAuto1 :
                i == 2 ? result.attackAuto2 :
                result.attackAuto3;
            if (attackAuto == null)
                continue;
            String prefixString = AutomatonUtil.getAutomatonStringLocalMin(attackAuto.prefix);
            if (prefixString == null)
                continue;
            String pumpString = AutomatonUtil.getAutomatonStringLocalMin(attackAuto.pump, true);
            String suffixString = null;
            // try{
            //     suffixString = AutomatonUtil.getAutomatonStringLocalMin(attackAuto.suffix.complement());
            // } catch (UnsupportedOperationException err) {
            //     if (!attackAuto.suffix.run("#X"))
            //         suffixString = "#X";
            //     else
            //         throw err;
            // }
            // FIXME
            if (!attackAuto.suffix.run("#X"))
                suffixString = "#X";
            else {
                try {
                    Automaton suffixCompl = attackAuto.suffix.complement();
                    suffixString = AutomatonUtil.getAutomatonStringLocalMin(suffixCompl);
                } catch (UnsupportedOperationException err) {
                    Logger.getLogger(AnalyzeRegExp.class.getName()).log(
                        java.util.logging.Level.WARNING,
                        "cannot generate a string from the complement of suffix automaton",
                        err
                    );
                    suffixString = "!!!!!ERROR!!!!!";
                }
            }
            String fenceString = attackAuto.fence == null ? null :
                AutomatonUtil.getAutomatonStringLocalMin(attackAuto.fence);
            out.print(
                "[[exp]]\n" + 
                "regex = " + DataLoadSave.toTomlString(result.rpattern.pattern) + '\n' +
                "prefix = " + DataLoadSave.toTomlString(prefixString) + '\n' +
                "pump = " + DataLoadSave.toTomlString(pumpString) + '\n' +
                "suffix = " + DataLoadSave.toTomlString(suffixString) + '\n' + 
                (fenceString == null ? "" : ("fence = " + DataLoadSave.toTomlString(fenceString) + '\n')) +
                (result.rpattern.source == null ? "" : ("source = " + DataLoadSave.toTomlString(result.rpattern.source) + '\n')) +
                '\n'
            );
        }
    }

    static int getCaptureMax(RegExp exp) {
        int maxGroup = 0;
        ArrayDeque<RegExp> worklist = new ArrayDeque<RegExp>();
        worklist.add(exp);
        while (!worklist.isEmpty()) {
            RegExp e = worklist.removeLast();
            if (e.kind == RegExp.Kind.REGEXP_CAPTURE && e.group > maxGroup)
                maxGroup = e.group;
            if (e.exp2 != null)
                worklist.addLast(e.exp2);
            if (e.exp1 != null)
                worklist.addLast(e.exp1);
        }
        return maxGroup;
    } 

    static class EachCaptureBackrefAnalysis implements Cloneable {
        RegExp capture;
        boolean starInCapture;
        boolean backrefInCapture;
        BackrefAnalysis[] backrefs;

        @Override
        public EachCaptureBackrefAnalysis clone() {
            try{
                return (EachCaptureBackrefAnalysis) super.clone();
            } catch (CloneNotSupportedException err) {
                throw new RuntimeException(err.getMessage(), err);
            }
        }
    }

    static class BackrefAnalysis implements Cloneable {
        RegExp backref;
        boolean backrefInBridge;

        @Override
        public BackrefAnalysis clone() {
            try{
                return (BackrefAnalysis) super.clone();
            } catch (CloneNotSupportedException err) {
                throw new RuntimeException(err.getMessage(), err);
            }
        }
    }
    
    private static class EachCaptureBackrefHelperAnalysis extends EachCaptureBackrefAnalysis {
        boolean openCapture;
        boolean closeCapture;
        boolean backrefAfterCapture;
        
        @Override
        public EachCaptureBackrefHelperAnalysis clone() {
            return (EachCaptureBackrefHelperAnalysis) super.clone();
        }
    }

    static EachCaptureBackrefAnalysis[] analyzeEachCaptureBackref(RegExp exp) {
        int maxCapture = getCaptureMax(exp);
        EachCaptureBackrefHelperAnalysis[] initState = new EachCaptureBackrefHelperAnalysis[maxCapture + 1];
        for (int i = 1; i <= maxCapture; ++i) {
            initState[i] = new EachCaptureBackrefHelperAnalysis();
            initState[i].backrefs = new BackrefAnalysis[0];
        }
        return (EachCaptureBackrefAnalysis[]) analyzeEachCaptureBackrefHelper(exp, initState);
    }

    private static EachCaptureBackrefHelperAnalysis[] analyzeEachCaptureBackrefHelper(
        RegExp exp,
        EachCaptureBackrefHelperAnalysis[] status
    ) {
        switch (exp.kind) {
            case REGEXP_CAPTURE:
                EachCaptureBackrefHelperAnalysis[] newStatus1 = status.clone(); 
                newStatus1[exp.group] = status[exp.group].clone();
                newStatus1[exp.group].capture = exp;
                newStatus1[exp.group].openCapture = true;
                newStatus1 = analyzeEachCaptureBackrefHelper(exp.exp1, newStatus1);
                newStatus1[exp.group].closeCapture = true;
                return newStatus1;
            case REGEXP_REPEAT_MIN:
            case REGEXP_REPEAT_MIN_UNGREEDY:
                EachCaptureBackrefHelperAnalysis[] newStatus2 = status;
                for (int g = 1; g < status.length; ++g) {
                    if (status[g].openCapture && !status[g].closeCapture) {
                        if (newStatus2 == status)
                            newStatus2 = status.clone();
                        newStatus2[g] = status[g].clone();
                        newStatus2[g].starInCapture = true;
                    }
                }
                return analyzeEachCaptureBackrefHelper(exp.exp1, newStatus2);
            case REGEXP_BACKREF:
                EachCaptureBackrefHelperAnalysis[] newStatus3 = status;
                for (int g = 1; g < status.length; ++g) {
                    if (g == exp.group || status[g].openCapture) {
                        if (newStatus3 == status)
                            newStatus3 = status.clone();
                        newStatus3[g] = status[g].clone();
                    }
                    if (g == exp.group) {
                        BackrefAnalysis ba = new BackrefAnalysis();
                        ba.backref = exp;
                        ba.backrefInBridge = newStatus3[g].backrefAfterCapture;
                        newStatus3[g].backrefs = ArrayUtil.copyAndAddLast(newStatus3[g].backrefs, ba);
                    }
                    if (status[g].openCapture) {
                        if (!status[g].closeCapture)
                            status[g].backrefInCapture = true;
                        else
                            status[g].backrefAfterCapture = true;
                    }
                }
                return newStatus3;
            case REGEXP_UNION:
                EachCaptureBackrefHelperAnalysis[] newStatus41 = analyzeEachCaptureBackrefHelper(exp.exp1, status);
                EachCaptureBackrefHelperAnalysis[] newStatus42 = analyzeEachCaptureBackrefHelper(exp.exp2, status);
                if (newStatus41 == status)
                    // equivalent to if (newStatus42 == status) return status; else return newStatus42;
                    return newStatus42;
                else if (newStatus42 == status)
                    return newStatus41;
                // else
                for (int g = 1; g < newStatus41.length; ++g) {
                    EachCaptureBackrefHelperAnalysis cbha41 = newStatus41[g]; 
                    EachCaptureBackrefHelperAnalysis cbha42 = newStatus42[g];
                    if (cbha41 == null) {
                        newStatus41[g] = cbha42;
                        continue;
                    } else if (cbha42 == null)
                        continue;
                    cbha41.capture = cbha42.capture != null ? cbha42.capture : cbha41.capture;
                    cbha41.starInCapture = cbha41.starInCapture || cbha42.starInCapture;
                    cbha41.backrefInCapture = cbha41.backrefInCapture || cbha42.backrefInCapture;
                    cbha41.backrefs = cbha41.backrefs.length == 0 ? cbha42.backrefs : 
                        cbha42.backrefs.length == 0 ? cbha41.backrefs : 
                        ArrayUtil.concat(cbha41.backrefs, cbha42.backrefs);
                    cbha41.openCapture = cbha41.openCapture || cbha42.openCapture;
                    cbha41.closeCapture = cbha41.closeCapture || cbha42.closeCapture;
                    cbha41.backrefAfterCapture = cbha41.backrefAfterCapture || cbha42.backrefAfterCapture;
                }
                return newStatus41;
            case REGEXP_INTERSECTION:
            case REGEXP_CONCATENATION:
                EachCaptureBackrefHelperAnalysis[] newState5 = analyzeEachCaptureBackrefHelper(exp.exp1, status);
                newState5 = analyzeEachCaptureBackrefHelper(exp.exp2, newState5);
                return newState5;
            default:
                if (exp.exp1 != null)
                    return analyzeEachCaptureBackrefHelper(exp.exp1, status);
                else
                    return status;
        }
    }

    static class CaptureBackrefAnalysis {
        boolean capture;
        boolean backref;
        boolean starInCapture;
        boolean backrefInCapture;
        boolean backrefInBridge;
    }

    static CaptureBackrefAnalysis analyzeCaptureBackref(RegExp exp) {
        EachCaptureBackrefAnalysis[] cba = analyzeEachCaptureBackref(exp);
        CaptureBackrefAnalysis res = new CaptureBackrefAnalysis();
        for (int g = 1; g < cba.length; ++g) {
            EachCaptureBackrefAnalysis a = cba[g];
            if (a.capture != null)
                res.capture = true;
            boolean backref = a.backrefs.length > 0;
            res.backref = res.backref || backref;
            res.starInCapture = res.starInCapture || (backref && a.starInCapture);
            res.backrefInCapture = res.backrefInCapture || (backref && a.backrefInCapture);
            for (BackrefAnalysis b : a.backrefs)
                res.backrefInBridge = res.backrefInBridge || b.backrefInBridge;
        }
        return res;
    }

    static RegExp removeAnchor(RegExp exp) {
        RegExp newExp = new RegExp();
        if (exp.kind == RegExp.Kind.REGEXP_ANCHOR_LINE_START || 
            exp.kind == RegExp.Kind.REGEXP_ANCHOR_LINE_END ||
            exp.kind == RegExp.Kind.REGEXP_ANCHOR_WORDBORDER ||
            exp.kind == RegExp.Kind.REGEXP_ANCHOR_NOT_WORDBORDER
        ) {
            newExp.kind = RegExp.Kind.REGEXP_EMPTYSTRING;
        } else if (
            RegExp.findCharCateShort(exp) != RegExp.EMPTY_CHAR ||
            RegExp.CHAR_CATE_POSIX_MAP.containsValue(exp)
        ) {
            return exp;
        } else {
            newExp.kind = exp.kind;
            newExp.s = exp.s;
            newExp.c = exp.c;
            newExp.min = exp.min;
            newExp.max = exp.max;
            newExp.digits = exp.digits;
            newExp.from = exp.from;
            newExp.to = exp.to;
            newExp.group = exp.group;
            if (exp.exp1 != null)
                newExp.exp1 = removeAnchor(exp.exp1);
            if (exp.exp2 != null)
                newExp.exp2 = removeAnchor(exp.exp2);
        }
        return newExp;
    }

}
