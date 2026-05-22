package dk.brics.automaton;

import java.io.IOException;
import java.io.PrintStream;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.logging.Level;
import java.util.logging.Logger;

import net.sourceforge.argparse4j.ArgumentParsers;
import net.sourceforge.argparse4j.impl.Arguments;
import net.sourceforge.argparse4j.inf.ArgumentParser;
import net.sourceforge.argparse4j.inf.ArgumentParserException;
import net.sourceforge.argparse4j.inf.Namespace;

public class Main {

    static final Logger LOGGER = Logger.getLogger(Main.class.getName());

    /* DetectEntry */

    static class DetectEntry {
        final int vulType;
        /** null = detection was not attempted; empty = attempted but nothing found */
        List<AttackAutomaton> attackAutos;
        Throwable detectError;
        long detectTimeNs;

        DetectEntry(int vulType) {
            this.vulType = vulType;
        }

        boolean isVulnerable() {
            return attackAutos != null && !attackAutos.isEmpty();
        }
    }

    /* RegexAutomatonAnalyzeResult */

    static class RegexAutomatonAnalyzeResult {
        int originIndex;
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
        List<DetectEntry> detectEntries = new ArrayList<>();

        boolean isVulnerable() {
            for (DetectEntry e : detectEntries)
                if (e.isVulnerable()) return true;
            return false;
        }

        boolean isVulnerableByType(int vulType) {
            for (DetectEntry e : detectEntries)
                if (e.vulType == vulType && e.isVulnerable()) return true;
            return false;
        }

        boolean hasDetectError() {
            for (DetectEntry e : detectEntries)
                if (e.detectError != null) return true;
            return false;
        }

        long totalDetectTimeNs() {
            long total = 0;
            for (DetectEntry e : detectEntries)
                total += e.detectTimeNs;
            return total;
        }

        String toDetectTomlString() {
            StringBuilder sb = new StringBuilder();
            sb.append("\n[[note]]\npattern = ")
              .append(DataLoadSave.toTomlString(rpattern.pattern)).append('\n')
              .append("originIndex = ").append(originIndex).append('\n');
            if (limitError != null) {
                sb.append("limitError = '''\n").append(throwableToString(limitError)).append("'''\n");
                return sb.toString();
            }
            if (compileError != null) {
                sb.append("compileError = '''\n").append(throwableToString(compileError)).append("'''\n");
                return sb.toString();
            }
            sb.append("capture = ").append(capture)
              .append("\nbackref = ").append(backref)
              .append("\nstarInCapture = ").append(starInCapture)
              .append("\nbackrefInCapture = ").append(backrefInCapture)
              .append("\nbackrefInBridge = ").append(backrefInBridge)
              .append("\nremoveAnchor = ").append(removeAnchor)
              .append('\n');
            if (convertError != null) {
                sb.append("convertError = '''\n").append(throwableToString(convertError)).append("'''\n");
                return sb.toString();
            }
            for (DetectEntry entry : detectEntries) {
                int v = entry.vulType;
                if (entry.detectError != null) {
                    sb.append("detectError").append(v).append(" = '''\n")
                      .append(throwableToString(entry.detectError)).append("'''\n");
                } else {
                    sb.append("vulnerable").append(v).append(" = ")
                      .append(entry.isVulnerable()).append('\n');
                }
                sb.append("detectTimeNs").append(v).append(" = ").append(entry.detectTimeNs).append('\n');
            }
            if (rpattern.sources != null)
                sb.append("sources = ").append(sourcesToTomlList(rpattern.sources)).append('\n');
            return sb.toString();
        }

        String toAtkreTomlString() {
            StringBuilder sb = new StringBuilder();
            if (!isVulnerable())
                return sb.toString();
            Automaton auto;
            try {
                auto = AnalyzeRegExp.removeAnchor(
                    new RegExp(rpattern.pattern, RegExp.NONE)).toAutomaton(false);
            } catch (IllegalArgumentException | UnsupportedOperationException err) {
                return sb.toString();
            }
            String[] captures = AutomatonUtil.getAutomatonCaptureStringLocalMin(auto);
            for (DetectEntry entry : detectEntries) {
                if (!entry.isVulnerable())
                    continue;
                for (AttackAutomaton attackAuto : entry.attackAutos) {
                    String prefixString = AutomatonUtil.getAutomatonStringLocalMin(
                        attackAuto.prefix, false, captures);
                    if (prefixString == null) {
                        LOGGER.warning("cannot generate prefix string");
                        prefixString = "!!!!! ERROR: CANNOT GENERATE !!!!!";
                    }
                    String pumpString = AutomatonUtil.getAutomatonStringLocalMin(
                        attackAuto.pump, true);
                    if (pumpString == null) {
                        LOGGER.warning("cannot generate pump string");
                        pumpString = "!!!!! ERROR: CANNOT GENERATE !!!!!";
                    }
                    String suffixString;
                    if (!attackAuto.suffix.run("#X")) {
                        suffixString = "#X";
                    } else {
                        try {
                            suffixString = AutomatonUtil.getAutomatonStringLocalMin(
                                attackAuto.suffix.complement());
                        } catch (UnsupportedOperationException err) {
                            LOGGER.log(Level.WARNING,
                                "cannot generate a string from the complement of suffix automaton",
                                err);
                            suffixString = "!!!!! ERROR: CANNOT GENERATE !!!!!";
                        }
                    }
                    String fenceString = null;
                    if (attackAuto.fence != null) {
                        fenceString = AutomatonUtil.getAutomatonStringLocalMin(
                            attackAuto.fence, false, captures);
                        if (fenceString == null) {
                            LOGGER.warning("cannot generate fence string");
                            fenceString = "!!!!! ERROR: CANNOT GENERATE !!!!!";
                        }
                    }
                    sb.append("[[exp]]\n")
                      .append("regex = ").append(DataLoadSave.toTomlString(rpattern.pattern)).append('\n')
                      .append("originIndex = ").append(originIndex).append('\n')
                      .append("vul_type = ").append(attackAuto.vulnerableType).append('\n')
                      .append("prefix = ").append(DataLoadSave.toTomlString(prefixString)).append('\n')
                      .append("pump = ").append(DataLoadSave.toTomlString(pumpString)).append('\n')
                      .append("suffix = ").append(DataLoadSave.toTomlString(suffixString)).append('\n');
                    if (fenceString != null)
                        sb.append("fence = ").append(DataLoadSave.toTomlString(fenceString)).append('\n');
                    if (rpattern.sources != null)
                        sb.append("sources = ").append(sourcesToTomlList(rpattern.sources)).append('\n');
                    sb.append('\n');
                }
            }
            return sb.toString();
        }
    }

    /* Entry point */

    public static void main(String[] args) throws IOException, SQLException {
        Namespace ns = parseArgs(args);

        String input = ns.getString("input");
        Path inputPath = Path.of(input);
        String inputFormat = ns.getString("format");
        if (inputFormat == null) {
            inputFormat = DataLoadSave.guessInputFormatByPath(inputPath);
            if (inputFormat == null) {
                System.err.println("Cannot guess input format from path; provide -f/--format.");
                System.exit(1);
            }
        }
        List<RPattern> rpatterns;
        switch (inputFormat) {
            case "toml":     rpatterns = DataLoadSave.loadTomlPattern(inputPath);          break;
            case "json":     rpatterns = DataLoadSave.loadJsonPattern(inputPath);          break;
            case "snort":    rpatterns = DataLoadSave.loadSnortRulesPattern(inputPath);    break;
            case "snortdir": rpatterns = DataLoadSave.loadSnortRulesDirPattern(inputPath); break;
            default:
                System.err.println("Unknown input format: " + inputFormat);
                System.exit(1);
                return;
        }

        int[] vulTypes  = parseVulTypes(ns.getString("vultypes"));
        boolean multiple  = Boolean.TRUE.equals(ns.get("multiple"));
        long timeoutNs = (long) ns.getInt("timeout") * 1_000_000_000L;

        String outputReport = ns.getString("output");
        String outputAtkre  = ns.getString("atkre");

        PrintStream reportPS = null;
        PrintStream atkrePS  = null;
        try {
            if (outputReport != null)
                reportPS = new PrintStream(outputReport, StandardCharsets.UTF_8);
            if (outputAtkre != null)
                atkrePS = new PrintStream(outputAtkre, StandardCharsets.UTF_8);
            analyzeRegexAutomatons(rpatterns, vulTypes, multiple, timeoutNs, reportPS, atkrePS);
        } finally {
            if (reportPS != null) reportPS.close();
            if (atkrePS  != null) atkrePS.close();
        }

        for (ExecutorService ex : ANALYZE_EXECUTORS.values()) {
            try {
                ex.shutdown();
                ex.awaitTermination(timeoutNs, TimeUnit.NANOSECONDS);
            } catch (InterruptedException ignored) {}
        }
    }

    /* Argument parsing */

    private static Namespace parseArgs(String[] args) {
        ArgumentParser parser = ArgumentParsers.newFor("dk.brics.automaton.Main").build()
            .description("Analyze regular expressions with backreferences for DoS vulnerabilities.");
        parser.addArgument("-i", "--input").metavar("FILE").required(true)
            .help("Input file path");
        parser.addArgument("-f", "--format")
            .choices("json", "toml", "snort", "snortdir")
            .help("Input format (default: inferred from file extension)");
        parser.addArgument("-o", "--output").metavar("FILE")
            .help("Detection report output file (TOML)");
        parser.addArgument("-a", "--atkre").metavar("FILE")
            .help("Attack string output file (TOML)");
        parser.addArgument("-t", "--timeout").metavar("SECONDS")
            .type(Integer.class).setDefault(60)
            .help("Per-regex detection timeout in seconds (default: 60)");
        parser.addArgument("-v", "--vultypes").metavar("TYPES")
            .setDefault("123")
            .help("Vul types to detect; each char in \"0123\" selects a type (default: all)");
        parser.addArgument("-m", "--multiple")
            .type(Boolean.class).action(Arguments.storeTrue()).setDefault(false)
            .help("Detect all vulnerabilities per type instead of stopping at the first");
        try {
            return parser.parseArgs(args);
        } catch (ArgumentParserException e) {
            parser.handleError(e);
            System.exit(1);
            return null; // unreachable
        }
    }

    private static int[] parseVulTypes(String s) {
        if (s == null) return new int[]{0, 1, 2, 3};
        LinkedHashSet<Integer> seen = new LinkedHashSet<>();
        for (char c : s.toCharArray()) {
            if (c >= '0' && c <= '3')
                seen.add(c - '0');
            else {
                System.err.println("Unknown vul type '" + c + "'; valid chars: 0 1 2 3");
                System.exit(1);
            }
        }
        int[] result = new int[seen.size()];
        int i = 0;
        for (int t : seen) result[i++] = t;
        return result;
    }

    /* Batch analysis */

    static void analyzeRegexAutomatons(
        List<RPattern> rpatterns,
        int[] vulTypes,
        boolean multiple,
        long timeoutNs,
        PrintStream reportPS,
        PrintStream atkrePS
    ) {
        int totalOriginPatterns = rpatterns.size();
        rpatterns = DataLoadSave.mergeRepeatRPattern(rpatterns);
        int totalUniquePatterns = rpatterns.size();

        int totalLimitError = 0, totalCompileError = 0;
        int totalCapture = 0, totalBackref = 0;
        int totalStarInCapture = 0, totalBackrefInCapture = 0, totalBackrefInBridge = 0;
        int totalRemoveAnchor = 0, totalConvertError = 0;
        int totalDetectError = 0, totalVulnerable = 0;
        int[] totalVulnerableByType = new int[4];
        long totalDetectTimeNs = 0;

        int i = 0;
        for (RPattern rpattern : rpatterns) {
            rpattern.pattern = rpattern.pattern.replace("[]", "\\[\\]");
            System.err.print(i + ": " + rpattern.toString() + '\n');

            RegexAutomatonAnalyzeResult result = analyzeRegexAutomaton(
                rpattern, vulTypes, multiple, timeoutNs);
            result.originIndex = i;

            if (result.limitError != null)   ++totalLimitError;
            if (result.compileError != null) ++totalCompileError;
            if (result.capture)              ++totalCapture;
            if (result.backref)              ++totalBackref;
            if (result.starInCapture)        ++totalStarInCapture;
            if (result.backrefInCapture)     ++totalBackrefInCapture;
            if (result.backrefInBridge)      ++totalBackrefInBridge;
            if (result.removeAnchor)         ++totalRemoveAnchor;
            if (result.convertError != null) ++totalConvertError;
            if (result.hasDetectError())     ++totalDetectError;
            if (result.isVulnerable())       ++totalVulnerable;
            for (DetectEntry entry : result.detectEntries) {
                totalDetectTimeNs += entry.detectTimeNs;
                if (entry.isVulnerable() && entry.vulType < totalVulnerableByType.length)
                    ++totalVulnerableByType[entry.vulType];
            }

            if (reportPS != null) reportPS.print(result.toDetectTomlString());
            if (atkrePS  != null) atkrePS.print(result.toAtkreTomlString());
            ++i;
        }

        StringBuilder total = new StringBuilder();
        total.append("totalOriginPatterns = ").append(totalOriginPatterns).append('\n')
             .append("totalUniquePatterns = ").append(totalUniquePatterns).append('\n')
             .append("totalLimitError = ").append(totalLimitError).append('\n')
             .append("totalCompileError = ").append(totalCompileError).append('\n')
             .append("totalCapture = ").append(totalCapture).append('\n')
             .append("totalBackref = ").append(totalBackref).append('\n')
             .append("totalStarInCapture = ").append(totalStarInCapture).append('\n')
             .append("totalBackrefInCapture = ").append(totalBackrefInCapture).append('\n')
             .append("totalBackrefInBridge = ").append(totalBackrefInBridge).append('\n')
             .append("totalRemoveAnchor = ").append(totalRemoveAnchor).append('\n')
             .append("totalConvertError = ").append(totalConvertError).append('\n');
        for (int v = 0; v < totalVulnerableByType.length; ++v)
            total.append("totalVulnerable").append(v).append(" = ")
                 .append(totalVulnerableByType[v]).append('\n');
        total.append("totalDetectError = ").append(totalDetectError).append('\n')
             .append("totalVulnerable = ").append(totalVulnerable).append('\n')
             .append("totalDetectTimeNs = ").append(totalDetectTimeNs).append('\n');

        if (reportPS != null) {
            reportPS.print("\n[total]\n");
            reportPS.print(total.toString());
        }
        System.out.print('\n');
        System.out.print(total.toString());
    }

    /* Per-regex analysis */

    private static final HashMap<Long, ExecutorService> ANALYZE_EXECUTORS = new HashMap<>();

    static RegexAutomatonAnalyzeResult analyzeRegexAutomaton(
        RPattern rpattern, int[] vulTypes, boolean multiple, long timeoutNs
    ) {
        RegexAutomatonAnalyzeResult result = new RegexAutomatonAnalyzeResult();
        result.rpattern = rpattern;
        try {
            // Compile
            RegExp regex;
            try {
                regex = new RegExp(rpattern.pattern, RegExp.NONE);
            } catch (IllegalArgumentException compErr) {
                result.compileError = compErr;
                return result;
            }

            // Capture/backref analysis
            AnalyzeRegExp.CaptureBackrefAnalysis cba = AnalyzeRegExp.analyzeCaptureBackref(regex);
            result.capture          = cba.capture;
            result.backref          = cba.backref;
            result.starInCapture    = cba.starInCapture;
            result.backrefInCapture = cba.backrefInCapture;
            result.backrefInBridge  = cba.backrefInBridge;

            // Build automaton
            Automaton auto;
            try {
                auto = regex.toAutomaton(false);
            } catch (UnsupportedOperationException cvtErr) {
                regex = AnalyzeRegExp.removeAnchor(regex);
                try {
                    auto = regex.toAutomaton(false);
                    result.removeAnchor = true;
                } catch (UnsupportedOperationException cvtErr2) {
                    result.convertError = cvtErr2;
                    return result;
                }
            }

            if (vulTypes.length == 0)
                return result;

            // Run all requested vul-type detections inside a single executor task so
            // the combined timeout covers all of them.  The task fills `entries` in
            // order; on interruption it stops early, leaving the rest unrecorded.
            final Automaton finalAuto = auto;
            final List<DetectEntry> entries = new ArrayList<>();

            ExecutorService executor = getOrCreateExecutor();
            Thread executorThread = getExecutorThread(executor);

            Future<?> future = executor.submit(new Callable<Void>() {
                @Override
                public Void call() {
                    for (int vulType : vulTypes) {
                        // Clear + check interrupt flag before each type so a leftover
                        // flag from a prior timeout does not skip detection immediately.
                        if (Thread.interrupted())
                            break;
                        DetectEntry entry = new DetectEntry(vulType);
                        long t = System.nanoTime();
                        try {
                            if (multiple) {
                                entry.attackAutos = runDetectMany(vulType, finalAuto);
                            } else {
                                AttackAutomaton one = runDetectOne(vulType, finalAuto);
                                entry.attackAutos = one != null
                                    ? Collections.singletonList(one)
                                    : Collections.<AttackAutomaton>emptyList();
                            }
                        } catch (UnsupportedOperationException err) {
                            entry.detectError = err;
                        } catch (InterruptedException err) {
                            // Interrupted mid-detection: record elapsed time, stop loop.
                            // Do NOT restore the interrupt flag so the executor thread
                            // is clean for the next regex.
                            entry.detectTimeNs = System.nanoTime() - t;
                            entries.add(entry);
                            break;
                        }
                        entry.detectTimeNs = System.nanoTime() - t;
                        entries.add(entry);
                        // detectMany with POLICY_INTERRUPT_RETURN sets the flag on
                        // partial return; clear + check it here to stop early.
                        if (Thread.interrupted())
                            break;
                    }
                    return null;
                }
            });

            try {
                future.get(timeoutNs, TimeUnit.NANOSECONDS);
            } catch (TimeoutException | InterruptedException timeoutErr) {
                executorThread.interrupt();
                // Wait for the task to finish so `entries` is fully written before
                // we read it below.
                try { future.get(); } catch (InterruptedException | ExecutionException ignored) {}
                result.limitError = timeoutErr;
            } catch (ExecutionException exErr) {
                Throwable cause = exErr.getCause();
                // The task is designed not to throw checked exceptions; escalate unexpected ones.
                if (cause instanceof RuntimeException) throw (RuntimeException) cause;
                if (cause instanceof Error)             throw (Error) cause;
                result.limitError = cause;
            }
            // future.get() provides the happens-before guarantee.
            result.detectEntries = entries;

        } catch (OutOfMemoryError | StackOverflowError limitErr) {
            result.limitError = limitErr;
        }
        return result;
    }

    /* Detection dispatch */

    private static List<AttackAutomaton> runDetectMany(int vulType, Automaton auto)
    throws UnsupportedOperationException, InterruptedException {
        switch (vulType) {
            case 0: return SuperlinearDetector.detectAsManyIDA(auto);
            case 1: return SuperlinearDetector.detectAsManyOneBackrefToOverlapLoop(auto);
            case 2: return SuperlinearDetector.detectAsManyOverlapLoopBeforeBackrefToLoop(auto);
            case 3: return SuperlinearDetector.detectAsMuchBackrefToLoopAndOverlapLoop(auto);
            default: throw new IllegalArgumentException("unknown vul type: " + vulType);
        }
    }

    private static AttackAutomaton runDetectOne(int vulType, Automaton auto)
    throws UnsupportedOperationException, InterruptedException {
        switch (vulType) {
            case 0: return SuperlinearDetector.detectOneIDA(auto);
            case 1: return SuperlinearDetector.detectOneBackrefToOverlapLoop(auto);
            case 2: return SuperlinearDetector.detectOneOverlapLoopBeforeBackrefToLoop(auto);
            case 3: return SuperlinearDetector.detectOneBackrefToLoopAndOverlapLoop(auto);
            default: throw new IllegalArgumentException("unknown vul type: " + vulType);
        }
    }

    /* Helpers */


    private static ExecutorService getOrCreateExecutor() {
        long threadId = Thread.currentThread().getId();
        ExecutorService executor = ANALYZE_EXECUTORS.get(threadId);
        if (executor == null) {
            executor = Executors.newSingleThreadExecutor();
            ANALYZE_EXECUTORS.put(threadId, executor);
        }
        return executor;
    }

    private static Thread getExecutorThread(ExecutorService executor) {
        try {
            return executor.submit(new Callable<Thread>() {
                @Override
                public Thread call() { return Thread.currentThread(); }
            }).get();
        } catch (ExecutionException | InterruptedException err) {
            throw new RuntimeException("unexpected exception when getting executor thread", err);
        }
    }

    static String throwableToString(Throwable t) {
        StringWriter sw = new StringWriter();
        t.printStackTrace(new PrintWriter(sw));
        return sw.toString();
    }

    private static String sourcesToTomlList(String[] sources) {
        StringBuilder sb = new StringBuilder("[\n");
        for (String s : sources)
            sb.append("    ").append(DataLoadSave.toTomlString(s)).append(",\n");
        sb.append(']');
        return sb.toString();
    }
}
