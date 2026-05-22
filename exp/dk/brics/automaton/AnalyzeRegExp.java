package dk.brics.automaton;
import java.util.ArrayDeque;
import java.util.logging.Logger;


public class AnalyzeRegExp {
    static final long DETECT_IDA_TIMEOUT_NS = 1L * 60L * 1000_000_000L; // 1 minute

    static final Logger LOGGER = Logger.getLogger(AnalyzeRegExp.class.getName());

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
