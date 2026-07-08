package edu.stonybrook.rewbguard;
import java.lang.reflect.Field;
import java.lang.reflect.Modifier;
import java.util.ArrayDeque;
import java.util.logging.Logger;

import dk.brics.automaton.RegExp;


public class AnalyzeRegExp {
    static final long DETECT_IDA_TIMEOUT_NS = 1L * 60L * 1000_000_000L; // 1 minute

    static final Logger LOGGER = Logger.getLogger(AnalyzeRegExp.class.getName());

    static int getCaptureMax(RegExp exp) {
        int maxGroup = 0;
        ArrayDeque<RegExp> worklist = new ArrayDeque<RegExp>();
        worklist.add(exp);
        while (!worklist.isEmpty()) {
            RegExp e = worklist.removeLast();
            RegExp.Kind kind = getRegExpKind(e);
            RegExp subExp2 = getRegExpExp2(e);
            RegExp subExp1 = getRegExpExp1(e);
            int group;
            if (kind == RegExp.Kind.REGEXP_CAPTURE && (group = getRegExpGroup(e)) > maxGroup)
                maxGroup = group;
            if (subExp2 != null)
                worklist.addLast(subExp2);
            if (subExp1 != null)
                worklist.addLast(subExp1);
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
        RegExp subExp1 = getRegExpExp1(exp);
        RegExp subExp2 = getRegExpExp2(exp);
        int group = getRegExpGroup(exp);
        switch (getRegExpKind(exp)) {
            case REGEXP_CAPTURE:
                EachCaptureBackrefHelperAnalysis[] newStatus1 = status.clone(); 
                newStatus1[group] = status[group].clone();
                newStatus1[group].capture = exp;
                newStatus1[group].openCapture = true;
                newStatus1 = analyzeEachCaptureBackrefHelper(subExp1, newStatus1);
                newStatus1[group].closeCapture = true;
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
                return analyzeEachCaptureBackrefHelper(subExp1, newStatus2);
            case REGEXP_BACKREF:
                EachCaptureBackrefHelperAnalysis[] newStatus3 = status;
                for (int g = 1; g < status.length; ++g) {
                    if (g == group || status[g].openCapture) {
                        if (newStatus3 == status)
                            newStatus3 = status.clone();
                        newStatus3[g] = status[g].clone();
                    }
                    if (g == group) {
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
                EachCaptureBackrefHelperAnalysis[] newStatus41 = analyzeEachCaptureBackrefHelper(subExp1, status);
                EachCaptureBackrefHelperAnalysis[] newStatus42 = analyzeEachCaptureBackrefHelper(subExp2, status);
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
                EachCaptureBackrefHelperAnalysis[] newState5 = analyzeEachCaptureBackrefHelper(subExp1, status);
                newState5 = analyzeEachCaptureBackrefHelper(subExp2, newState5);
                return newState5;
            default:
                if (subExp1 != null)
                    return analyzeEachCaptureBackrefHelper(subExp1, status);
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
        RegExp.Kind kind = getRegExpKind(exp);
        if (kind == RegExp.Kind.REGEXP_ANCHOR_LINE_START || 
            kind == RegExp.Kind.REGEXP_ANCHOR_LINE_END ||
            kind == RegExp.Kind.REGEXP_ANCHOR_WORDBORDER ||
            kind == RegExp.Kind.REGEXP_ANCHOR_NOT_WORDBORDER
        ) {
            return new RegExp(""); // accept empty string
        } else {
            try{
                RegExp newExp = new RegExp("");
                for (Field field : RegExp.class.getDeclaredFields()) {
                    if (Modifier.isStatic(field.getModifiers()))
                        continue;
                    @SuppressWarnings("deprecated")
                    boolean accessible = field.isAccessible();
                    field.setAccessible(true);
                    Object value = field.get(exp);
                    field.set(newExp, value);
                    field.setAccessible(accessible);
                }
                for (int i = 1; i <= 2; ++i) {
                    Field field = i == 1 ? REGEXP_FIELD_EXP1 : REGEXP_FIELD_EXP2;
                    RegExp subExp = (RegExp) getFieldValue(field, exp);
                    if (subExp == null)
                        continue;
                    RegExp newSubExp = removeAnchor(subExp);
                    setFieldValue(field, newExp, newSubExp);
                }
                return newExp;
            } catch (IllegalAccessException | SecurityException e) {
                throw new RuntimeException("cannot access fields of RegExp", e);
            }
        }
    }


    private static Field getRegExpDeclaredField(String name) {
        try {
            return RegExp.class.getDeclaredField(name);
        } catch (NoSuchFieldException | SecurityException e) {
            throw new RuntimeException("cannot get RegExp field reflection " + name, e);
        }
    }

    static final Field REGEXP_FIELD_KIND = getRegExpDeclaredField("kind");
    static final Field REGEXP_FIELD_EXP1 = getRegExpDeclaredField("exp1");
    static final Field REGEXP_FIELD_EXP2 = getRegExpDeclaredField("exp2");
    static final Field REGEXP_FIELD_GROUP = getRegExpDeclaredField("group");

    private static Object getFieldValue(Field field, Object obj) {
        try {
            @SuppressWarnings("deprecated")
            boolean accessible = field.isAccessible();
            field.setAccessible(true);
            Object value = field.get(obj);
            field.setAccessible(accessible);
            return value;
        } catch (IllegalAccessException e) {
            IllegalAccessError error = new IllegalAccessError("error when get field");
            error.initCause(e);
            throw error;
        }
    }
    private static void setFieldValue(Field field, Object obj, Object value) {
        try {
            @SuppressWarnings("deprecated")
            boolean accessible = field.isAccessible();
            field.setAccessible(true);
            field.set(obj, value);
            field.setAccessible(accessible);
        } catch (IllegalAccessException e) {
            IllegalAccessError error = new IllegalAccessError("error when get field");
            error.initCause(e);
            throw error;
        }
    }

    private static RegExp.Kind getRegExpKind(RegExp exp) {
        return (RegExp.Kind) getFieldValue(REGEXP_FIELD_KIND, exp);
    }
    private static RegExp getRegExpExp1(RegExp exp) {
        return (RegExp) getFieldValue(REGEXP_FIELD_EXP1, exp);
    }
    private static RegExp getRegExpExp2(RegExp exp) {
        return (RegExp) getFieldValue(REGEXP_FIELD_EXP2, exp);
    }
    private static int getRegExpGroup(RegExp exp) {
        return ((Integer) getFieldValue(REGEXP_FIELD_GROUP, exp)).intValue();
    }
}
