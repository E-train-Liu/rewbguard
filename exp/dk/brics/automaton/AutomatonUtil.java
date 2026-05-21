package dk.brics.automaton;

import java.util.ArrayDeque;
import java.util.Arrays;
import java.util.Comparator;
import java.util.HashSet;
import java.util.IdentityHashMap;

public class AutomatonUtil{
    private static class StateCapture {
        State state;
        String[] captureP1;
        String[] captureP2;
        StateCapture() {}
		StateCapture(State state, int nGroups) {
            this(state, new String[nGroups + 1], new String[nGroups + 1]);
        }
        StateCapture(State state, String[] captureP1, String[] captureP2) {
            this.state = state;
            this.captureP1 = captureP1;
            this.captureP2 = captureP2;
        }
        public StateCapture deepClone() {
            return new StateCapture(
                state,
                captureP1 == null ? null : captureP1.clone(),
                captureP2 == null ? null : captureP2.clone()
            );
        }
    }

    private static class TransitionStringComparator implements Comparator<Transition> {
        private String[] capture;
        public TransitionStringComparator(String[] capture) {
            this.capture = capture;
        }
        public int compare(Transition t1, Transition t2) {
            String str1 = tranToStr(t1);
            String str2 = tranToStr(t2);
            if (str1 == null)
                return str2 == null ? 0 : -1;
            else if (str2 == null)
                return 1;
            int strCmp = str1.compareTo(str2);
            if (strCmp != 0)
                return strCmp;
            int kindCmp = t1.getKind().compareTo(t2.getKind());
            if (kindCmp != 0)
                return kindCmp;
            if (t1.getDest() == null)
                return t2.getDest() == null ? 0 : -1;
            if (t2.getDest() == null)
                return 1;
            return Integer.compare(t1.getDest().number, t2.getDest().number);
        }
        private String tranToStr(Transition t) {
            switch (t.getKind()) {
                case TRANSITION_REALEPSILON:
                case TRANSITION_CAPTURE_OPEN:
                case TRANSITION_CAPTURE_CLOSE:
                    return "";
                case TRANSITION_BACKREF:
                    return capture[t.getGroup()];
                case TRANSITION_CHAR:
                default:
                    return String.valueOf(t.getMin());
            }
        }
    }

    public static String[] getAutomatonCaptureStringLocalMin(
        Automaton auto,
        boolean tryAvoidEps,
        String[] captureP2
    ) {
        IdentityHashMap<Transition, Void> visited = new IdentityHashMap<Transition, Void>();
        ArrayDeque<StateCapture> worklist = new ArrayDeque<StateCapture>();
        String[] captureP1 = new String[captureP2.length];
        captureP1[0] = "";
        worklist.addLast(new StateCapture(
            auto.getInitialState(), captureP1, captureP2
        ));
		String[] resultWithEps = null;
        while (!worklist.isEmpty()) {
            StateCapture stCap = worklist.removeLast();
            if (stCap.state.accept) {
                String[] result = stCap.captureP2.clone();
                result[0] = stCap.captureP1[0];
                if (tryAvoidEps && result[0].isEmpty())
                    resultWithEps = result;
                else
                    return result;
			}
            Transition[] trans = stCap.state.getSortedTransitionArray(false);
            Arrays.sort(trans, new TransitionStringComparator(stCap.captureP2));
            for (int t = trans.length - 1; t >= 0; --t) {
                Transition tran = trans[t];
                if (visited.containsKey(tran))
                    continue;
                visited.put(tran, null);
                // avoid copy for the first one transition
                StateCapture newStCap = t == 0 ? stCap : stCap.deepClone();
                newStCap.state = tran.getDest();
                switch (tran.getKind()) {
                    case TRANSITION_CHAR:
                        for (int g = 0; g < newStCap.captureP1.length; ++g)
                            if (newStCap.captureP1[g] != null)
                                newStCap.captureP1[g] = newStCap.captureP1[g] + tran.getMin();
                        break;
                    case TRANSITION_REALEPSILON:
                        break;
                    case TRANSITION_CAPTURE_OPEN:
                        newStCap.captureP1[tran.getGroup()] = "";
                        break;
                    case TRANSITION_CAPTURE_CLOSE:
                        int group = tran.getGroup();
                        // FIXME
                        // Attack automatons foten have incomplete capture 
                        // groups (close without opening). 
                        // We currently ignore such close transitions.
                        if (newStCap.captureP1[group] == null)
                            break;
                        newStCap.captureP2[group] = newStCap.captureP1[group];
                        newStCap.captureP1[group] = null;
                        break;
                    case TRANSITION_BACKREF:
                        String cap = stCap.captureP2[tran.getGroup()];
                        if (cap == null)
                            continue;
                        for (int g = 0; g < newStCap.captureP1.length; ++g)
                            if (newStCap.captureP1[g] != null)
                                newStCap.captureP1[g] += cap;
                        break;
                    default:
                        break;
                }
                worklist.addLast(newStCap);
            }
        }
        return resultWithEps != null ? resultWithEps : new String[captureP2.length];
    }

    public static String[] getAutomatonCaptureStringLocalMin(
        Automaton auto,
        boolean tryAvoidEps
    ) {
        int maxGroup = auto.getMaxGroup();
        return getAutomatonCaptureStringLocalMin(auto, tryAvoidEps, new String[maxGroup + 1]);
    }

    public static String[] getAutomatonCaptureStringLocalMin(Automaton auto) {
        return getAutomatonCaptureStringLocalMin(auto, false);
    }

    public static String getAutomatonStringLocalMin(
        Automaton auto,
        boolean tryAvoidEps,
        String[] captureP2
    ) {
        return getAutomatonCaptureStringLocalMin(auto, tryAvoidEps, captureP2)[0];
    }

    public static String getAutomatonStringLocalMin(
        Automaton auto,
        boolean tryAvoidEps
    ) {
        return getAutomatonCaptureStringLocalMin(auto, tryAvoidEps)[0];
    }

    public static String getAutomatonStringLocalMin(Automaton auto) {
		return getAutomatonCaptureStringLocalMin(auto)[0];
	}
}
