package dk.brics.automaton;

import java.util.ArrayDeque;
import java.util.Arrays;
import java.util.Comparator;
import java.util.HashSet;

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

    public static String getAutomatonStringLocalMin(Automaton auto, boolean tryAvoidEps) {
        // FIXME
        // System.out.println(auto.toDot());
        HashSet<Integer> visited = new HashSet<Integer>();
        ArrayDeque<StateCapture> worklist = new ArrayDeque<StateCapture>();
        int nGroups = Math.max(auto.getMaxBackrefGroup(), auto.getMaxCaptureGroup());
        StateCapture start = new StateCapture(auto.getInitialState(), nGroups);
        start.captureP1[0] = "";
        worklist.addLast(start);
        // visited.add(auto.getInitialState());
		boolean acceptEps = false;
        while (!worklist.isEmpty()) {
            StateCapture stCap = worklist.removeLast();
            // FIXME
            // System.out.println("getAutomatonStringLocalMin: (" + stCap.state.number + ") " + stCap.captureP1[0]);
            if (stCap.state.accept) {
                if (tryAvoidEps && stCap.captureP1[0].isEmpty())
                    acceptEps = true;
                else
                    return stCap.captureP1[0];
			}
            Transition[] trans = stCap.state.getSortedTransitionArray(false);
            Arrays.sort(trans, new TransitionStringComparator(stCap.captureP2));
            for (int t = trans.length - 1; t >= 0; --t) {
                Transition tran = trans[t];
				int tranObjId = System.identityHashCode(tran); 
				// FIXME
				// System.out.println(tran);
                if (visited.contains(tranObjId))
                    continue;
                visited.add(tranObjId);
                // avoid copy for the first one transition
                StateCapture newStCap = /*t == 0 ? stCap :*/ new StateCapture(null, stCap.captureP1, stCap.captureP2);
                newStCap.state = tran.getDest();
                // copy on write
                switch (tran.getKind()) {
                    case TRANSITION_CHAR:
                        newStCap.captureP1 = stCap.captureP1.clone();
                        for (int g = 0; g < newStCap.captureP1.length; ++g)
                            if (newStCap.captureP1[g] != null)
                                newStCap.captureP1[g] = newStCap.captureP1[g] + tran.getMin();
                        break;
                    case TRANSITION_REALEPSILON:
                        break;
                    case TRANSITION_CAPTURE_OPEN:
                        newStCap.captureP1 = stCap.captureP1.clone();
                        newStCap.captureP1[tran.getGroup()] = "";
                        break;
                    case TRANSITION_CAPTURE_CLOSE:
                        newStCap.captureP1 = stCap.captureP1.clone();
                        newStCap.captureP2 = stCap.captureP2.clone();
                        newStCap.captureP2[tran.getGroup()] = newStCap.captureP1[tran.getGroup()];
                        newStCap.captureP1[tran.getGroup()] = null;
                        break;
                    case TRANSITION_BACKREF:
                        String cap = stCap.captureP2[tran.getGroup()];
                        if (cap == null)
                            continue;
                        newStCap.captureP1 = stCap.captureP1.clone();
                        for (int g = 0; g < newStCap.captureP1.length; ++g)
                            if (newStCap.captureP1[g] != null)
                                newStCap.captureP1[g] += cap;
                        break;
                    default:
                        break;
                }
                worklist.addLast(newStCap);
                // FIXME
                // System.out.println(tran);
                // System.out.println(newStCap.captureP1[0]);
            }
        }
        // FIXME
        // System.out.println(auto.toDot());
        // System.out.println(auto.toDot());
		// throw new UnsupportedOperationException("wtf?");
        return acceptEps ? "" : null;
    }

    public static String getAutomatonStringLocalMin(Automaton auto) {
		return getAutomatonStringLocalMin(auto, false);
	}
}
