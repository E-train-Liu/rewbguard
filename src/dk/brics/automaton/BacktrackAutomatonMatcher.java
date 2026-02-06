package dk.brics.automaton;

import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.regex.MatchResult;

public class BacktrackAutomatonMatcher implements MatchResult {

    private static class IntRange {
        int start;
        int end;
        IntRange(int start, int end) {
            this.start = start;
            this.end = end; 
        }
		@Override
		public boolean equals(Object o) {
			if (o == null || !(o instanceof IntRange))
				return false;
			IntRange that = (IntRange) o;
			return start == that.start && end == that.end;
		}
    }

    private static class BacktrackStatus {
        int index;
        State state;
        IntRange[] captures;
        BacktrackStatus(int index, State state, IntRange[] captures) {
            this.index = index;
            this.state = state;
            this.captures = captures;
        }
		@Override
		public boolean equals(Object o) {
			if (o == null || !(o instanceof BacktrackStatus))
				return false;
			BacktrackStatus that = (BacktrackStatus) o;
			return index == that.index && state.equals(that.state) && Arrays.equals(captures, that.captures);
		}
    }

	static final int MATCH_DEFAULT = 0;
	static final int MATCH_BACKREF_EPSILON = 1 << 0;

	
	private final Automaton automaton;
	private final CharSequence chars;
	private int flags;
    private IntRange[] groups = null;

    BacktrackAutomatonMatcher(CharSequence chars, Automaton automaton, int flags) {
		this.chars = chars;
		this.automaton = automaton;
		this.flags = flags;
	}

	BacktrackAutomatonMatcher(CharSequence chars, Automaton automaton) {
		this(chars, automaton, MATCH_DEFAULT);
	}

	public boolean find(int begin) {
		for (int i = begin; i <= chars.length(); ++i) {
			if (exec(i, false))
				return true;
		}
		return false;
	}

	public boolean find() {
		int begin = getNextBegin();
		if (begin < 0) {
			setFailGroups();
			return false;
		}
		return find(begin);
	}

	public boolean matches() {
		return exec(true);
	}

	public boolean lookingAt() {
		return exec(false);
	}

	// TODO: improve this to avoid being trapped by epsilon loop
	boolean exec(int begin, boolean full) {
		int maxGroup = automaton.getMaxCaptureGroup();
		int charsLength = chars.length();
		ArrayDeque<BacktrackStatus> stack = new ArrayDeque<BacktrackStatus>();
		{
			int index = begin;
			State state = automaton.getInitialState();
			IntRange[] captures = new IntRange[maxGroup + 1];
			stack.addLast(new BacktrackStatus(index, state, captures));
		}
		ArrayList<BacktrackStatus> newStack = new ArrayList<BacktrackStatus>();
		BacktrackStatus acceptStatus = null;
		while (!stack.isEmpty()) {
			BacktrackStatus status = stack.removeLast();
			int index = status.index;
			State state = status.state;
			IntRange[] captures = status.captures;
			// accept
			if (state.isAccept() && (!full || index == charsLength)) {
				acceptStatus = status;
				break;
			}
			// all possible transitions
			for (Transition t : state.transitions) {
				switch (t.kind) {
					case TRANSITION_CHAR:
						if (index < charsLength) {
							char c = chars.charAt(index);
							if (t.min <= c && c <= t.max)
								newStack.add(new BacktrackStatus(index + 1, t.to, captures));
						}
						break;
					case TRANSITION_REALEPSILON:
						newStack.add(new BacktrackStatus(index, t.to, captures));
						break;
					case TRANSITION_CAPTURE_OPEN:
						// copy on write
						IntRange[] newCaptures1 = captures.clone();
						newCaptures1[t.group] = new IntRange(index, -1);
						newStack.add(new BacktrackStatus(index, t.to, newCaptures1));
						break;
					case TRANSITION_CAPTURE_CLOSE:
						IntRange[] newCaptures2 = captures;
						if (captures[t.group] != null && captures[t.group].end == -1) {
							newCaptures2 = captures.clone();
							newCaptures2[t.group].end = index;							
						}
						newStack.add(new BacktrackStatus(index, t.to, newCaptures2));
						break;
					case TRANSITION_BACKREF:
						IntRange capture = captures.length > t.group ? captures[t.group] : null;
						if (capture == null || capture.end < capture.start) {
							if (checkFlag(MATCH_BACKREF_EPSILON))
								newStack.add(new BacktrackStatus(index, t.to, captures));
						} else {
							int captureLength = capture.end - capture.start;
							if (compareSubChars(index, capture.start, captureLength))
								newStack.add(new BacktrackStatus(index + captureLength, state, captures));
						}
						break;
				}
			}
			// Add all new states to the stack (note the order)
			for (int i = newStack.size() - 1; i >= 0; --i)
				stack.addLast(newStack.get(i));
			newStack.clear();
		}
		// process accept or reject
		if (acceptStatus != null) {
			acceptStatus.captures[0] = new IntRange(begin, acceptStatus.index);
			// for (IntRange r : acceptStatus.captures) {
			// 	if (r.end < r.start)
			// 		r.end = charsLength;
			// }
			groups = acceptStatus.captures;
			return true;
		} else {
			if (groups != null && groups.length == maxGroup + 1)
				Arrays.fill(groups, null);
			else
				groups = new IntRange[maxGroup + 1]; // all null
			return false;
		}
    }

	boolean exec(boolean full) {
		int begin = getNextBegin();
		if (begin < 0) {
			setFailGroups();
			return false;
		}
		return exec(begin, full);
	}

	public void reset() {
		groups = null;
	}

	@Override
    public int groupCount() {
        return groups != null ? groups.length - 1 : automaton.getMaxCaptureGroup();
    }

	@Override
	public String group() {
		return group(0);
	}

	@Override 
	public String group(int group) {
		checkGroupAndGoodMatch(group);
		IntRange capture = groups[group];
		if (capture == null)
			return checkFlag(MATCH_BACKREF_EPSILON) ? "" : null;
		return chars.subSequence(capture.start, capture.end).toString();
	}

	@Override
	public int start() {
		return start(0);
	}

	@Override 
	public int start(int group) {
		checkGroupAndGoodMatch(group);
		IntRange capture = groups[group];
		if (capture == null)
			throw new IllegalStateException("Capture group " + group + " not executed in previous matching.");
		return capture.start;
	}

	@Override
	public int end() {
		return end(0);
	}

	@Override 
	public int end(int group) {
		checkGroupAndGoodMatch(group);
		IntRange capture = groups[group];
		if (capture == null)
			throw new IllegalStateException("Capture group " + group + " not executed in previous matching.");
		return capture.end;
	}

	private boolean checkFlag(int flags) {
		return (this.flags & flags) != 0;
	}

	private int getNextBegin() {
		if (groups == null)
			return 0;
		if (groups[0] == null)
			return -1;
		int begin = groups[0].end;
		if (groups[0].end == groups[0].start)
			begin += 1;
		if (begin > chars.length())
			return -1;
		return begin;

	}

	private boolean compareSubChars(int index1, int index2, int length) {
		int charsLength = chars.length();
		if (index1 + length > charsLength || index2 + length > charsLength)
			return false;
		for (int i = 0; i < length; ++i)
			if (chars.charAt(index1 + i) != chars.charAt(index2 + i))
				return false;
		return true;
	}

	private void setFailGroups() {
		// all null
		if (groups == null)
			groups = new IntRange[groupCount() + 1];
		else
			Arrays.fill(groups, null);
	}

	private void checkGroupAndGoodMatch(int group) throws IllegalStateException, IndexOutOfBoundsException {
		if (groups == null)
			throw new IllegalStateException("No matching have been executed.");
		if (groups[0] == null)
			throw new IllegalStateException("Previous matching failed.");
		if (group < 0 || group >= groups.length)
			throw new IndexOutOfBoundsException("Max group number is " + (groups.length - 1) + " groups, index " + group + " out of bound.");
	}
}
