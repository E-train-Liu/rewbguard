/*
 * dk.brics.automaton
 * 
 * Copyright (c) 2001-2017 Anders Moeller
 * All rights reserved.
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 * 
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

package dk.brics.automaton;

import java.io.Serializable;
import java.util.logging.Logger;

/** 
 * <code>Automaton</code> transition. 
 * <p>
 * A transition, which belongs to a source state, consists of a Unicode character interval
 * and a destination state.
 * @author Anders M&oslash;ller &lt;<a href="mailto:amoeller@cs.au.dk">amoeller@cs.au.dk</a>&gt;
 */
public class Transition implements Serializable, Cloneable {
	
	static final long serialVersionUID = 40001;
	
	static final Logger logger = Logger.getLogger(Transition.class.getName());

	public static enum Kind {
		TRANSITION_CHAR,
		TRANSITION_REALEPSILON,
		TRANSITION_CAPTURE_OPEN,
		TRANSITION_CAPTURE_CLOSE,
		TRANSITION_BACKREF
	}

	Kind kind;

	/* 
	 * CLASS INVARIANT: min<=max
	 */

	char min;
	char max;

	int group;
	
	State to;
	
	/** 
	 * Constructs a new singleton char interval transition. 
	 * @param c transition character
	 * @param to destination state
	 */
	public Transition(char c, State to)	{
		this(c, c, to);
	}
	
	/** 
	 * Constructs a new char transition. 
	 * Both end points are included in the interval.
	 * @param min transition interval minimum
	 * @param max transition interval maximum
	 * @param to destination state
	 */
	public Transition(char min, char max, State to)	{
		kind = Kind.TRANSITION_CHAR;
		if (max < min) {
			char t = max;
			max = min;
			min = t;
		}
		this.min = min;
		this.max = max;
		this.to = to;
	}

	/**
	 * Construct a new real epsilon transition.
	 * @param to destination state
	 */
	public Transition(State to) {
		kind = Kind.TRANSITION_REALEPSILON;
		this.to = to;
	}

	/**
	 * Construct a new capture open, capture close, or backreference transition.
	 * @param kind transition kind, only can be 
	 * 		  		{@link Kind#TRANSITION_CAPTURE_OPEN}, 
	 * 		  		{@link Kind#TRANSITION_CAPTURE_CLOSE},
	 * 		  		{@link Kind#TRANSITION_BACKREF}.
	 * @param group group number of capture or backreference
	 * @param to destination state
	 */
	public Transition(Kind kind, int group, State to) {
		this.kind = kind;
		this.group = group;
		this.to = to;
		if (kind != Kind.TRANSITION_CAPTURE_OPEN 
			&& kind != Kind.TRANSITION_CAPTURE_CLOSE
			&& kind != Kind.TRANSITION_BACKREF
		)
			logger.warning("When kind = " + kind.name() + ", group should be unset.");
	}
	
	/** Returns minimum of this char transition interval. */
	public char getMin() {
		if (kind != Kind.TRANSITION_CHAR)
			logger.warning("When kind = " + kind.name() + ", min should unset.");
		return min;
	}
	
	/** Returns maximum of this char transition interval. */
	public char getMax() {
		if (kind != Kind.TRANSITION_CHAR)
			logger.warning("When kind = " + kind.name() + ", max should unset.");
		return max;
	}
	
	/** Returns destination of this transition. */
	public State getDest() {
		return to;
	}

	/** Return the kind of transition, */
	public Kind getKind() {
		return kind;
	}

	/** Returns the group number of capture-open, capture-close or backreference transition. */
	public int getGroup() {
		if (kind != Kind.TRANSITION_CAPTURE_OPEN 
			&& kind != Kind.TRANSITION_CAPTURE_CLOSE
			&& kind != Kind.TRANSITION_BACKREF
		)
			logger.warning("When kind = " + kind.name() + ", group should be unset.");
		return group;
	}
	
	/** 
	 * Checks for equality.
	 * @param obj object to compare with
	 * @return true if <code>obj</code> is a transition with same 
	 *         character interval and destination state as this transition.
	 */
	@Override
	public boolean equals(Object obj) {
		if (!(obj instanceof Transition))
			return false;
		Transition t = (Transition)obj;
		if (t.kind != kind)
			return false;
		switch (kind) {
			case TRANSITION_REALEPSILON:
				return t.to == to;
			case TRANSITION_CAPTURE_OPEN:
			case TRANSITION_CAPTURE_CLOSE:
			case TRANSITION_BACKREF:
				return t.group == group && t.to == to;
			case TRANSITION_CHAR:
			default:
				return t.min == min && t.max == max && t.to == to;
		}
	}
	
	/** 
	 * Returns hash code.
	 * The hash code is based on the character interval (not the destination state).
	 * @return hash code
	 */
	@Override
	public int hashCode() {
		switch (kind) {
			case TRANSITION_BACKREF:
			case TRANSITION_CAPTURE_CLOSE:
			case TRANSITION_CAPTURE_OPEN:
				int k = kind == Kind.TRANSITION_BACKREF ? 4 : 
					(kind == Kind.TRANSITION_CAPTURE_CLOSE ? 3 : 2);
				return group & ((1 << 28) - 1) | (k << 28);
			case TRANSITION_REALEPSILON:
				return System.identityHashCode(to) & ((1 << 28) - 1) | (1 << 28);
			case TRANSITION_CHAR:
			default:
				return min * 2 + max * 3;
		}
	}
	
	/** 
	 * Clones this transition. 
	 * @return clone with same character interval and destination state
	 */
	@Override
	public Transition clone() {
		try {
			return (Transition)super.clone();
		} catch (CloneNotSupportedException e) {
			throw new RuntimeException(e);
		}
	}

	/**
	 * Clone this transition, and set the destination of the new transition.
	 * @param to the new destination
	 * @return copy of this to the new destination
	 */
	public Transition cloneToNewDest(State to) {
		Transition newT = clone();
		newT.to = to;
		return newT;
	}

	static void appendCharString(char c, StringBuilder b, boolean dot) {
		if (c >= 0x21 && c <= 0x7e && c != '\\' && c != '"')
			b.append(c);
		else if (c == '\\')
			b.append(dot ? "\\\\\\\\" : "\\\\");
		else if (c == '"')
			b.append("\\\"");
		else {
			b.append(dot ? "\\\\u" : "\\u");
			String s = Integer.toHexString(c);
			if (c < 0x10)
				b.append("000").append(s);
			else if (c < 0x100)
				b.append("00").append(s);
			else if (c < 0x1000)
				b.append("0").append(s);
			else
				b.append(s);
		}
	}

	static void appendCharString(char c, StringBuilder b) {
		appendCharString(c, b, false);
	}
	
	/** 
	 * Returns a string describing this state. Normally invoked via 
	 * {@link Automaton#toString()}. 
	 */
	@Override
	public String toString() {
		StringBuilder b = new StringBuilder();
		appendRepr(b, false);
		b.append(" -> ").append(to.number);
		return b.toString();
	}

	void appendDot(StringBuilder b) {
		b.append(" -> ").append(to.number).append(" [label=\"");
		appendRepr(b, true);
		b.append('"');
		if (kind != Kind.TRANSITION_CHAR)
		 	b.append(",fontcolor=\"gray\"");
		b.append("]\n");
	}

	private void appendRepr(StringBuilder b, boolean dot) {
		switch (kind) {
			case TRANSITION_BACKREF:
				b.append(dot ? "\\\\" : "\\").append(group);
				break;
			case TRANSITION_CAPTURE_CLOSE:
				b.append(')').append(group);
				break;
			case TRANSITION_CAPTURE_OPEN:
				b.append('(').append(group);
				break;
			case TRANSITION_REALEPSILON:
				b.append('ϵ');
				break;
			case TRANSITION_CHAR:
			default:
				appendCharString(min, b, dot);
				if (min != max) {
					b.append("-");
					appendCharString(max, b, dot);
				}
		}
	}
}
