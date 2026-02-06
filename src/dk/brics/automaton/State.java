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
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/** 
 * <code>Automaton</code> state. 
 * @author Anders M&oslash;ller &lt;<a href="mailto:amoeller@cs.au.dk">amoeller@cs.au.dk</a>&gt;
 */
public class State implements Serializable, Comparable<State> {
	
	static final long serialVersionUID = 30001;
	
	boolean accept;
	Set<Transition> transitions;
	
	int number;
	
	int id;
	static int next_id;
	
	/** 
	 * Constructs a new state. Initially, the new state is a reject state. 
	 */
	public State() {
		resetTransitions();
		id = next_id++;
	}
	
	/** 
	 * Resets transition set. 
	 */
	final void resetTransitions() {
		transitions = new HashSet<Transition>();
	}
	
	/** 
	 * Returns the set of outgoing transitions. 
	 * Subsequent changes are reflected in the automaton.
	 * @return transition set
	 */
	public Set<Transition> getTransitions()	{
		return transitions;
	}
	
	/**
	 * Adds an outgoing transition.
	 * @param t transition
	 */
	public void addTransition(Transition t)	{
		transitions.add(t);
	}
	
	/** 
	 * Sets acceptance for this state.
	 * @param accept if true, this state is an accept state
	 */
	public void setAccept(boolean accept) {
		this.accept = accept;
	}
	
	/**
	 * Returns acceptance status.
	 * @return true is this is an accept state
	 */
	public boolean isAccept() {
		return accept;
	}
	
	/** 
	 * Performs lookup in transitions, assuming determinism. 
	 * @param c character to look up
	 * @return destination state, null if no matching outgoing transition
	 * @see #step(char, Collection)
	 */
	public State step(char c) {
		for (Transition t : transitions)
			if (t.kind == Transition.Kind.TRANSITION_CHAR && t.min <= c && c <= t.max)
				return t.to;
		return null;
	}

	/** 
	 * Performs lookup in transitions, allowing nondeterminism.
	 * @param c character to look up
	 * @param dest collection where destination states are stored
	 * @see #step(char)
	 */
	public void step(char c, Collection<State> dest) {
		for (Transition t : transitions)
			if (t.kind == Transition.Kind.TRANSITION_CHAR && t.min <= c && c <= t.max)
				dest.add(t.to);
	}
	
	/**
	 * Performs look in epsilon-like transitions.
	 * @param dest collection where destination states are store
	 * @param capture whether capture open and capture close are treated as epsilon
	 */
	public void step(Collection<State> dest, boolean capture) {
		for (Transition t : transitions)
			if (
				t.kind == Transition.Kind.TRANSITION_REALEPSILON ||
				(capture && (
					t.kind == Transition.Kind.TRANSITION_CAPTURE_OPEN ||
					t.kind == Transition.Kind.TRANSITION_CAPTURE_CLOSE
				))
			)
				dest.add(t.to);
	}

	/**
	 * See {@link #step(Collection, boolean)}.
	 * Same as {@code step(dest, false)}.
	 */
	public void step(Collection<State> dest) {
		step(dest, false);
	}

	public void stepOverEpsilon(char c, Collection<State> dest) {
		stepOverEpsilon(c, dest, false, null);
	}

	public void stepOverEpsilon(char c, Collection<State> dest, boolean capture) {
		stepOverEpsilon(c, dest, capture, null);
	}

	public void stepOverEpsilon(char c, Collection<State> dest, boolean capture, Set<State> visited) {
		if (visited == null)
			visited = new HashSet<State>();
		else if (visited.contains(this))
			return;
		ArrayList<State> epsClosure = new ArrayList<State>();
		epsClosure.ensureCapacity(transitions.size() + 1);
		epsClosure.add(this);
		stepOverEpsilon(epsClosure, capture, visited);
		ArrayList<State> charClosure = new ArrayList<State>();
		for (State es : epsClosure) {
			es.step(c, charClosure);
			for (State ts : charClosure) {
				if (!visited.contains(ts)) {
					dest.add(ts);
					ts.stepOverEpsilon(dest, capture, visited);
				}
			} 
			charClosure.clear();
		}
	}

	public void stepOverEpsilon(Collection<State> dest) {
		stepOverEpsilon(dest, true);
	}

	public void stepOverEpsilon(Collection<State> dest, boolean capture) {
		stepOverEpsilon(dest, capture, null);
	}

	public void stepOverEpsilon(Collection<State> dest, boolean capture, Set<State> visited) {
		if (visited == null)
			visited = new HashSet<State>();
		else if (visited.contains(this))
			return;
		ArrayDeque<State> stack = new ArrayDeque<State>();
		visited.add(this);
		stack.addLast(this);
		while (!stack.isEmpty()) {
			State s = stack.removeLast();
			for (Transition t : s.transitions) {
				if ((
					t.kind == Transition.Kind.TRANSITION_REALEPSILON || (
						capture && (
							t.kind == Transition.Kind.TRANSITION_CAPTURE_OPEN ||
							t.kind == Transition.Kind.TRANSITION_CAPTURE_CLOSE
						)
					)
				) && !visited.contains(t.to)) {
					dest.add(t.to);
					visited.add(t.to);
					stack.addLast(t.to);
				}
			}
		}
	}

	public void getEpsilonClosure(Collection<State> dest, boolean capture) {
		dest.add(this);
		stepOverEpsilon(dest, capture); 
	}

	public void getEpsilonClosure(Collection<State> dest) {
		dest.add(this);
		stepOverEpsilon(dest, true);
	}

	// public static class StateTreeIterator implements Iterator<State> {
	// 	private final boolean dfs;
	// 	private Deque<State> deque;
	// 	private State prevState;
	// 	StateTreeIterator(State initState, boolean dfs) {
	// 		this.dfs = dfs;
	// 		deque = dfs ? new ArrayDeque<State>() : new LinkedList<State>();
	// 		prevState = null;
	// 	}
	// }

	void addEpsilon(State to) {
		// TODO: only for experiment
		if (Automaton.epsilon_default_simulate)
			addSimulatedEpsilon(to);
		else
			addRealEpsilon(to);
	}

	void addSimulatedEpsilon(State to) {
		if (to.accept)
			accept = true;
		transitions.addAll(to.transitions);
	}

	void addRealEpsilon(State to) {
		transitions.add(new Transition(to));
	}
	
	/** Returns transitions sorted by (min, reverse max, to) or (to, min, reverse max) */
	Transition[] getSortedTransitionArray(boolean to_first) {
		Transition[] e = transitions.toArray(new Transition[transitions.size()]);
		Arrays.sort(e, new TransitionComparator(to_first));
		return e;
	}
	
	/**
	 * Returns sorted list of outgoing transitions.
	 * @param to_first if true, order by (to, min, reverse max); otherwise (min, reverse max, to)
	 * @return transition list
	 */
	public List<Transition> getSortedTransitions(boolean to_first)	{
		return Arrays.asList(getSortedTransitionArray(to_first));
	}
	
	/** 
	 * Returns string describing this state. Normally invoked via 
	 * {@link Automaton#toString()}. 
	 */
	@Override
	public String toString() {
		StringBuilder b = new StringBuilder();
		b.append("state ").append(number);
		if (accept)
			b.append(" [accept]");
		else
			b.append(" [reject]");
		b.append(":\n");
		for (Transition t : transitions)
			b.append("  ").append(t.toString()).append("\n");
		return b.toString();
	}
	
	/**
	 * Compares this object with the specified object for order.
	 * States are ordered by the time of construction.
	 */
	public int compareTo(State s) {
		return s.id - id;
	}

	/**
	 * See {@link java.lang.Object#equals(java.lang.Object)}.
	 */
	@Override
	public boolean equals(Object obj) {
		return super.equals(obj);
	}

	/**
	 * See {@link java.lang.Object#hashCode()}.
	 */
	@Override
	public int hashCode() {
		return super.hashCode();
	}
}
