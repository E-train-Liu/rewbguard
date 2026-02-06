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

import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.BitSet;
import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.BiFunction;


/**
 * Basic automata operations.
 */
final public class BasicOperations {
	
	private BasicOperations() {}

	/** 
	 * Returns an automaton that accepts the concatenation of the languages of 
	 * the given automata. 
	 * <p>
	 * Complexity: linear in number of states. 
	 */
	static public Automaton concatenate(Automaton a1, Automaton a2) {
		if (a1.isSingleton() && a2.isSingleton())
			return BasicAutomata.makeString(a1.singleton + a2.singleton);
		if (isSupportAndEmpty(a1) || isSupportAndEmpty(a2))
			return BasicAutomata.makeEmpty();
		boolean deterministic = Automaton.epsilon_default_simulate && a1.isSingleton() && a2.isDeterministic();
		if (a1 == a2) {
			a1 = a1.cloneExpanded();
			a2 = a2.cloneExpanded();
		} else {
			a1 = a1.cloneExpandedIfRequired();
			a2 = a2.cloneExpandedIfRequired();
		}
		if (Automaton.epsilon_default_simulate)
			for (State s : a1.getAcceptStates()) {
				s.accept = false;
				s.addSimulatedEpsilon(a2.initial);
			}
		else
			compactInplaceRealEpsilonConcatenate(a1, a2);
		a1.memory = a1.memory || a2.memory;
		a1.deterministic = !a1.memory && deterministic;
		a1.clearHashCode();
		a1.checkMinimizeAlways();
		return a1;
	}
	
	/**
	 * Returns an automaton that accepts the concatenation of the languages of
	 * the given automata.
	 * <p>
	 * Complexity: linear in total number of states.
	 */
	static public Automaton concatenate(List<Automaton> l) {
		if (l.isEmpty())
			return BasicAutomata.makeEmptyString();
		boolean all_singleton = true;
		for (Automaton a : l)
			if (!a.isSingleton()) {
				all_singleton = false;
				break;
			}
		if (all_singleton) {
			StringBuilder b = new StringBuilder();
			for (Automaton a : l)
				b.append(a.singleton);
			return BasicAutomata.makeString(b.toString());
		} else {
			for (Automaton a : l)
				if (isSupportAndEmpty(a))
					return BasicAutomata.makeEmpty();
			Set<Integer> ids = new HashSet<Integer>();
			for (Automaton a : l)
				ids.add(System.identityHashCode(a));
			boolean has_aliases = ids.size() != l.size();
			Automaton b = null;
			HashSet<State> ss = new HashSet<State>();
			Set<State> ac = null;
			boolean memory = false;
			for (Automaton a : l) {
				if (isSupportAndEmptyString(a))
					continue;
				Automaton aa = a;
				if (has_aliases)
					aa = aa.cloneExpanded();
				else
					aa = aa.cloneExpandedIfRequired();
				Set<State> ms = aa.getStates();
				Set<State> ns = filterAcceptStates(ms);
				if (b == null)
					b = aa;
				else {
					if (Automaton.epsilon_default_simulate)
						for (State s : ac) {
							s.accept = false;
							s.addSimulatedEpsilon(aa.initial);
							if (s.accept)
								ns.add(s);
						}
					else
						compactInplaceRealEpsilonConcatenate(ss, ac, ms, aa.initial);
				}
				ss.addAll(ms);
				ac = ns;
				memory = memory || aa.memory;
			}
			if (b == null)
				return BasicAutomata.makeEmptyString();
			b.deterministic = false;
			b.memory = memory;
			b.clearHashCode();
			b.checkMinimizeAlways();
			return b;
		}
	}


	/**
	 * Make conpact inplace concatenation using real epsilon,
	 * reduce the number of epsilon transitions.
	 */
	private static void compactInplaceRealEpsilonConcatenate(Automaton a1, Automaton a2) {
		Set<State> ss1 = a1.getStates();
		Set<State> fs1 = filterAcceptStates(ss1);
		compactInplaceRealEpsilonConcatenate(ss1, fs1, a2.getStates(), a2.initial);
	}

	/**
	 * Make conpact inplace concatenation using real epsilon,
	 * reduce the number of epsilon transitions.
	 * If the final states of automaton 1 is dropped, it will be removed from
	 * {@code states1}.
	 */
	private static void compactInplaceRealEpsilonConcatenate(
		Set<State> states1, Set<State> finals1,
		Set<State> states2, State initial2
	) {
		if (finals1.size() == 1) {
			State f1 = finals1.iterator().next();
			boolean oneway = f1.transitions.isEmpty();
			if (!oneway) {
				oneway = true;
				for (State s2 : states2)
					for (Transition t2 : s2.transitions)
						if (t2.to == initial2) {
							oneway = false;
							break;
						}
			}
			if (oneway) {
				for (State s1 : states1)
					for (Transition t1 : s1.transitions)
						if (t1.to == f1)
							t1.to = initial2;
				initial2.transitions.addAll(f1.transitions);
				states1.remove(f1);
				// a1.deterministic = a1.deterministic || a2.deterministic;
				// if (a1.deterministic) {
				// 	Transition t1p = null;
				// 	for (Transition t1 : a2.initial.getSortedTransitionArray(false)) {
				// 		if (t1.kind != Transition.Kind.TRANSITION_CHAR)
				// 			break;
				// 		if (t1p != null && t1.min <= t1p.max) {
				// 			a1.deterministic = false;
				// 			break;
				// 		}
				// 		t1p = t1;
				// 	}
				// }
				return;
			}
		}
		for (State f1 : finals1) {
			f1.accept = false;
			f1.addRealEpsilon(initial2);
		}
	}

	static Set<State> filterAcceptStates(Set<State> ss) {
		HashSet<State> fs = new HashSet<State>();
		for (State s : ss)
			if (s.accept)
				fs.add(s);
		return fs;
	}

	// static public Automaton concatenate(List<Automaton> l) {
	// 	if (l.isEmpty())
	// 		return BasicAutomata.makeEmptyString();
	// 	boolean all_singleton = true;
	// 	for (Automaton a : l)
	// 		if (!a.isSingleton()) {
	// 			all_singleton = false;
	// 			break;
	// 		}
	// 	if (all_singleton) {
	// 		StringBuilder b = new StringBuilder();
	// 		for (Automaton a : l)
	// 			b.append(a.singleton);
	// 		return BasicAutomata.makeString(b.toString());
	// 	} else {
	// 		for (Automaton a : l) {
	// 			if (isSupportAndEmpty(a))
	// 				return BasicAutomata.makeEmpty();
	// 		}
	// 		Set<Integer> ids = new HashSet<Integer>();
	// 		for (Automaton a : l)
	// 			ids.add(System.identityHashCode(a));
	// 		boolean has_aliases = ids.size() != l.size();
	// 		Automaton b = null;
	// 		Set<State> ac = null;
	// 		boolean memory = false;
	// 		for (Automaton a : l) {
	// 			if (isSupportAndEmptyString(a))
	// 				continue;
	// 			Automaton aa = a;
	// 			if (has_aliases)
	// 				aa = aa.cloneExpanded();
	// 			else
	// 				aa = aa.cloneExpandedIfRequired();
	// 			Set<State> ns = aa.getAcceptStates();
	// 			if (b == null)
	// 				b = aa;
	// 			else {
	// 				boolean compat = ac.size() == 1;
	// 				if (compat) {
	// 					State lastState = null;
	// 					for (Transition t : aa.initial.transitions) {
	// 						if (lastState != null && t.to != lastState) {
	// 							compat = false;
	// 							break;
	// 						}
	// 						lastState = t.to;
	// 					}
	// 				}
	// 				if (compat) {
	// 					State s = ac.iterator().next();
	// 					s.accept = false;
	// 					s.addSimulatedEpsilon(aa.initial);
	// 					if (s.accept)
	// 						ns.add(s);
	// 				} else
	// 					for (State s : ac) {
	// 						s.accept = false;
	// 						s.addEpsilon(aa.initial);
	// 						if (s.accept)
	// 							ns.add(s);
	// 					}
	// 			}
	// 			ac = ns;
	// 			memory = memory || aa.memory;
	// 		}
	// 		if (b == null)
	// 			return BasicAutomata.makeEmptyString();
	// 		b.deterministic = false;
	// 		b.memory = memory;
	// 		b.clearHashCode();
	// 		b.checkMinimizeAlways();
	// 		return b;
	// 	}
	// }

	/**
	 * Returns an automaton that accepts the union of the empty string and the
	 * language of the given automaton.
	 * <p>
	 * Complexity: linear in number of states.
	 */
	static public Automaton optional(Automaton a) {
		a = a.cloneExpandedIfRequired();
		State s = new State();
		s.addEpsilon(a.initial);
		s.accept = true;
		a.initial = s;
		a.deterministic = false;
		a.clearHashCode();
		a.checkMinimizeAlways();
		return a;
	}
	
	/**
	 * Returns an automaton that accepts the Kleene star (zero or more
	 * concatenated repetitions) of the language of the given automaton.
	 * Never modifies the input automaton language.
	 * <p>
	 * Complexity: linear in number of states.
	 */
	static public Automaton repeat(Automaton a) {
		a = a.cloneExpanded();
		State s = new State();
		s.accept = true;
		s.addEpsilon(a.initial);
		for (State p : a.getAcceptStates()) {
			if (p == a.initial)
	 			continue;
			p.addEpsilon(s);
			p.accept = Automaton.epsilon_default_simulate;
		}
		a.initial = s;
		a.deterministic = false;
		a.clearHashCode();
		a.checkMinimizeAlways();
		return a;
	}
	// static public Automaton repeat(Automaton a) {
	// 	a = a.cloneExpanded();
	// 	Set<State> ps = a.getAcceptStates();
	// 	if (ps.isEmpty())
	// 		return Automaton.makeEmpty();
	// 	a.initial.accept = true;
	// 	for (State p : ps) {
	// 		if (p == a.initial)
	// 			continue;
	// 		p.addEpsilon(a.initial);
	// 		p.accept = Automaton.epsilon_default_simulate;
	// 	}
	// 	a.deterministic = false;
	// 	a.clearHashCode();
	// 	a.checkMinimizeAlways();
	// 	return a;
	// }

	/**
	 * Returns an automaton that accepts <code>min</code> or more
	 * concatenated repetitions of the language of the given automaton.
	 * <p>
	 * Complexity: linear in number of states and in <code>min</code>.
	 */
	static public Automaton repeat(Automaton a, int min) {
		if (min == 0)
			return repeat(a);
		if (min == 1) {
			a = a.cloneExpanded();
			State s = new State();
			s.accept = true;
			s.addEpsilon(a.initial);
			for (State p : a.getAcceptStates()) {
				if (p == a.initial)
	 				continue;
				p.addEpsilon(s);
				p.accept = Automaton.epsilon_default_simulate;
			}
			a.deterministic = false;
			a.clearHashCode();
			a.checkMinimizeAlways();
			return a;
		}
		List<Automaton> as = new ArrayList<Automaton>();
		while (min-- > 1)
			as.add(a);
		as.add(repeat(a, 1));
		return concatenate(as);
	}
	// static public Automaton repeat(Automaton a, int min) {
	// 	if (min == 0)
	// 		return repeat(a);
	// 	if (min == 1) {
	// 		a = a.cloneExpanded();
	// 		Set<State> ps = a.getAcceptStates();
	// 		if (ps.isEmpty())
	// 			return Automaton.makeEmpty();
	// 		State s;
	// 		if (ps.size() == 1)
	// 			s = ps.iterator().next();
	// 		else {
	// 			s = new State();
	// 			s.addEpsilon(a.initial);
	// 		}
	// 		s.accept = true;
	// 		for (State p : ps) {
	// 			if (p == a.initial)
	// 				continue;
	// 			p.addEpsilon(s);
	// 			p.accept = Automaton.epsilon_default_simulate;
	// 		}
	// 		a.deterministic = false;
	// 		a.clearHashCode();
	// 		a.checkMinimizeAlways();
	// 		return a;
	// 	}
	// 	ArrayList<Automaton> as = new ArrayList<Automaton>();
	// 	as.ensureCapacity(min + 1);
	// 	while (min-- > 0)
	// 		as.add(a);
	// 	as.add(repeat(a));
	// 	return concatenate(as);
	// }
	
	/**
	 * Returns an automaton that accepts between <code>min</code> and
	 * <code>max</code> (including both) concatenated repetitions of the
	 * language of the given automaton.
	 * <p>
	 * Complexity: linear in number of states and in <code>min</code> and
	 * <code>max</code>.
	 */
	static public Automaton repeat(Automaton a, int min, int max) {
		if (min > max)
			return BasicAutomata.makeEmpty();
		if (min == max && a.isSingleton())
			return BasicAutomata.makeString(a.singleton.repeat(min));
		max -= min;
		a.expandSingleton();
		Automaton b;
		if (min == 0)
			b = BasicAutomata.makeEmptyString();
		else if (min == 1)
			b = a.clone();
		else {
			ArrayList<Automaton> as = new ArrayList<Automaton>();
			as.ensureCapacity(min);
			while (min-- > 0)
				as.add(a);
			b = concatenate(as);
		}
		if (max > 0) {
			Automaton d = a.clone();
			while (--max > 0) {
				Automaton c = a.clone();
				for (State p : c.getAcceptStates())
					p.addEpsilon(d.initial);
				d = c;
			}
			for (State p : b.getAcceptStates())
				p.addEpsilon(d.initial);
			b.deterministic = false;
			b.clearHashCode();
			b.checkMinimizeAlways();
		}
		return b;
	}

	/**
	 * Returns a (deterministic) automaton that accepts the complement of the
	 * language of the given automaton.
	 * <p>
	 * Complexity: linear in number of states (if already deterministic).
	 */
	static public Automaton complement(Automaton a) {
		a = a.cloneExpandedIfRequired();
		a.determinize();
		a.totalize();
		for (State p : a.getStates())
			p.accept = !p.accept;
		a.removeDeadTransitions();
		return a;
	}

	/**
	 * Returns a (deterministic) automaton that accepts the intersection of
	 * the language of <code>a1</code> and the complement of the language of 
	 * <code>a2</code>. As a side-effect, the automata may be determinized, if not
	 * already deterministic.
	 * <p>
	 * Complexity: quadratic in number of states (if already deterministic).
	 */
	static public Automaton minus(Automaton a1, Automaton a2) {
		if (a1 == a2 || isSupportAndEmpty(a1))
			return BasicAutomata.makeEmpty();
		if (isSupportAndEmpty(a2))
			return a1.cloneIfRequired();
		if (a1.isSingleton()) {
			if (a2.run(a1.singleton))
				return BasicAutomata.makeEmpty();
			else
				return a1.cloneIfRequired();
		}
		return intersection(a1, a2.complement());
	}

	/**
	 * Returns an automaton that accepts the intersection of
	 * the languages of the given automata. 
	 * Never modifies the input automata languages.
	 * <p>
	 * Complexity: quadratic in number of states.
	 */
	static public Automaton intersection(Automaton a1, Automaton a2) throws UnsupportedOperationException {
		if (a1.isSingleton()) {
			if (a2.run(a1.singleton))
				return a1.cloneIfRequired();
			else
				return BasicAutomata.makeEmpty();
		}
		if (a2.isSingleton()) {
			if (a1.run(a2.singleton))
				return a2.cloneIfRequired();
			else
				return BasicAutomata.makeEmpty();
		}
		if (a1 == a2)
			return a1.cloneIfRequired();
		Transition[][] transitions1 = Automaton.getSortedTransitions(a1.getStates());
		Transition[][] transitions2 = Automaton.getSortedTransitions(a2.getStates());
		Automaton c = new Automaton();
		LinkedList<StatePair> worklist = new LinkedList<StatePair>();
		HashMap<StatePair, StatePair> newstates = new HashMap<StatePair, StatePair>();
		StatePair p = new StatePair(c.initial, a1.initial, a2.initial);
		worklist.add(p);
		newstates.put(p, p);
		BiFunction<State, State, StatePair> getStatePair = new BiFunction<State, State, StatePair>() {
			@Override
			public StatePair apply(State s1, State s2) {
				StatePair q = new StatePair(s1, s2);
				StatePair r = newstates.get(q);
				if (r == null) {
					q.s = new State();
					worklist.add(q);
					newstates.put(q, q);
					r = q;
				}
				return r;
			}
		};
		while (worklist.size() > 0) {
			p = worklist.removeFirst();
			p.s.accept = p.s1.accept && p.s2.accept;
			Transition[] t1 = transitions1[p.s1.number];
			Transition[] t2 = transitions2[p.s2.number];
			// find the border between char transitions and epsilon transitions
			int e1 = 0;
			for (; e1 < t1.length && t1[e1].kind == Transition.Kind.TRANSITION_CHAR; e1++);
			int e2 = 0;
			for (; e2 < t2.length && t2[e2].kind == Transition.Kind.TRANSITION_CHAR; e2++);
			// deal with char transitions
			for (int n1 = 0, b2 = 0; n1 < e1; n1++) {
				for (; b2 < e2 && t2[b2].max < t1[n1].min; b2++);
				for (int n2 = b2; n2 < e2 && t1[n1].max >= t2[n2].min; n2++)
					if (t2[n2].max >= t1[n1].min) {
						StatePair r = getStatePair.apply(t1[n1].to, t2[n2].to);
						char min = t1[n1].min > t2[n2].min ? t1[n1].min : t2[n2].min;
						char max = t1[n1].max < t2[n2].max ? t1[n1].max : t2[n2].max;
						p.s.transitions.add(new Transition(min, max, r.s));
					}
			}
			// deal with epsilon transitions
			for (int n1 = e1; n1 < t1.length; ++n1) {
				if (t1[n1].kind == Transition.Kind.TRANSITION_BACKREF)
					throw new UnsupportedOperationException("intersection(): currently unsupport autonmaton with backref");
				// if (t1[n1].kind == Transition.Kind.TRANSITION_REALEPSILON ||
				// 	t1[n1].kind == Transition.Kind.TRANSITION_CAPTURE_OPEN ||
				// 	t1[n1].kind == Transition.Kind.TRANSITION_CAPTURE_CLOSE
				// )
				StatePair r = getStatePair.apply(t1[n1].to, p.s2);
				p.s.addRealEpsilon(r.s);
				
			}
			for (int n2 = e2; n2 < t2.length; ++n2) {
				if (t2[n2].kind == Transition.Kind.TRANSITION_BACKREF)
					throw new UnsupportedOperationException("intersection(): currently unsupport autonmaton with backref");
				// if (t2[n2].kind == Transition.Kind.TRANSITION_REALEPSILON ||
				// 	t2[n2].kind == Transition.Kind.TRANSITION_CAPTURE_OPEN ||
				// 	t2[n2].kind == Transition.Kind.TRANSITION_CAPTURE_CLOSE
				// )
				StatePair r = getStatePair.apply(p.s1, t2[n2].to);
				p.s.addRealEpsilon(r.s);
			}
		}
		c.deterministic = a1.deterministic && a2.deterministic;
		c.removeDeadTransitions();
		c.checkMinimizeAlways();
		return c;
	}
		
	/**
	 * Returns true if the language of <code>a1</code> is a subset of the
	 * language of <code>a2</code>. 
	 * <!--As a side-effect, <code>a2</code> is determinized if not already marked as
	 * deterministic.-->
	 * <p>
	 * Complexity: quadratic in number of states.
	 */
	public static boolean subsetOf(Automaton a1, Automaton a2) throws UnsupportedOperationException {
		if (a1 == a2)
			return true;
		if (a1.isSingleton()) {
			if (a2.isSingleton())
				return a1.singleton.equals(a2.singleton);
			return a2.run(a1.singleton);
		} else if (a2.isSingleton())
			return a1.run(a2.singleton);
		if (a1.isActualMemory() || a2.isActualMemory())
			throw new UnsupportedOperationException("subsetOf() currently unsupport automaton with backref");
		if (!a2.isActualDeterministic()) {
			a2 = a2.clone();
			a2.determinize();
		}
		Transition[][] transitions1 = Automaton.getSortedTransitions(a1.getStates());
		Transition[][] transitions2 = Automaton.getSortedTransitions(a2.getStates());
		Set<State> liveStates1 = a1.getLiveStates();		
		LinkedList<StatePair> worklist = new LinkedList<StatePair>();
		HashSet<StatePair> visited = new HashSet<StatePair>();
		StatePair p = new StatePair(a1.initial, a2.initial);
		worklist.add(p);
		visited.add(p);
		while (worklist.size() > 0) {
			p = worklist.removeFirst();
			if (p.s1.accept && !p.s2.accept)
				return false;
			Transition[] t1 = transitions1[p.s1.number];
			Transition[] t2 = transitions2[p.s2.number];
			for (int n1 = 0, b2 = 0; n1 < t1.length; n1++) {
				// transitions to dead states are not considered as transitions
				// that only appears in a1
				if (!liveStates1.contains(t1[n1].to))
					continue;
				// when compared, char trasiiton are less than other kinds of
				// transitions.
				if (t1[n1].kind == Transition.Kind.TRANSITION_REALEPSILON || 
					t1[n1].kind == Transition.Kind.TRANSITION_CAPTURE_OPEN ||
					t1[n1].kind == Transition.Kind.TRANSITION_CAPTURE_CLOSE
				) {
					StatePair q = new StatePair(t1[n1].to, p.s2);
					if (!visited.contains(q)) {
						worklist.add(q);
						visited.add(q);
						continue;
					}
				}
				while (b2 < t2.length && t2[b2].max < t1[n1].min)
					b2++;
				int min1 = t1[n1].min, max1 = t1[n1].max;
				for (int n2 = b2; n2 < t2.length && t1[n1].max >= t2[n2].min; n2++) {
					if (t2[n2].min > min1)
						return false;
					if (t2[n2].max < Character.MAX_VALUE) 
						min1 = t2[n2].max + 1;
					else {
						min1 = Character.MAX_VALUE;
						max1 = Character.MIN_VALUE;
					}
					StatePair q = new StatePair(t1[n1].to, t2[n2].to);
					if (!visited.contains(q)) {
						worklist.add(q);
						visited.add(q);
					}
				}
				if (min1 <= max1)
					return false;
			}		
		}
		return true;
	}
	
	/**
	 * Returns an automaton that accepts the union of the languages of the given automata.
	 * <p>
	 * Complexity: linear in number of states.
	 */
	public static Automaton union(Automaton a1, Automaton a2) {
		if ((a1.isSingleton() && a2.isSingleton() && a1.singleton.equals(a2.singleton)) || a1 == a2)
			return a1.cloneIfRequired();
		a1 = a1.cloneExpandedIfRequired();
		a2 = a2.cloneExpandedIfRequired();
		State s = new State();
		s.addEpsilon(a1.initial);
		s.addEpsilon(a2.initial);
		a1.initial = s;
		a1.deterministic = false;
		a1.memory = a1.memory || a2.memory;
		a1.clearHashCode();
		a1.checkMinimizeAlways();
		return a1;
	}
	
	/**
	 * Returns an automaton that accepts the union of the languages of the given automata.
	 * <p>
	 * Complexity: linear in number of states.
	 */
	public static Automaton union(Collection<Automaton> l) {
		Set<Integer> ids = new HashSet<Integer>();
		for (Automaton a : l)
			ids.add(System.identityHashCode(a));
		boolean has_aliases = ids.size() != l.size();
		boolean memory = false;
		State s = new State();
		for (Automaton b : l) {
			if (isSupportAndEmpty(b))
				continue;
			Automaton bb = b;
			memory = memory || bb.memory;
			if (has_aliases)
				bb = bb.cloneExpanded();
			else
				bb = bb.cloneExpandedIfRequired();
			s.addEpsilon(bb.initial);
		}
		Automaton a = new Automaton();
		a.initial = s;
		a.deterministic = false;
		a.memory = memory;
		a.clearHashCode();
		a.checkMinimizeAlways();
		return a;
	}

	/**
	 * Determinizes the given automaton.
	 * <p>
	 * Complexity: exponential in number of states.
	 */
	public static void determinize(Automaton a) {
		if (a.deterministic || a.isSingleton())
			return;
		Set<State> initialset = new HashSet<State>();
		initialset.add(a.initial);
		determinize(a, initialset);
	}

	/** 
	 * Determinizes the given automaton using the given set of initial states. 
	 */
	static void determinize(Automaton a, Set<State> initialset) {			
		HashSet<State> newInitialSet = new HashSet<State>();
		for (State s : initialset)
			s.getEpsilonClosure(newInitialSet);
		initialset = newInitialSet;
		char[] points = a.getStartPoints();
		// subset construction
		LinkedList<Set<State>> worklist = new LinkedList<Set<State>>();
		Map<Set<State>, State> newstate = new HashMap<Set<State>, State>();
		worklist.add(initialset);
		a.initial = new State();
		newstate.put(initialset, a.initial);
		while (worklist.size() > 0) {
			Set<State> s = worklist.removeFirst();
			State r = newstate.get(s);
			for (State q : s)
				if (q.accept) {
					r.accept = true;
					break;
				}
			for (int n = 0; n < points.length; n++) {
				Set<State> p = new HashSet<State>();
				for (State q : s)
					for (Transition t : q.transitions) {
						if (t.kind == Transition.Kind.TRANSITION_BACKREF)
							throw new UnsupportedOperationException("determinize(): currently unsupport automaton with backref");
						if (t.kind == Transition.Kind.TRANSITION_CHAR && t.min <= points[n] && points[n] <= t.max)
							t.to.getEpsilonClosure(p, true);
					}
				if (!p.isEmpty()) {
                    State q = newstate.get(p);
                    if (q == null) {
                        worklist.add(p);
                        q = new State();
                        newstate.put(p, q);
                    }
                    char min = points[n];
                    char max;
                    if (n + 1 < points.length)
                        max = (char) (points[n + 1] - 1);
                    else
                        max = Character.MAX_VALUE;
                    r.transitions.add(new Transition(min, max, q));
                }
			}
		}
		a.deterministic = true;
		a.memory = false;
		a.removeDeadTransitions();
	}

	// static void determinize(Automaton a, Set<State> initialset) {
	// 	// cannot determinize automaton with backrefe
	// 	if (a.isActualMemory())
	// 		throw new UnsupportedOperationException(
	// 			"determinize() currently unsupport automaton with backref"
	// 		);
	// 	// add states that are in the epsilon closure of initial set
	// 	HashSet<State> initset = new HashSet<State>();
	// 	for (State s : initialset)
	// 		s.getEpsilonClosure(initset, true);
	// 	initialset = initset;
	// 	// // replace all real espilon transitions with simulated epsilon transitions
	// 	// for (State s : a.getStates()) {
	// 	// 	ArrayList<Transition> realEpsTrans = new ArrayList<Transition>();
	// 	// 	for (Transition t : s.transitions) {
	// 	// 		if (
	// 	// 			t.kind == Transition.Kind.TRANSITION_CAPTURE_OPEN ||
	// 	// 			t.kind == Transition.Kind.TRANSITION_CAPTURE_CLOSE ||
	// 	// 			t.kind == Transition.Kind.TRANSITION_BACKREF
	// 	// 		)
	// 	// 			throw new UnsupportedOperationException(
	// 	// 				"currently do not support determinizing automaton with captures or backrefs"
	// 	// 			);
	// 	// 		else if (t.kind == Transition.Kind.TRANSITION_REALEPSILON)
	// 	// 			realEpsTrans.add(t);
	// 	// 	}
	// 	// 	s.transitions.removeAll(realEpsTrans);
	// 	// 	for (Transition t : realEpsTrans)
	// 	// 		s.addSimulatedEpsilon(t.to);
	// 	// }
	// 	char[] points = a.getStartPoints();
	// 	// subset construction
	// 	LinkedList<Set<State>> worklist = new LinkedList<Set<State>>();
	// 	Map<Set<State>, State> newstate = new HashMap<Set<State>, State>();
	// 	worklist.add(initialset);
	// 	a.initial = new State();
	// 	newstate.put(initialset, a.initial);
	// 	while (worklist.size() > 0) {
	// 		Set<State> s = worklist.removeFirst();
	// 		State r = newstate.get(s);
	// 		for (State q : s)
	// 			if (q.accept) {
	// 				r.accept = true;
	// 				break;
	// 			}
	// 		for (int n = 0; n < points.length; n++) {
	// 			Set<State> p = new HashSet<State>();
	// 			for (State q : s)
	// 				for (Transition t : q.transitions)
	// 					if (t.kind == Transition.Kind.TRANSITION_CHAR && t.min <= points[n] && points[n] <= t.max)
	// 						p.add(t.to);
	// 			if (!p.isEmpty()) {
	// 				HashSet<State> pn = new HashSet<State>();
	// 				for (State st : p)
	// 					st.getEpsilonClosure(pn, true);
	// 				p = pn;
    //                 State q = newstate.get(p);
    //                 if (q == null) {
    //                     worklist.add(p);
    //                     q = new State();
    //                     newstate.put(p, q);
    //                 }
    //                 char min = points[n];
    //                 char max;
    //                 if (n + 1 < points.length)
    //                     max = (char) (points[n + 1] - 1);
    //                 else
    //                     max = Character.MAX_VALUE;
    //                 r.transitions.add(new Transition(min, max, q));
    //             }
	// 		}
	// 	}
	// 	a.deterministic = true;
	// 	a.removeDeadTransitions();
	// }
	
	// /**
	//  * Equivalent to {@code simulateAllEpsilons(a, true)}.
	//  * See {@link #simulateAllEpsilons(Automaton, boolean)}.
	//  */
	// public static void simulateAllEpsilons(Automaton a) {
	// 	simulateAllEpsilons(a, true);
	// }

	// /**
	//  * Replace all real epsilon transitions (and capture transitions if 
	//  * {@code capture} is {@code true}) with simulated epsilon transitions.
	//  */
	// public static void simulateAllEpsilons(Automaton a, boolean capture) {
	// 	HashMap<State, Boolean> dealed = new HashMap<State, Boolean>();
	// 	LinkedList<State> workList = new LinkedList<State>();
	// 	ArrayList<Transition> epsilonTransitions = new ArrayList<Transition>();
	// 	workList.addLast(a.initial);
	// 	dealed.put(a.initial, Boolean.FALSE);
	// 	while (!workList.isEmpty()) {
	// 		State s = workList.removeFirst();
	// 		boolean done = true;
	// 		for (Transition t : s .transitions) {
	// 			Boolean td = dealed.get(t.to);
	// 			if (td == null) {
	// 				workList.addLast(t.to);
	// 				dealed.put(t.to, Boolean.FALSE);
	// 			}
	// 			if (t.kind == Transition.Kind.TRANSITION_REALEPSILON || (capture && (
	// 				t.kind == Transition.Kind.TRANSITION_CAPTURE_OPEN ||
	// 				t.kind == Transition.Kind.TRANSITION_CAPTURE_CLOSE
	// 			))) {
	// 				if (td == null || !td.booleanValue())
	// 					done = false;
	// 				else
	// 					epsilonTransitions.add(t);
	// 			}
	// 		}
	// 		for (Transition t : epsilonTransitions) {
	// 			s.transitions.remove(t);
	// 			s.addSimulatedEpsilon(t.to);
	// 		}
	// 		epsilonTransitions.clear();
	// 		if (done)
	// 			dealed.put(s, Boolean.TRUE);
	// 		else
	// 			workList.addLast(s);
	// 	}
	// }

	/**
	 * Surround a automaton with capture group (opening transition and closing
	 * transition).
	 * @param a automaton.
	 * @param group The capture group index.
	 */
	public static Automaton capture(Automaton a, int group) {
		a = a.cloneExpanded();
		State newInit = new State();
		newInit.addTransition(new Transition(Transition.Kind.TRANSITION_CAPTURE_OPEN, group, a.initial));
		a.initial = newInit;
		State beforeAccept = null;
		Set<State> oldAccepts = a.getAcceptStates();
		if (oldAccepts.size() == 1) {
			beforeAccept = oldAccepts.iterator().next();
			beforeAccept.accept = false;
		} else {
			beforeAccept = new State();
			for (State s : oldAccepts) {
				s.accept = false;
				s.addEpsilon(beforeAccept);
			}
		}
		State newAccept = new State();
		newAccept.accept = true;
		beforeAccept.addTransition(new Transition(Transition.Kind.TRANSITION_CAPTURE_CLOSE, group, newAccept));
		a.deterministic = false;
		return a;
	}

	/** 
	 * Adds epsilon transitions to the given automaton.
	 * This method adds extra character interval transitions that are equivalent to the given
	 * set of epsilon transitions. 
	 * @param pairs collection of {@link StatePair} objects representing pairs of source/destination states 
	 *        where epsilon transitions should be added
	 */
	public static void addEpsilons(Automaton a, Collection<StatePair> pairs) {
		a.expandSingleton();
		HashMap<State, HashSet<State>> forward = new HashMap<State, HashSet<State>>();
		HashMap<State, HashSet<State>> back = new HashMap<State, HashSet<State>>();
		for (StatePair p : pairs) {
			HashSet<State> to = forward.get(p.s1);
			if (to == null) {
				to = new HashSet<State>();
				forward.put(p.s1, to);
			}
			to.add(p.s2);
			HashSet<State> from = back.get(p.s2);
			if (from == null) {
				from = new HashSet<State>();
				back.put(p.s2, from);
			}
			from.add(p.s1);
		}
		// calculate epsilon closure
		LinkedList<StatePair> worklist = new LinkedList<StatePair>(pairs);
		HashSet<StatePair> workset = new HashSet<StatePair>(pairs);
		while (!worklist.isEmpty()) {
			StatePair p = worklist.removeFirst();
			workset.remove(p);
			HashSet<State> to = forward.get(p.s2);
			HashSet<State> from = back.get(p.s1);
			if (to != null) {
				for (State s : to) {
					StatePair pp = new StatePair(p.s1, s);
					if (!pairs.contains(pp)) {
						pairs.add(pp);
						forward.get(p.s1).add(s);
						back.get(s).add(p.s1);
						worklist.add(pp);
						workset.add(pp);
						if (from != null) {
							for (State q : from) {
								StatePair qq = new StatePair(q, p.s1);
								if (!workset.contains(qq)) {
									worklist.add(qq);
									workset.add(qq);
								}
							}
						}
					}
				}
			}
		}
		// add transitions
		for (StatePair p : pairs)
			p.s1.addEpsilon(p.s2);
		a.deterministic = false;
		a.clearHashCode();
		a.checkMinimizeAlways();
	}
	
	private static class StateBoolean {
		State s;
		boolean b;
		StateBoolean() {}
		StateBoolean(State s, boolean b) {
			this.s = s;
			this.b = b;
		}
	}

	private static enum ResultBoolean {
		FALSE,
		TRUE,
		ERROR
	}

	/**
	 * Returns true if the given automaton accepts the empty string and nothing else.
	 */
	public static boolean isEmptyString(Automaton a) throws UnsupportedOperationException {
		// if (a.isSingleton())
		// 	return a.singleton.length() == 0;
		// else
		// 	return a.initial.accept && a.initial.transitions.isEmpty();
		if (a.isSingleton())
			return a.singleton.isEmpty();
		if (a.initial.accept && a.initial.transitions.isEmpty())
			return true;
		HashMap<State, Boolean> onlyEpsReach = new HashMap<State, Boolean>();
		ArrayDeque<StateBoolean> worklist = new ArrayDeque<StateBoolean>();
		onlyEpsReach.put(a.initial, Boolean.TRUE);
		worklist.addLast(new StateBoolean(a.initial, true));
		boolean acceptEps = false;
		while (!worklist.isEmpty()) {
			StateBoolean sb = worklist.removeLast();
			if (sb.s.accept) {
				if (sb.b)
					acceptEps = true;
				else
					return false;
			}
			for (Transition t : sb.s.transitions) {
				boolean onlyEps = true;
				switch (t.kind) {
					case TRANSITION_CHAR:
						onlyEps = false;
						break;
					case TRANSITION_BACKREF:
						throw new UnsupportedOperationException("isEmptyString() currently unsupport automaton with backref");
					case TRANSITION_REALEPSILON:
					case TRANSITION_CAPTURE_OPEN:
					case TRANSITION_CAPTURE_CLOSE:
					default:
						onlyEps = sb.b;
				}
				Boolean cachedOnlyEps = onlyEpsReach.get(t.to);
				if (
					cachedOnlyEps == null ||
					(cachedOnlyEps.booleanValue() && !onlyEps)
				) {
					onlyEpsReach.put(t.to, Boolean.valueOf(onlyEps));
					worklist.addLast(new StateBoolean(t.to, onlyEps));
				}
			}
		}
		return acceptEps;
	}

	// /**
	//  * Returns true if the given automaton accepts the empty string and nothing else.
	//  */
	// public static boolean isEmptyString(Automaton a) throws UnsupportedOperationException {
	// 	// if (a.isSingleton())
	// 	// 	return a.singleton.length() == 0;
	// 	// else
	// 	// 	return a.initial.accept && a.initial.transitions.isEmpty();
	// 	if (a.isSingleton())
	// 		return a.singleton.isEmpty();
	// 	if (a.initial.accept && a.initial.transitions.isEmpty())
	// 		return true;
	// 	HashMap<State, Boolean> onlyEpsReach = new HashMap<State, Boolean>();
	// 	ArrayDeque<StateBoolean> worklist = new ArrayDeque<StateBoolean>();
	// 	onlyEpsReach.put(a.initial, Boolean.TRUE);
	// 	worklist.addLast(new StateBoolean(a.initial, true));
	// 	boolean acceptEps = false;
	// 	while (!worklist.isEmpty()) {
	// 		StateBoolean sb = worklist.removeLast();
	// 		if (sb.s.accept) {
	// 			if (sb.b)
	// 				acceptEps = true;
	// 			else
	// 				return false;
	// 		}
	// 		for (Transition t : sb.s.transitions) {
	// 			boolean onlyEps = true;
	// 			switch (t.kind) {
	// 				case TRANSITION_CHAR:
	// 					onlyEps = false;
	// 					break;
	// 				case TRANSITION_BACKREF:
	// 					throw new UnsupportedOperationException("isEmptyString() currently unsupport automaton with backref");
	// 				case TRANSITION_REALEPSILON:
	// 				case TRANSITION_CAPTURE_OPEN:
	// 				case TRANSITION_CAPTURE_CLOSE:
	// 				default:
	// 					onlyEps = sb.b;
	// 			}
	// 			Boolean cachedOnlyEps = onlyEpsReach.get(t.to);
	// 			if (
	// 				cachedOnlyEps == null ||
	// 				(cachedOnlyEps.booleanValue() && !onlyEps)
	// 			) {
	// 				onlyEpsReach.put(t.to, Boolean.valueOf(onlyEps));
	// 				worklist.addLast(new StateBoolean(t.to, onlyEps));
	// 			}
	// 		}
	// 	}
	// 	return acceptEps;
	// }

	private static boolean isSupportAndEmptyString(Automaton a) {
		try {
			return isEmptyString(a);
		} catch (UnsupportedOperationException e) {
			if (!e.getStackTrace()[0].getMethodName().equals("isEmptyString"))
				throw e;
			return false;
		}
	}

	/**
	 * Returns true if the given automaton accepts no strings.
	 */
	public static boolean isEmpty(Automaton a) throws UnsupportedOperationException {
		if (a.isSingleton())
			return false;
		// return !a.initial.accept && a.initial.transitions.isEmpty();
		if (!a.initial.accept && a.initial.transitions.isEmpty())
			return true;
		boolean hasBackref = false;
		HashSet<State> visited = new HashSet<State>();
		ArrayDeque<State> worklist = new ArrayDeque<State>();
		visited.add(a.initial);
		worklist.addLast(a.initial);
		while (!worklist.isEmpty()) {
			State s = worklist.removeLast();
			if (s.accept)
				return false;
			for (Transition t : s.transitions) {
				if (t.kind == Transition.Kind.TRANSITION_BACKREF)
					hasBackref = true;
				else if (!visited.contains(t.to)) {
					visited.add(t.to);
					worklist.add(t.to);
				}
			}
		}
		if (hasBackref)
			throw new UnsupportedOperationException("isEmpty() currently unsupport automaton with backref");
		return true;
	}

	private static boolean isSupportAndEmpty(Automaton a) {
		try {
			return isEmpty(a);
		} catch (UnsupportedOperationException e) {
			if (!e.getStackTrace()[0].getMethodName().equals("isEmpty"))
				throw e;
			return false;
		}
	}
	
	/**
	 * Returns true if the given automaton accepts all strings.
	 */
	public static boolean isTotal(Automaton a) {
		if (a.isSingleton())
			return false;
		if (a.initial.accept && a.initial.transitions.size() == 1) {
			Transition t = a.initial.transitions.iterator().next();
			return t.to == a.initial && t.min == Character.MIN_VALUE && t.max == Character.MAX_VALUE;
		}
		return false;
	}
	
	/**
	 * Returns a shortest accepted/rejected string. 
	 * If more than one shortest string is found, the lexicographically first of the shortest strings is returned.
	 * @param accepted if true, look for accepted strings; otherwise, look for rejected strings
	 * @return the string, null if none found
	 */
	public static String getShortestExample(Automaton a, boolean accepted) {
		if (a.isSingleton()) {
			if (accepted)
				return a.singleton;
			else if (a.singleton.length() > 0)
				return "";
			else
				return "\u0000";

		}
		return getShortestExample(a.getInitialState(), accepted);
	}

	static String getShortestExample(State s, boolean accepted) {
		Map<State,String> path = new HashMap<State,String>();
		LinkedList<State> queue = new LinkedList<State>();
		path.put(s, "");
		queue.add(s);
		String best = null;
		while (!queue.isEmpty()) {
			State q = queue.removeFirst();
			String p = path.get(q);
			if (q.accept == accepted) {
				if (best == null || p.length() < best.length() || (p.length() == best.length() && p.compareTo(best) < 0))
					best = p;
			} else 
				for (Transition t : q.getTransitions()) {
					String tp = path.get(t.to);
					String np = p + t.min;
					if (tp == null || (tp.length() == np.length() && np.compareTo(tp) < 0)) {
						if (tp == null)
							queue.addLast(t.to);
						path.put(t.to, np);
					}
				}
		}
		return best;
	}
	
	/**
	 * Returns true if the given string is accepted by the automaton. 
	 * <p>
	 * Complexity: 
	 * <ul>
	 * 	<li>for memory automaton, exponiential in the length of ths string.</li>
	 * 	<li>for non-memory automaton, linear in the length of the string.</li>
	 * </ul>
	 * <p>
	 * <b>Note:</b> for full performance, use the {@link RunAutomaton} class.
	 */
	public static boolean run(Automaton a, String s) {
		if (a.isSingleton())
			return s.equals(a.singleton);
		if (a.memory)
			return (new BacktrackAutomatonMatcher(s, a)).matches();
		if (a.deterministic) {
			State p = a.initial;
			for (int i = 0; i < s.length(); i++) {
				State q = p.step(s.charAt(i));
				if (q == null)
					return false;
				p = q;
			}
			return p.accept;
		} else {
			Set<State> states = a.getStates();
			Automaton.setStateNumbers(states);
			LinkedList<State> pp = new LinkedList<State>();
			LinkedList<State> pp_other = new LinkedList<State>();
			BitSet bb = new BitSet(states.size());
			BitSet bb_other = new BitSet(states.size());
			pp.add(a.initial);
			ArrayList<State> dest = new ArrayList<State>();
			boolean accept = a.initial.accept;
			for (int i = 0; i < s.length(); i++) {
				char c = s.charAt(i);
				accept = false;
				pp_other.clear();
				bb_other.clear();
				for (State p : pp) {
					dest.clear();
					p.step(c, dest);
					for (State q : dest) {
						if (q.accept)
							accept = true;
						if (!bb_other.get(q.number)) {
							bb_other.set(q.number);
							pp_other.add(q);
						}
					}
				}
				LinkedList<State> tp = pp;
				pp = pp_other;
				pp_other = tp;
				BitSet tb = bb;
				bb = bb_other;
				bb_other = tb;
			}
			return accept;
		}
	}
}
