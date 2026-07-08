package edu.stonybrook.rewbguard;

import java.lang.reflect.UndeclaredThrowableException;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

import dk.brics.automaton.Automaton;
import dk.brics.automaton.BasicAutomata;
import dk.brics.automaton.BasicOperations;
import dk.brics.automaton.State;
import dk.brics.automaton.Transition;

public class SuperlinearDetector {

	/** Policy: find at most one vulnerability */
	public static final int POLICY_ONE = 1 << 0;
	/** 
	 * Policy: when {@link UnsupportedOperationException happens, store the 
	 * exception and continue finding other vulnabilities (instead of returning) 
	 */
	public static final int POLICY_ERROR_DELAY = 1 << 1;
	/**
	 * Policy: if there is {@link UnsupportedOperationException} happens during
	 * detection and no vulnerability is successfully found, throw the error.
	 * Only make effect when {@link #POLICY_ERROR_DELAY} is used.
	 */
	public static final int POLICY_ERROR_EMPTY = 1 << 2;
	/**
	 * Policy: if an {@link InterruptedException} happens during detection, 
	 * instead of throwing it, the function will stop detection and go to the 
	 * return stage, and the {@link Thread#interrupted()} flag will be 
	 * {@code true} after the function exiting. Note that it an
	 * {@UnsupportedOperationException} may still be thrown during the return 
	 * stage when {@link #POLICY_ERROR_EMPTY} is used. If no exception is 
	 * thrown, the function will return all vulnerabilities it detected before
	 * the interruption.
	 */
	public static final int POLICY_INTERRUPT_RETURN = 1 << 3;

	private static class CaptureBackrefs {
		State beforeOpen;
		State afterOpen;
		State beforeClose;
		State afterClose;
		ArrayList<State> beforeBackrefs;
		ArrayList<State> afterBackrefs;

		CaptureBackrefs() {
			beforeBackrefs = new ArrayList<State>();
			afterBackrefs = new ArrayList<State>();
		}
	}

	private static class AutomatonStateMap {
		Automaton auto;
		Map<State, State> stateMap;
		AutomatonStateMap() {}
		AutomatonStateMap(Automaton auto, Map<State, State> stateMap) {
			this.auto = auto;
			this.stateMap = stateMap;
		}
	} 

	public static ArrayList<AttackAutomaton> detectBackrefToOverlapLoop(Automaton auto, int policy)
	throws UnsupportedOperationException, InterruptedException {
		ArrayList<AttackAutomaton> result = new ArrayList<AttackAutomaton>();
		UnsupportedOperationException error = null;
		try {
			CaptureBackrefs[] capBkrefs = captureBackrefInfo(auto);
			for (int group = 1, maxGroup = capBkrefs.length - 1; group <= maxGroup; ++group) {
				pollInterrupt();
				CaptureBackrefs cb = capBkrefs[group];
				if (cb == null || cb.beforeOpen == null || cb.beforeClose == null || cb.beforeBackrefs.isEmpty())
					continue;
				Automaton prefixAuto = pathsFromTo(auto.getInitialState(), cb.beforeOpen, group);
				ArrayList<State> statesInGroup = statesReachable(cb.afterOpen, group);
				ArrayList<Automaton> lRLoopAutos = new ArrayList<Automaton>();
				for (State loopState : statesInGroup) {
					pollInterrupt();
					try {
						Automaton loopAuto = pathsLoop(loopState, group);
						if (isEmptyIt(loopAuto) || isEmptyStringIt(loopAuto))
							continue;
						Automaton leftAuto = pathsFromTo(cb.afterOpen, loopState,  group);
						Automaton lLoopAuto = intersectionIt(leftAuto.repeat(1), loopAuto);
						minimizeIt(lLoopAuto);
						if (isEmptyIt(lLoopAuto))
							continue;
						Automaton rightAuto = pathsFromTo(loopState, cb.beforeClose, group);
						Automaton lRLoopAuto = intersectionIt(rightAuto.repeat(1), lLoopAuto);
						minimizeIt(lRLoopAuto);
						if (isEmptyIt(lRLoopAuto))
							continue;
						lRLoopAutos.add(lRLoopAuto);
					} catch (UnsupportedOperationException err) {
						if ((policy & POLICY_ERROR_DELAY) != 0) {
							error = err;
							continue;
						} else
							throw err;
					}
				}
				if (lRLoopAutos.isEmpty())
					continue;
				Automaton leftRightLoopAuto = unionIt(lRLoopAutos);
				minimizeIt(leftRightLoopAuto);
				for (int b = 0, nbackref = cb.beforeBackrefs.size(); b < nbackref; ++b) {
					pollInterrupt();
					State beforeBackref = cb.beforeBackrefs.get(b);
					State afterBackref = cb.afterBackrefs.get(b);
					try{
						Automaton bridgeAuto = pathsFromTo(cb.afterClose, beforeBackref, group);
						Automaton pumpAuto = intersectionIt(bridgeAuto.repeat(1), leftRightLoopAuto);
						minimizeIt(pumpAuto);
						if (isEmptyIt(pumpAuto))
							continue;
						if (isEmptyStringIt(pumpAuto))
							pumpAuto = leftRightLoopAuto;
						Automaton suffixAuto = pathsToAccept(afterBackref);
						result.add(new AttackAutomaton(1, prefixAuto, pumpAuto, suffixAuto, null));
						if ((policy & POLICY_ONE) != 0)
							return result;
					} catch (UnsupportedOperationException err) {
						if ((policy & POLICY_ERROR_DELAY) != 0)
							error = err;
						else
							throw err;
					}
				}
			}
		} catch (InterruptedException err) {
			if ((policy & POLICY_INTERRUPT_RETURN) != 0)
				Thread.currentThread().interrupt();
			else
				throw err;
		}
		if ((policy & POLICY_ERROR_EMPTY) != 0 && error != null && result.isEmpty())
			throw new UnsupportedOperationException("unsupport detecting this automaton", error);
		return result;
	}

	public static AttackAutomaton detectOneBackrefToOverlapLoop(Automaton auto)
	throws UnsupportedOperationException, InterruptedException {
		ArrayList<AttackAutomaton> l = detectBackrefToOverlapLoop(
			auto, 
			POLICY_ONE | POLICY_ERROR_DELAY | POLICY_ERROR_EMPTY
		);
		return l.isEmpty() ? null : l.get(0);
	}

	public static ArrayList<AttackAutomaton> detectAsManyOneBackrefToOverlapLoop(Automaton auto)
	throws UnsupportedOperationException, InterruptedException {
		return detectBackrefToOverlapLoop(
			auto,
			POLICY_ERROR_DELAY | POLICY_INTERRUPT_RETURN
		);
	}

	public static ArrayList<AttackAutomaton> detectOverlapLoopBeforeBackrefToLoop(Automaton auto, int policy) 
	throws UnsupportedOperationException, InterruptedException {
		ArrayList<AttackAutomaton> result = new ArrayList<AttackAutomaton>();
		UnsupportedOperationException error = null;
		try {
			CaptureBackrefs[] capBkrefs = captureBackrefInfo(auto);
			for (int group = 1, maxGroup = capBkrefs.length - 1; group <= maxGroup; ++group) {
				pollInterrupt();
				CaptureBackrefs cb = capBkrefs[group];
				if (cb == null || cb.beforeClose == null || cb.beforeBackrefs.isEmpty())
					continue;
				Automaton prefixAuto = pathsFromTo(auto.getInitialState(), cb.beforeOpen);
				ArrayList<State> statesInGroup = statesReachable(cb.afterOpen, group);
				ArrayList<Automaton> leftLoopAutos = new ArrayList<Automaton>();
				ArrayList<Automaton> loopAutos = new ArrayList<Automaton>();
				ArrayList<Automaton> rightAutos = new ArrayList<Automaton>();
				for (State loopState : statesInGroup) {
					pollInterrupt();
					try {
						Automaton loopAuto = pathsLoop(loopState, group);
						if (isEmptyIt(loopAuto) || isEmptyStringIt(loopAuto))
							continue;
						Automaton leftAuto = pathsFromTo(cb.afterOpen, loopState, group);
						Automaton leftLoopAuto = intersectionIt(leftAuto.repeat(1), loopAuto);
						minimizeIt(leftLoopAuto);
						if (isEmptyIt(leftLoopAuto))
							continue;
						Automaton rightAuto = pathsFromTo(loopState, cb.beforeClose, group);
						leftLoopAutos.add(leftLoopAuto);
						loopAutos.add(loopAuto);
						rightAutos.add(rightAuto);
					} catch (UnsupportedOperationException err) {
						if ((policy & POLICY_ERROR_DELAY) != 0)
							error = err;
						else
							throw err;
					}
				}

				ArrayList<State> statesAfterClose = statesReachable(cb.afterClose, group);
				ArrayList<Automaton> gapAutos = new ArrayList<Automaton>();
				ArrayList<State> cycleStates = new ArrayList<State>();
				ArrayList<Automaton> cycleAutos = new ArrayList<Automaton>();
				for (State cycleState : statesAfterClose) {
					pollInterrupt();
					try {
						Automaton cycleAuto = pathsLoop(cycleState, group);
						if (isEmptyIt(cycleAuto) || isEmptyStringIt(cycleAuto))
							continue;
						Automaton gapAuto = pathsFromTo(cb.afterClose, cycleState, group);
						gapAutos.add(gapAuto);
						cycleStates.add(cycleState);
						cycleAutos.add(cycleAuto);
					} catch (UnsupportedOperationException err) {
						if ((policy & POLICY_ERROR_DELAY) != 0)
							error = err;
						else
							throw err;
					}
				}

				for (int l = 0, nLoops = loopAutos.size(); l < nLoops; ++l) {
					pollInterrupt();
					Automaton leftLoopAuto = leftLoopAutos.get(l);
					Automaton loopAuto = loopAutos.get(l);
					Automaton rightAuto = rightAutos.get(l);
					for (int c = 0, nCycles = cycleAutos.size(); c < nCycles; ++c) {
						pollInterrupt();
						Automaton gapAuto = gapAutos.get(c);
						State cycleState = cycleStates.get(c);
						Automaton cycleAuto = cycleAutos.get(c);
						Automaton leftLoopCycleAuto = null, fenceAuto = null;
						try {
							leftLoopCycleAuto = intersectionIt(leftLoopAuto, cycleAuto);
							minimizeIt(leftLoopCycleAuto);
							if (isEmptyStringIt(leftLoopCycleAuto))
								continue;
							fenceAuto = rightAuto.concatenate(gapAuto);
							// FIXME
							// Automaton disAuto = intersectionIt(fenceAuto.repeat(1), loopAuto, cycleAuto);
							// if (!isEmptyIt(disAuto))
							// 	continue;
						} catch (UnsupportedOperationException err) {
							if ((policy & POLICY_ERROR_DELAY) != 0) {
								error = err;
								continue;
							} else
								throw err;
						}

						for(int b = 0, nBackref = cb.beforeBackrefs.size(); b < nBackref; ++b) {
							pollInterrupt();
							State beforeBackref = cb.beforeBackrefs.get(b);
							State afterBackref = cb.afterBackrefs.get(b);
							try {
								Automaton bridgeAuto = pathsFromTo(cycleState, beforeBackref, group);
								if (isEmptyIt(bridgeAuto))
									continue;
								Automaton pumpAuto = intersectionIt(bridgeAuto.repeat(1), leftLoopCycleAuto);
								minimizeIt(pumpAuto);
								if (isEmptyIt(pumpAuto))
									continue;
								Automaton suffixAuto = pathsToAccept(afterBackref);
								result.add(new AttackAutomaton(2, prefixAuto, pumpAuto, suffixAuto, fenceAuto));
								if ((policy & POLICY_ONE) != 0)
									return result;
							} catch (UnsupportedOperationException err) {
								if ((policy & POLICY_ERROR_DELAY) != 0)
									error = err;
								else
									throw err;
							}
						}
					}
				}
			}
		} catch (InterruptedException err) {
			if ((policy & POLICY_INTERRUPT_RETURN) != 0)
				Thread.currentThread().interrupt();
			else
				throw err;
		}
		if (error != null && (policy & POLICY_ERROR_EMPTY) != 0 && result.isEmpty())
			throw new UnsupportedOperationException("unsupport detecting this automaton", error);
		return result;
	}

	public static AttackAutomaton detectOneOverlapLoopBeforeBackrefToLoop(Automaton auto)
	throws UnsupportedOperationException, InterruptedException {
		ArrayList<AttackAutomaton> l = detectOverlapLoopBeforeBackrefToLoop(
			auto,
			POLICY_ONE | POLICY_ERROR_DELAY | POLICY_ERROR_EMPTY
		);
		return l.isEmpty() ? null : l.get(0);
	}

	public static ArrayList<AttackAutomaton> detectAsManyOverlapLoopBeforeBackrefToLoop(Automaton auto)
	throws UnsupportedOperationException, InterruptedException {
		return detectOverlapLoopBeforeBackrefToLoop(
			auto,
			POLICY_ERROR_DELAY | POLICY_INTERRUPT_RETURN
		);
	}

	public static ArrayList<AttackAutomaton> detectBackrefToLoopAndOverlapLoop(Automaton auto, int policy)
	throws UnsupportedOperationException, InterruptedException {
		ArrayList<AttackAutomaton> result = new ArrayList<AttackAutomaton>();
		UnsupportedOperationException error = null;
		try{
			CaptureBackrefs[] capBkrefs = captureBackrefInfo(auto);
			for (int group = 1, maxGroup = capBkrefs.length - 1; group <= maxGroup; ++group) {
				pollInterrupt();
				CaptureBackrefs cb = capBkrefs[group];
				if (cb == null || cb.beforeClose == null || cb.beforeBackrefs.isEmpty())
					continue;
				Automaton prefixAuto = pathsFromTo(auto.getInitialState(), cb.beforeOpen);
				ArrayList<State> statesInGroup = statesReachable(cb.afterOpen, group);
				ArrayList<State> loopStates = new ArrayList<State>();
				ArrayList<Automaton> loopAutos = new ArrayList<Automaton>();
				ArrayList<Automaton> leftLoopAutos = new ArrayList<Automaton>();
				ArrayList<State> cycleStates = new ArrayList<State>();
				ArrayList<Automaton> cycleAutos = new ArrayList<Automaton>();
				ArrayList<Automaton> cycleRightAutos = new ArrayList<Automaton>();
				for (State loopState : statesInGroup) {
					pollInterrupt();
					try{
						Automaton loopAuto = pathsLoop(loopState, group);
						if (isEmptyIt(loopAuto) || isEmptyStringIt(loopAuto))
							continue;
						Automaton leftAuto = pathsFromTo(cb.afterOpen, loopState, group);
						Automaton leftLoopAuto = intersectionIt(leftAuto.repeat(1), loopAuto);
						minimizeIt(leftLoopAuto);
						if (!isEmptyIt(leftLoopAuto)) {
							loopStates.add(loopState);
							loopAutos.add(loopAuto);
							leftLoopAutos.add(leftLoopAuto);	
						}
						Automaton rightAuto = pathsFromTo(loopState, cb.beforeClose, group);
						Automaton cycleRightAuto = intersectionIt(rightAuto.repeat(1), loopAuto);
						minimizeIt(cycleRightAuto);
						if (!isEmptyIt(cycleRightAuto)) {
							cycleStates.add(loopState);
							cycleAutos.add(loopAuto);
							cycleRightAutos.add(cycleRightAuto);
						}
					} catch (UnsupportedOperationException err) {
						if ((policy & POLICY_ERROR_DELAY) != 0)
							error = err;
						else
							throw err;
					}
				}
				for (int l = 0, nLoops = loopAutos.size(); l < nLoops; ++l) {
					pollInterrupt();
					State loopState = loopStates.get(l);
					Automaton loopAuto = loopAutos.get(l);
					Automaton leftLoopAuto = leftLoopAutos.get(l);

					for (int c = 0, nCycles = cycleAutos.size(); c < nCycles; ++c) {
						pollInterrupt();
						State cycleState = cycleStates.get(c);
						if (loopState == cycleState)
							continue;
						Automaton cycleAuto = cycleAutos.get(c);
						Automaton cycleRightAuto = cycleRightAutos.get(c);

						Automaton fenceAuto = null, leftLoopCycleRightAuto = null;
						try {
							fenceAuto = pathsFromTo(loopState, cycleState, group);
							if (isEmptyIt(fenceAuto))
								continue;
							leftLoopCycleRightAuto = intersectionIt(leftLoopAuto, cycleRightAuto);
							minimizeIt(leftLoopCycleRightAuto);
							if (isEmptyStringIt(leftLoopCycleRightAuto) || isEmptyIt(leftLoopCycleRightAuto))
								continue;
							Automaton disAuto = intersectionIt(fenceAuto.repeat(1), loopAuto, cycleAuto);
							if (!isEmptyIt(disAuto))
								continue;
						} catch (UnsupportedOperationException err) {
							if ((policy & POLICY_ERROR_DELAY) != 0) {
								error = err;
								continue;
							} else
								throw err;
						}
						for (int b = 0, nBackrefs = cb.beforeBackrefs.size(); b < nBackrefs; ++b) {
							pollInterrupt();
							State beforeBackref = cb.beforeBackrefs.get(b);
							State afterBackref = cb.afterBackrefs.get(b);
							try {
								Automaton bridgeAuto = pathsFromTo(cb.afterClose, beforeBackref, group);
								Automaton pumpAuto = intersectionIt(bridgeAuto.repeat(1), leftLoopCycleRightAuto);
								minimizeIt(pumpAuto);
								if (isEmptyIt(pumpAuto))
									continue;
								if (isEmptyStringIt(pumpAuto))
									pumpAuto = leftLoopCycleRightAuto;
								Automaton suffixAuto = pathsToAccept(afterBackref);
								result.add(new AttackAutomaton(3, prefixAuto, pumpAuto, suffixAuto, fenceAuto));
								if ((policy & POLICY_ONE) != 0)
									return result;
							} catch (UnsupportedOperationException err) {
								if ((policy & POLICY_ERROR_DELAY) != 0)
									error = err;
								else
									throw err;
							}
						}
					}
				}
			}
		} catch (InterruptedException err) {
			if ((policy & POLICY_INTERRUPT_RETURN) != 0)
				Thread.currentThread().interrupt();
			else
				throw err;
		}
		if (error != null && (policy & POLICY_ERROR_EMPTY) != 0 && result.isEmpty())
			throw new UnsupportedOperationException("unsupport detecting this automaton", error);
		return result;
	}

	public static AttackAutomaton detectOneBackrefToLoopAndOverlapLoop(Automaton auto)
	throws UnsupportedOperationException, InterruptedException {
		ArrayList<AttackAutomaton> l = detectBackrefToLoopAndOverlapLoop(
			auto, 
			POLICY_ONE | POLICY_ERROR_DELAY | POLICY_ERROR_EMPTY
		);
		return l.isEmpty() ? null : l.get(0);
	}

	public static ArrayList<AttackAutomaton> detectAsMuchBackrefToLoopAndOverlapLoop(Automaton auto)
	throws UnsupportedOperationException, InterruptedException {
		return detectBackrefToLoopAndOverlapLoop(
			auto, 
			POLICY_ERROR_DELAY | POLICY_INTERRUPT_RETURN
		);
	}

	public static ArrayList<AttackAutomaton> detectSuperlinearBackref(Automaton auto, int policy)
	throws UnsupportedOperationException, InterruptedException {
		ArrayList<AttackAutomaton> result = null;
		UnsupportedOperationException error = null;
		for (int i = 1; i <= 3; ++i) {
			try {
				ArrayList<AttackAutomaton> res = 
					i == 1 ? detectBackrefToOverlapLoop(auto, policy) :
					i == 2 ? detectOverlapLoopBeforeBackrefToLoop(auto, policy) :
					detectBackrefToLoopAndOverlapLoop(auto, policy);
				if ((policy & POLICY_ONE) != 0 && !res.isEmpty())
					return res;
				if (result == null || result.isEmpty())
					result = res;
				else
					result.addAll(res);
				pollInterrupt();
			} catch (UnsupportedOperationException err) {
				if ((policy & POLICY_ERROR_DELAY) != 0)
					error = err;
				else
					throw err;
			} catch (InterruptedException err) {
				if ((policy & POLICY_INTERRUPT_RETURN) != 0) {
					Thread.currentThread().interrupt();
					break;
				} else
					throw err;
			}
		}
		if (error != null && (policy & POLICY_ERROR_EMPTY) != 0 && result.isEmpty())
			throw new UnsupportedOperationException("unsupport detecting this automaton", error);
		return result;
	}

	public static AttackAutomaton detectOneSuperlinearBackref(Automaton auto)
	throws UnsupportedOperationException, InterruptedException {
		ArrayList<AttackAutomaton> l = detectSuperlinearBackref(
			auto,
			POLICY_ONE | POLICY_ERROR_DELAY | POLICY_ERROR_EMPTY
		);
		return l.isEmpty() ? null : l.get(0);
	}

	public static ArrayList<AttackAutomaton> detectAsManySuperlinearBackref(Automaton auto)
	throws UnsupportedOperationException, InterruptedException {
		return detectSuperlinearBackref(
			auto,
			POLICY_ERROR_DELAY | POLICY_INTERRUPT_RETURN
		);
	}

	// public static ArrayList<AttackAutomaton> detectIDA(Automaton auto, int policy) {
	// 	ArrayList<AttackAutomaton> result = new ArrayList<AttackAutomaton>();
	// 	UnsupportedOperationException error = null;
	// 	ArrayList<State> states = statesReachable(auto.getInitialState());
	// 	ArrayList<State> loopStates = new ArrayList<State>();
	// 	ArrayList<Automaton> loopAutos = new ArrayList<Automaton>();
	// 	for (State state : states) {
	// 		try {
	// 			if (state.getTransitions().size() <= 1)
	// 				continue;
	// 			// FIXME
	// 			// System.out.println("states[" + states.indexOf(state) + "]");
	// 			Automaton loopAuto = pathsLoop(state);
	// 			loopAuto.minimize();
	// 			if (!loopAuto.isEmpty() && !loopAuto.isEmptyString()) {
	// 				loopStates.add(state);
	// 				loopAutos.add(loopAuto);
	// 			}
	// 		} catch (UnsupportedOperationException err) {
	// 			if ((policy & POLICY_ERROR_DELAY) != 0)
	// 				error = err;
	// 			else
	// 				throw err;
	// 		}
	// 	}
	// 	// FIXME
	// 	// System.out.println("    " + loopStates.size() + " loops");
	// 	int nLoops = loopStates.size();
	// 	for (int l1 = 0; l1 < nLoops; ++l1) {
	// 		State loopState1 = loopStates.get(l1);
	// 		Automaton loopAuto1 = loopAutos.get(l1);
	// 		Automaton prefixAuto = pathsFromTo(auto.getInitialState(), loopState1);
	// 		for (int l2 = 0; l2 < nLoops; ++l2) {
	// 			try {
	// 				if (l1 == l2)
	// 					continue;
	// 				// FIXME
	// 				// System.out.println("(" + l1 + ", " + l2 + ")");
	// 				State loopState2 = loopStates.get(l2);
	// 				Automaton loopAuto2 = loopAutos.get(l2);
	// 				Automaton bridgeAuto = pathsFromTo(loopState1, loopState2);
	// 				if (bridgeAuto.isEmpty())
	// 					continue;
	// 				Automaton pumpAuto = bridgeAuto.repeat(1).intersection(loopAuto1.intersection(loopAuto2));
	// 				if (pumpAuto.isEmpty() || pumpAuto.isEmptyString())
	// 					continue;
	// 				Automaton suffixAuto = pathsToAccept(loopState2);
	// 				result.add(new AttackAutomaton(prefixAuto, pumpAuto, suffixAuto));
	// 				// FIXME
	// 				System.out.println("Loop1\n" + loopAuto1.toDot() + "\nLoop2\n" + loopAuto2.toDot());
	// 				if ((policy & POLICY_ONE) != 0)
	// 					return result;
	// 			} catch (UnsupportedOperationException err) {
	// 				if ((policy & POLICY_ERROR_DELAY) != 0)
	// 					error = err;
	// 				else
	// 					throw err;
	// 			}
	// 		}
	// 	}
	// 	if (error != null && (policy & POLICY_ERROR_EMPTY) != 0 && result.isEmpty())
	// 		throw new UnsupportedOperationException("unsupport detecting this automaton", error);
	// 	return result;
	// }

	// public static ArrayList<AttackAutomaton> detectIDA(Automaton auto, int policy) {
	// 	ArrayList<AttackAutomaton> result = new ArrayList<AttackAutomaton>();
	// 	UnsupportedOperationException error = null;
	// 	ArrayList<State> states = statesReachable(auto.getInitialState());
	// 	ArrayList<State> loopInitStates = new ArrayList<State>();
	// 	ArrayList<Automaton> loopAutos = new ArrayList<Automaton>();
	// 	for (State state : states) {
	// 		try {
	// 			Automaton loopAuto = pathsLoop(state);
	// 			// loopAuto.minimize();
	// 			if (!loopAuto.isEmpty() && !loopAuto.isEmptyString()) {
	// 				loopInitStates.add(state);
	// 				loopAutos.add(loopAuto);
	// 			}
	// 		} catch (UnsupportedOperationException err) {
	// 			if ((policy & POLICY_ERROR_DELAY) != 0)
	// 				error = err;
	// 			else
	// 				throw err;
	// 		}
	// 	}
	// 	int nLoops = loopInitStates.size();
	// 	for (State loop1InitState : loopInitStates) {
	// 		// quick path
	// 		if (loop1InitState.getTransitions().size() <= 1)
	// 			continue;
	// 		Automaton prefixAuto = pathsFromTo(auto.getInitialState(), loop1InitState);
	// 		HashSet<State> tos = new HashSet<State>();
	// 		for (Transition t : loop1InitState.getTransitions())
	// 			tos.add(t.getDest());
	// 		if (tos.size() <= 1)
	// 			continue;
			
	// 		for (State loop1SecondState : tos) {
	// 			Automaton loop1Auto = pathsFromSecondTo(loop1InitState, loop1SecondState, loop1InitState);
	// 			try {
	// 				if (loop1Auto.isEmpty() || loop1Auto.isEmptyString())
	// 					continue;
	// 			} catch (UnsupportedOperationException err) {
	// 				if ((policy & POLICY_ERROR_DELAY) != 0) {
	// 					error = err;
	// 					continue;
	// 				} else
	// 					throw err;
	// 			}
	// 			for (State bridgeSecondState : tos) {
	// 				if (loop1SecondState == bridgeSecondState)
	// 					continue;
	// 				for (int i = 0; i < nLoops; ++i) {
	// 					State loop2InitState = loopInitStates.get(i);
	// 					if (loop1InitState == loop2InitState)
	// 						continue;
	// 					Automaton loop2Auto = loopAutos.get(i);
	// 					Automaton bridgeAuto = pathsFromSecondTo(loop1InitState, bridgeSecondState, loop2InitState);
	// 					try {
	// 						if (bridgeAuto.isEmpty())
	// 							continue;
	// 						Automaton pumpAuto = bridgeAuto.repeat(1).intersection(loop1Auto.intersection(loop2Auto));
	// 						pumpAuto.minimize();
	// 						if (pumpAuto.isEmpty() || pumpAuto.isEmptyString())
	// 							continue;
	// 						Automaton suffixAuto = pathsToAccept(loop2InitState);
	// 						result.add(new AttackAutomaton(prefixAuto, pumpAuto, suffixAuto));
	// 						// FIXME
	// 						System.out.println("Loop 1:\n" + loop1Auto.toDot() + "\nLoop 2:\n" + loop2Auto.toDot() + "\nBridge:\n" + bridgeAuto.toDot());
	// 						if ((policy & POLICY_ONE) != 0)
	// 							return result;
	// 					} catch (UnsupportedOperationException err) {
	// 						if ((policy & POLICY_ERROR_DELAY) != 0)
	// 							error = err;
	// 						else
	// 							throw err;
	// 					}
	// 				}
	// 			}
	// 		}
	// 	}
	// 	if (error != null && (policy & POLICY_ERROR_EMPTY) != 0 && result.isEmpty())
	// 		throw new UnsupportedOperationException("unsupport detecting this automaton", error);
	// 	return result;
	// }

	public static ArrayList<AttackAutomaton> detectPDA(Automaton auto, int policy)
	throws UnsupportedOperationException, InterruptedException {
		ArrayList<AttackAutomaton> result = new ArrayList<AttackAutomaton>();
		UnsupportedOperationException error = null;
		try{
			ArrayList<State> states = statesReachable(auto.getInitialState());
			ArrayList<State> loopInitStates = new ArrayList<State>();
			ArrayList<Set<State>> loopStateSets = new ArrayList<Set<State>>();
			ArrayList<Automaton> loopAutos = new ArrayList<Automaton>();
			for (State state : states) {
				pollInterrupt();
				try {
					AutomatonStateMap loopAutoStateMap = pathsLoopAndStateMap(state);
					// loopAuto.minimize();
					if (!isEmptyIt(loopAutoStateMap.auto) && !isEmptyStringIt(loopAutoStateMap.auto)) {
						loopInitStates.add(state);
						loopStateSets.add(loopAutoStateMap.stateMap.keySet());
						loopAutos.add(loopAutoStateMap.auto);
					}
				} catch (UnsupportedOperationException err) {
					if ((policy & POLICY_ERROR_DELAY) != 0)
						error = err;
					else
						throw err;
				}
			}
			int nLoops = loopInitStates.size();
			for (int l1 = 0; l1 < nLoops; ++l1) {
				pollInterrupt();
				State loop1InitState = loopInitStates.get(l1);
				Set<State> loop1StateSet = loopStateSets.get(l1);
				Automaton loop1Auto = loopAutos.get(l1);
				Automaton prefixAuto = pathsFromTo(auto.getInitialState(), loop1InitState);
				for (int l2 = 0; l2 < nLoops; ++l2) {
					pollInterrupt();
					if (l1 == l2)
						continue;
					State loop2InitState = loopInitStates.get(l2);
					Automaton loop2Auto = loopAutos.get(l2);
					if (loop1StateSet.contains(loop2InitState))
						continue;
					try {
						Automaton bridgeAuto = pathsFromTo(loop1InitState, loop2InitState);
						if (isEmptyIt(bridgeAuto))
							continue;
						Automaton pumpAuto = intersectionIt(loop1Auto, loop2Auto);
						minimizeIt(pumpAuto);
						if (isEmptyStringIt(pumpAuto))
							continue;
						pumpAuto = intersectionIt(pumpAuto, bridgeAuto.repeat(1));
						minimizeIt(pumpAuto);
						if (isEmptyIt(pumpAuto) || isEmptyStringIt(pumpAuto))
							continue;
						Automaton suffixAuto = pathsToAccept(loop2InitState);
						result.add(new AttackAutomaton(0, prefixAuto, pumpAuto, suffixAuto));
						if ((policy & POLICY_ONE) != 0)
							return result;
					} catch (UnsupportedOperationException err) {
						if ((policy & POLICY_ERROR_DELAY) != 0)
							error = err;
						else
							throw err;
					}
				}
			}
		} catch (InterruptedException err) {
			if ((policy & POLICY_INTERRUPT_RETURN) != 0)
				Thread.currentThread().interrupt();
			else
				throw err;
		}
		if (error != null && (policy & POLICY_ERROR_EMPTY) != 0 && result.isEmpty())
			throw new UnsupportedOperationException("unsupport detecting this automaton", error);
		return result;
	}


	public static AttackAutomaton detectOnePDA(Automaton auto)
	throws UnsupportedOperationException, InterruptedException {
		ArrayList<AttackAutomaton> l = detectPDA(
			auto,
			POLICY_ONE | POLICY_ERROR_DELAY | POLICY_ERROR_EMPTY
		);
		return l.isEmpty() ? null : l.get(0);
	}

	public static ArrayList<AttackAutomaton> detectAsManyPDA(Automaton auto)
	throws UnsupportedOperationException, InterruptedException {
		return detectPDA(
			auto,
			POLICY_ERROR_DELAY | POLICY_INTERRUPT_RETURN
		);
	}

	public static ArrayList<AttackAutomaton> detectEDA(Automaton auto, int policy)
	throws UnsupportedOperationException, InterruptedException {
		ArrayList<AttackAutomaton> result = new ArrayList<AttackAutomaton>();
		UnsupportedOperationException error = null;
		try {
			for (State state : auto.getStates()) {
				pollInterrupt();
				// quick path
				if (state.getTransitions().size() < 2)
					continue;
				Automaton loopAuto = pathsLoop(state);
				try {
					if (isEmptyIt(loopAuto) || isEmptyStringIt(loopAuto))
						continue;
				} catch (UnsupportedOperationException err) {
					if ((policy & POLICY_ERROR_DELAY) != 0) {
						error = err;
						continue;
					} else
						throw err;
				}
				State loopInitState = loopAuto.getInitialState();
				int nTrans = loopInitState.getTransitions().size();
				if (nTrans < 2)
					continue;
				Transition[] trans = loopInitState.getTransitions().toArray(new Transition[nTrans]);
				Automaton prefixAuto = pathsFromTo(auto.getInitialState(), state);
				Automaton suffixAuto = pathsToAccept(state);
				HashMap<State, Automaton> partSubLoopAutos = new HashMap<State, Automaton>();
				for (int i1 = 0; i1 < trans.length; ++i1) {
					pollInterrupt();
					Transition tran1 = trans[i1];
					State to1 = tran1.getDest();
					for (int i2 = i1 + 1; i2 < trans.length; ++i2) {
						pollInterrupt();
						Transition tran2 = trans[i2];
						State to2 = tran2.getDest();
						// check if overlap
						if (tran1.getKind() == Transition.Kind.TRANSITION_CHAR
						&& tran2.getKind() == Transition.Kind.TRANSITION_CHAR
						&& (tran1.getMax() < tran2.getMin() || tran2.getMax() < tran1.getMin()))
							continue;
						// quick path
						if (to1 == to2) {
							result.add(new AttackAutomaton(0, prefixAuto, loopAuto, suffixAuto));
							if ((policy & POLICY_ONE) != 0)
								return result;
							continue;
						}
						Automaton partSubLoopAuto1 = partSubLoopAutos.get(to1);
						if (partSubLoopAuto1 == null) {
							partSubLoopAuto1 = pathsFromTo(to1, loopInitState);
							partSubLoopAutos.put(to1, partSubLoopAuto1);
						}
						Automaton subLoopAuto1 = prependTransition(tran1, partSubLoopAuto1);
						Automaton partSubLoopAuto2 = partSubLoopAutos.get(to2);
						if (partSubLoopAuto2 == null) {
							partSubLoopAuto2 = pathsFromTo(to2, loopInitState);
							partSubLoopAutos.put(to2, partSubLoopAuto2);
						}
						Automaton subLoopAuto2 = prependTransition(tran2, partSubLoopAuto2);
						try {
							Automaton pumpAuto = intersectionIt(subLoopAuto1, subLoopAuto2);
							minimizeIt(pumpAuto);
							if (isEmptyIt(pumpAuto) || isEmptyStringIt(pumpAuto))
								continue;
							result.add(new AttackAutomaton(0, prefixAuto, pumpAuto, suffixAuto));
							if ((policy & POLICY_ONE) != 0)
								return result;
						} catch (UnsupportedOperationException err) {
							if ((policy & POLICY_ERROR_DELAY) != 0)
								error = err;
							else
								throw err;
						}
					}
				}
			}
		} catch (InterruptedException err) {
			if ((policy & POLICY_INTERRUPT_RETURN) != 0)
				Thread.currentThread().interrupt();
			else
				throw err;
		}
		if (error != null && (policy & POLICY_ERROR_EMPTY) != 0 && result.isEmpty())
			throw new UnsupportedOperationException("unsupport detecting this automaton", error);
		return result;
	}

	public static AttackAutomaton detectOneEDA(Automaton auto)  throws InterruptedException {
		ArrayList<AttackAutomaton> l = detectEDA(
			auto,
			POLICY_ONE | POLICY_ERROR_DELAY | POLICY_ERROR_EMPTY
		);
		return l.isEmpty() ? null : l.get(0);
	}

	private static Automaton prependTransition(Transition tran, Automaton auto) {
		Automaton res = new Automaton();
		res.getInitialState().addTransition(
			tran.cloneToNewDest(auto.getInitialState())
		);
		res.setDeterministic(auto.isDeterministic());
		res.setMemory(auto.isMemory());
		return res;
	}

	public static ArrayList<AttackAutomaton> detectIDA(Automaton auto, int policy)
	throws UnsupportedOperationException, InterruptedException {
		ArrayList<AttackAutomaton> result = null;
		UnsupportedOperationException error = null;
		for (int i = 0; i <  2; ++i) {
			try {
				ArrayList<AttackAutomaton> res = 
					i == 0 ? detectPDA(auto, policy) : detectEDA(auto, policy);
				if ((policy & POLICY_ONE) != 0 && !res.isEmpty())
					return res;
				if (result == null || result.isEmpty())
					result = res;
				else
					result.addAll(res);
				pollInterrupt();
			} catch (UnsupportedOperationException err) {
				if ((policy & POLICY_ERROR_DELAY) != 0)
					error = err;
				else
					throw err;
			} catch (InterruptedException err) {
				if ((policy & POLICY_INTERRUPT_RETURN) != 0){
					Thread.currentThread().interrupt();
					break;
				} else
					throw err;
			}
		}
		if (error != null && (policy & POLICY_ERROR_EMPTY) != 0 && (result == null || result.isEmpty()))
			throw new UnsupportedOperationException("unsupport detecting this automaton", error);
		return result != null ? result : new ArrayList<AttackAutomaton>();
	}

	public static AttackAutomaton detectOneIDA(Automaton auto)
	throws UnsupportedOperationException, InterruptedException {
		ArrayList<AttackAutomaton> l = detectIDA(
			auto,
			POLICY_ONE | POLICY_ERROR_DELAY | POLICY_ERROR_EMPTY
		);
		return l.isEmpty() ? null : l.get(0);
	}

	public static ArrayList<AttackAutomaton> detectAsManyIDA(Automaton auto)
	throws UnsupportedOperationException, InterruptedException {
		return detectIDA(auto, POLICY_ERROR_DELAY | POLICY_INTERRUPT_RETURN);
	}

	// private static Automaton getCapturePumpAuto(State afterOpen, State beforeClose, int group)
	// throws UnsupportedOperationException {
	// 	HashSet<State> visited = new HashSet<State>();
	// 	visited.add(afterOpen);
	// 	ArrayDeque<State> worklist = new ArrayDeque<>();
	// 	worklist.addLast(afterOpen);
	// 	ArrayList<Automaton> capAutos = new ArrayList<Automaton>();
	// 	while (!worklist.isEmpty()) {
	// 		State state = worklist.removeLast();
	// 		for (Transition tran : state.getTransitions()) {
	// 			State to = tran.getDest();
	// 			if (!(tran.getKind() == Transition.Kind.TRANSITION_CAPTURE_CLOSE
	// 			&& tran.getGroup() == group) && !visited.contains(to)) {
	// 				worklist.add(to);
	// 				visited.add(to);
	// 			}
	// 		}
	// 		Automaton loopAuto = pathsLoop(state, group);
	// 		if (loopAuto.isEmptyString() || loopAuto.isEmpty())
	// 			continue;
	// 		Automaton leftAuto = pathsFromTo(afterOpen, state, group);
	// 		Automaton rightAuto = pathsFromTo(state, beforeClose, group);
	// 		Automaton capAuto = loopAuto;
	// 		if (!leftAuto.isEmptyString())
	// 			capAuto = capAuto.intersection(leftAuto.repeat());
	// 		if (!rightAuto.isEmptyString())
	// 			capAuto = capAuto.intersection(rightAuto.repeat());
	// 		capAuto.minimize();
	// 		if (!capAuto.isEmptyString() && !capAuto.isEmpty())
	// 			capAutos.add(capAuto);
	// 	}
	// 	Automaton captureAuto = Automaton.union(capAutos);
	// 	captureAuto.minimize();
	// 	return captureAuto;
	// }

	static <T> T detectWithTimeout(Callable<T> callable, long timeoutNs) 
	throws TimeoutException, InterruptedException {
		ExecutorService executor = Executors.newSingleThreadExecutor();
		Future<T> future = executor.submit(callable);
		try { 
			return future.get(timeoutNs, TimeUnit.NANOSECONDS); 
		} catch (TimeoutException e) { 
			future.cancel(true); // interrupt if possible
			throw e;
		} catch (ExecutionException e) {
			Throwable eCause = e.getCause();
			if (eCause instanceof Error)
				throw (Error) eCause;
			else if (eCause instanceof RuntimeException)
				throw (RuntimeException) eCause;
			else
				throw new UndeclaredThrowableException(eCause);
		} finally {
			executor.shutdownNow();
		}
	}

	private static CaptureBackrefs[] captureBackrefInfo(Automaton auto) 
	throws InterruptedException {
		int maxGroup = Math.max(auto.getMaxBackrefGroup(), auto.getMaxCaptureGroup());
		CaptureBackrefs[] capBkrefs = new CaptureBackrefs[maxGroup + 1];
		ArrayDeque<State> workList = new ArrayDeque<State>();
		HashSet<State> visited = new HashSet<State>();
		workList.addLast(auto.getInitialState());
		visited.add(auto.getInitialState());
		while (!workList.isEmpty()) {
			pollInterrupt();
			State s = workList.removeLast();
			for (Transition t : s.getTransitions()) {
				pollInterrupt();
				Transition.Kind kind = t.getKind();
				State to = t.getDest();
				if (kind == Transition.Kind.TRANSITION_CAPTURE_OPEN ||
					kind == Transition.Kind.TRANSITION_CAPTURE_CLOSE ||
					kind == Transition.Kind.TRANSITION_BACKREF
				) {
					int group = t.getGroup();
					if (capBkrefs[group] == null)
						capBkrefs[group] = new CaptureBackrefs();
					CaptureBackrefs cb = capBkrefs[group];
					switch (kind) {
						case TRANSITION_CAPTURE_OPEN:
							cb.beforeOpen = s;
							cb.afterOpen = to;
							break;
						case TRANSITION_CAPTURE_CLOSE:
							cb.beforeClose = s;
							cb.afterClose = to;
							break;
						case TRANSITION_BACKREF:
							cb.beforeBackrefs.add(s);
							cb.afterBackrefs.add(to);
							break;
						default:
					}
				}
				if (!visited.contains(to)) {
					workList.add(to);
					visited.add(to);
				}
			}
		}
		return capBkrefs;
	}

	static AutomatonStateMap pathsFromToAndStateMap(State begin, State end, int noCloseGroup)
	throws InterruptedException {
		ArrayDeque<State> workList = new ArrayDeque<State>();
		HashMap<State, HashSet<State>> revTrans = new HashMap<State, HashSet<State>>();
		workList.addLast(begin);
		revTrans.put(begin, new HashSet<State>());
		while (!workList.isEmpty()) {
			pollInterrupt();
			State from = workList.removeLast();
			for (Transition t : from.getTransitions()) {
				pollInterrupt();
				if (t.getKind() == Transition.Kind.TRANSITION_CAPTURE_CLOSE 
				&& t.getGroup() == noCloseGroup)
					continue;
				State to = t.getDest();
				HashSet<State> set = revTrans.get(to);
				if (set == null) {
					set = new HashSet<State>();
					revTrans.put(to, set);
					workList.add(to);
				}
				set.add(from);
			}
		}
		if (!revTrans.containsKey(end))
			return new AutomatonStateMap(BasicAutomata.makeEmpty(), Collections.<State, State>emptyMap());
		HashMap<State, State> oldNewStateMap = new HashMap<State, State>();
		State newEnd = new State(); 
		newEnd.setAccept(true);
		oldNewStateMap.put(end, newEnd);
		workList.addLast(end);
		while (!workList.isEmpty()) {
			pollInterrupt();
			State to = workList.removeLast();
			State newTo = oldNewStateMap.get(to);
			for (State from : revTrans.get(to)) {
				pollInterrupt();
				State newFrom = oldNewStateMap.get(from);
				if (newFrom == null) {
					newFrom = new State();
					oldNewStateMap.put(from, newFrom);
					workList.add(from);
				}
				for (Transition t : from.getTransitions()) {
					pollInterrupt();
					if (t.getDest() != to)
						continue;
					Transition newT = t.cloneToNewDest(newTo);
					newFrom.addTransition(newT);
				}
			}
		}
		Automaton pathAuto = new Automaton();
		State newBegin = oldNewStateMap.get(begin);
		pathAuto.setInitialState(newBegin);
		if (pathAuto.isActualMemory()) {
			pathAuto.setMemory(true);
			pathAuto.setDeterministic(false);
		} else
			pathAuto.setDeterministic(pathAuto.isActualDeterministic());
		return new AutomatonStateMap(pathAuto, oldNewStateMap);
	}

	static AutomatonStateMap pathsFromToAndStateMap(State begin, State end)
	throws InterruptedException {
		return pathsFromToAndStateMap(begin, end, -1);
	}

	static Automaton pathsFromTo(State begin, State end, int noCloseGroup)
	throws InterruptedException {
		return pathsFromToAndStateMap(begin, end, noCloseGroup).auto;
	}

	static Automaton pathsFromTo(State begin, State end)
	throws InterruptedException {
		return pathsFromToAndStateMap(begin, end).auto;
	}

	static AutomatonStateMap pathsLoopAndStateMap(State state, int noCloseGroup)
	throws InterruptedException {
		return pathsFromToAndStateMap(state, state, noCloseGroup);
	}

	static AutomatonStateMap pathsLoopAndStateMap(State state)
	throws InterruptedException {
		return pathsFromToAndStateMap(state, state);
	}

	static Automaton pathsLoop(State state, int noCloseGroup)
	throws InterruptedException {
		return pathsLoopAndStateMap(state, noCloseGroup).auto;
	}

	static Automaton pathsLoop(State state) throws InterruptedException {
		return pathsLoopAndStateMap(state).auto;
	}

	static Automaton pathsToAccept(State state) {
		Automaton auto = new Automaton();
		auto.setInitialState(state);
		if (auto.isActualMemory()) {
			auto.setMemory(true);
			auto.setDeterministic(false);
		} else
			auto.setDeterministic(auto.isActualDeterministic());
		// if (auto.getAllowMutate())
		// 	auto = auto.clone();
		auto = auto.clone();
		return auto;
	}

	// private static Automaton pathsFromSecondTo(State begin, State second, State end) {
	// 	Automaton auto = pathsFromTo(second, end);
	// 	if (auto.isEmpty())
	// 		return Automaton.makeEmpty();
	// 	State newBegin = begin == end ? auto.getAcceptStates().iterator().next() : new State();
	// 	State newSecond = auto.getInitialState();
	// 	for (Transition t : begin.getTransitions()) {
	// 		if (t.getDest() != second)
	// 			continue;
	// 		switch (t.getKind()) {
	// 			case TRANSITION_CHAR:
	// 				for (Transition newOtherT : newBegin.getTransitions())
	// 					if (newOtherT.getKind() == Transition.Kind.TRANSITION_CHAR 
	// 					&& t.getMin() <= newOtherT.getMax() && newOtherT.getMin() <= t.getMax()) {
	// 						auto.setDeterministic(false);
	// 						break;
	// 					}
	// 				break;
	// 			case TRANSITION_BACKREF:
	// 				auto.setMemory(true);
	// 			// case TRANSITION_REALEPSILON:
	// 			// case TRANSITION_CAPTURE_OPEN:
	// 			// case TRANSITION_CAPTURE_CLOSE:
	// 			default:
	// 				auto.setDeterministic(false);
	// 		}
	// 		newBegin.addTransition(t.cloneToNewDest(newSecond));
	// 	}
	// 	auto.setInitialState(newBegin);
	// 	return auto;
	// }

	private static ArrayList<State> statesReachable(State state, int noCloseGroup) 
	throws InterruptedException {
		ArrayDeque<State> workList = new ArrayDeque<State>();
		workList.addLast(state);
		HashSet<State> visited = new HashSet<State>();
		visited.add(state);
		ArrayList<State> result = new ArrayList<State>();
		result.add(state);
		while (!workList.isEmpty()) {
			pollInterrupt();
			State from = workList.removeLast();
			for (Transition t : from.getTransitions()) {
				pollInterrupt();
				State to = t.getDest();
				if (!(t.getKind() == Transition.Kind.TRANSITION_CAPTURE_CLOSE
				&& t.getGroup() == noCloseGroup) && !visited.contains(to)) {
					visited.add(to);
					result.add(to);
					workList.add(to);
				}
			}
		}
		return result;
	}

	private static ArrayList<State> statesReachable(State state)
	throws InterruptedException {
		return statesReachable(state, -1);
	}

	private static Automaton intersectionIt(Automaton a1, Automaton a2)
	throws InterruptedException {
		Automaton r = BasicOperations.intersection(a1, a2);
		pollInterrupt();
		return r;
	}

	private static Automaton intersectionIt(Automaton a1, Automaton a2, Automaton a3)
	throws InterruptedException {
		Automaton r = BasicOperations.intersection(a1, a2);
		pollInterrupt();
		r = BasicOperations.intersection(r, a3);
		pollInterrupt();
		return r;
	}

	private static Automaton unionIt(Collection<Automaton> as) 
	throws InterruptedException {
		Automaton r = Automaton.union(as);
		pollInterrupt();
		return r;
	}

	private static boolean isEmptyIt(Automaton a) throws InterruptedException {
		boolean b = BasicOperations.isEmpty(a);
		pollInterrupt();
		return b;
	}
	
	private static boolean isEmptyStringIt(Automaton a)
	throws InterruptedException {
		boolean b = BasicOperations.isEmptyString(a);
		pollInterrupt();
		return b;
	}

	private static void minimizeIt(Automaton a) throws InterruptedException {
		a.minimize();
		pollInterrupt();
	}

	private static void pollInterrupt() throws InterruptedException {
		if (Thread.interrupted())
			throw new InterruptedException("thread interrupted during detection");
	}
}
