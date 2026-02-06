package dk.brics.automaton;

public class AttackAutomaton {
    public Automaton prefix;
    public Automaton pump;
    public Automaton suffix;
    public Automaton fence;

    AttackAutomaton(Automaton prefix, Automaton pump, Automaton suffix, Automaton fence) {
        this.prefix = prefix;
        this.pump = pump;
        this.suffix = suffix;
        this.fence = fence;
    }
    AttackAutomaton(Automaton prefix, Automaton pump, Automaton suffix) {
        this(prefix, pump, suffix, null);
    }
}