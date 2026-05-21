package dk.brics.automaton;

public class AttackAutomaton {
    int vulnerableType;
    public Automaton prefix;
    public Automaton pump;
    public Automaton suffix;
    public Automaton fence;

    AttackAutomaton(int vulnerableType, Automaton prefix, Automaton pump, Automaton suffix, Automaton fence) {
        this.vulnerableType = vulnerableType;
        this.prefix = prefix;
        this.pump = pump;
        this.suffix = suffix;
        this.fence = fence;
    }
    AttackAutomaton(int vulnerableType, Automaton prefix, Automaton pump, Automaton suffix) {
        this(vulnerableType, prefix, pump, suffix, null);
    }
}