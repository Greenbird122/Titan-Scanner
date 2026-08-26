# Multi-AI Mutation Loop

An autonomous security scanning system where multiple AI models work together,
each with a specialized role, compounding intelligence across iterations.

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                   MUTATION LOOP                         │
│                                                         │
│  ┌─────────────┐                                        │
│  │  PHASE 0    │  Human sets target + consent           │
│  │  Initialize │  Creates estate.md                     │
│  └──────┬──────┘                                        │
│         │                                               │
│  ┌──────▼──────┐    findings.md    ┌─────────────┐     │
│  │  PHASE 1    │──────────────────▶│  PHASE 2     │     │
│  │  Scanner    │                   │  Mutator     │     │
│  │  (Model A)  │◀──────────────────│  (Model B)   │     │
│  └──────┬──────┘    new probes     └──────┬──────┘     │
│         │                                  │             │
│  ┌──────▼──────────────────────────────────▼──────┐     │
│  │              PHASE 3: Verifier                  │     │
│  │              (Model C)                          │     │
│  │              Tests all new probes               │     │
│  └──────────────────────┬──────────────────────────┘     │
│                         │                               │
│  ┌──────────────────────▼──────────────────────────┐     │
│  │              PHASE 4: Researcher                 │     │
│  │              (Model D + Web Search)              │     │
│  │              If stuck, searches for new vectors  │     │
│  └──────────────────────┬──────────────────────────┘     │
│                         │                               │
│  ┌──────────────────────▼──────────────────────────┐     │
│  │              PHASE 5: Human Gate                 │     │
│  │              Review + Approve + Terminate?       │     │
│  └──────────────────────────────────────────────────┘     │
└─────────────────────────────────────────────────────────┘
```

## File Structure

```
findings/<target>/
├── estate.md           # Target info, scope, known endpoints
├── findings.md         # All confirmed findings
├── mutations.md        # What was tried, what worked, what failed
├── hypotheses.md       # Next things to try
├── iteration.md        # Current iteration number + status
├── log.md              # Full history of every iteration
└── approved/           # Human-approved findings ready for report
```

## Model Roles

| Model | Role | Input | Output |
|-------|------|-------|--------|
| Scanner | Finds vulns | estate.md + hypotheses.md | findings.md |
| Mutator | Creates variants | findings.md + mutations.md | new probes in hypotheses.md |
| Verifier | Tests probes | hypotheses.md + estate.md | updated findings.md |
| Researcher | Finds new vectors | findings.md + web search | new hypotheses.md |

## Termination Conditions

The loop STOPS when ANY of these are true:
1. **No new findings** in last 3 iterations
2. **All hypotheses exhausted** (hypotheses.md is empty)
3. **Budget limit** reached (max iterations or max API calls)
4. **Human says STOP** (approval gate)
5. **Time limit** hit (configurable)

## Usage

```bash
# Start the loop
python titan/brain/mutation_loop/coordinator.py \
  --target https://example.com \
  --consent consent/example.com.json \
  --max-iterations 10 \
  --budget 500
```

## The Iron Clad Rule

**There is always more.** But the system must know when to stop.

The rule means: never assume you've found everything.
The termination conditions mean: don't run forever.

Both coexist. The human decides when "enough" is enough.
