"""LLM/AI application testing (Track C).

A conversational probe channel that talks to the target's AI endpoints and
judges responses with a deterministic behavioral contract + consensus oracle
(titan/verify/llm_oracles.py). The oracle is the model's BEHAVIOUR under an
attacker instruction, verified across >= min_agree of N trials — never a byte
diff and never a model-in-the-loop verdict.
"""
