# 🔐 ECDSA Signature Analyzer – Reuse, Low-S, and Linear Dependency Detection

This Python script analyzes a list of **ECDSA signatures** (`r`, `s`, `z`) to detect
potential vulnerabilities related to nonce (`k`) usage.  
It can identify cases of **nonce reuse**, **low-s values**, and **linear dependency** between
nonces — all of which can weaken ECDSA security and potentially reveal the private key.

──────────────────────────────────────────────────────────────
⚙️  OVERVIEW

The script performs a series of cryptographic consistency checks on provided ECDSA signatures.
It uses:
- `defaultdict` for grouping signatures with repeated `r` values
- `sympy` for symbolic equation solving and linear dependency detection
- Standard Python modular arithmetic for cryptographic relationships

──────────────────────────────────────────────────────────────
📚  INCLUDED CHECKS

### 1️⃣ Nonce Reuse Detection (`find_reused_k`)
ECDSA uses a random `k` per signature. If `r` repeats, the same `k` was reused.
The function groups signatures by identical `r` and flags reuse.

```python
def find_reused_k(signatures):
    r_values = defaultdict(list)
    for i, sig in enumerate(signatures):
        r_values[sig["r"]].append(i)
    reused_k = [indices for indices in r_values.values() if len(indices) > 1]
    return reused_k
→ Output: list of indices where the same r (thus same k) appears.

2️⃣ Private Key Recovery from Reused k (recover_private_key)

If two signatures share the same nonce k, the private key d can be computed using:

d = (z1 - z2) * (s1 - s2)^(-1) mod n

def recover_private_key(signatures):
    reused_k_indices = find_reused_k(signatures)
    for indices in reused_k_indices:
        i1, i2 = indices
        z1, z2 = sig1["z"], sig2["z"]
        s1, s2 = sig1["s"], sig2["s"]
        d = ((z1 - z2) * pow(s1 - s2, -1, n)) % n
        return hex(d)


→ If r repeats, this recovers the private key in hex format.

3️⃣ Low-S Detection (detect_low_s)

Checks whether the s component of any signature is less than n/2.
Low s values are technically valid but may indicate normalization or signing issues.

def detect_low_s(signatures):
    low_s = []
    for i, sig in enumerate(signatures):
        if sig["s"] < n // 2:
            low_s.append(i)
    return low_s


→ Output: indices of low-s signatures.

4️⃣ Linear Dependency Detection (detect_linear_k)

Builds a symbolic system of equations using SymPy to identify possible linear relationships
between different k values in the signing process (rare, but useful for research).

def detect_linear_k(signatures):
    equations = []
    k_symbols = symbols(f'k0:{len(signatures)}')
    for i, sig in enumerate(signatures):
        eq = Eq(sig["s"] * k_symbols[i] - sig["z"], 0)
        equations.append(eq)
    solution = solve(equations, k_symbols)
    return solution if solution else None


→ Output: symbolic relationships between k variables, if any exist.

──────────────────────────────────────────────────────────────
🧮 ECDSA PARAMETERS

Curve: secp256k1 (same as Bitcoin)

Order n =
0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

──────────────────────────────────────────────────────────────
🚀 HOW TO USE

Add your ECDSA signatures to the list ecdsa_signatures,
where each entry includes r, s, and z as integers.

Run the script:

python ecdsa_analyzer.py


Example output:

🚀 Checking ECDSA attacks...
⚠️ Reused k found in signatures: [[0, 3]]
🔑 Recovered private key: 0x1a2b3c4d5e6f...
⚠️ Low-S signatures detected: [2, 7, 9]
⚠️ Linear dependency detected among k: [{k0: k1 + 5}]
✅ Analysis complete!


──────────────────────────────────────────────────────────────
📦 DEPENDENCIES

Install requirements via pip:

pip install sympy


──────────────────────────────────────────────────────────────
⚠️ DISCLAIMER

This script is provided for educational and research purposes only.
It is meant to help researchers and developers understand how weak or reused ECDSA nonces
can compromise key security.
Do not use it for unauthorized key recovery, blockchain analysis, or wallet inspection.

──────────────────────────────────────────────────────────────
✅ SUMMARY

A lightweight ECDSA vulnerability scanner that:

Detects reused nonces (r collisions)

Identifies low-s signatures

Finds potential linear dependencies between signing nonces

Can recover a private key if nonce reuse occurs

Intended for research, auditing, and cryptographic education.

BTC donation address: bc1q4nyq7kr4nwq6zw35pg0zl0k9jmdmtmadlfvqhr
