import plotly.graph_objects as go
import pandas as pd

# Data for the comparison
data = [
    {
        "Category": "Key Generation Method",
        "Quantum Approach": "BB84 Quantum Key Distribution Protocol",
        "Classical Approach": "Cryptographically Secure Pseudo-Random Number Generator (CSPRNG)"
    },
    {
        "Category": "Encryption Algorithm", 
        "Quantum Approach": "AES-256 with quantum-generated keys",
        "Classical Approach": "AES-256 with classically-generated keys"
    },
    {
        "Category": "Security Basis",
        "Quantum Approach": "Information-theoretic security (quantum mechanics)",
        "Classical Approach": "Computational security (mathematical complexity)"
    },
    {
        "Category": "Key Distribution",
        "Quantum Approach": "Quantum channel with entanglement",
        "Classical Approach": "RSA-OAEP secure key exchange"
    },
    {
        "Category": "Dependencies",
        "Quantum Approach": "Qiskit, quantum simulators/hardware",
        "Classical Approach": "Standard cryptographic libraries (PyCryptodome, cryptography)"
    },
    {
        "Category": "Implementation Complexity",
        "Quantum Approach": "High - requires quantum circuit design",
        "Classical Approach": "Low - uses proven cryptographic standards"
    },
    {
        "Category": "Hardware Requirements",
        "Quantum Approach": "Quantum computers or simulators",
        "Classical Approach": "Standard computing hardware"
    },
    {
        "Category": "Performance",
        "Quantum Approach": "Slower - quantum simulation overhead",
        "Classical Approach": "Fast - optimized classical algorithms"
    },
    {
        "Category": "Practical Deployment",
        "Quantum Approach": "Limited - quantum hardware not widely available",
        "Classical Approach": "Ready - deployable on existing infrastructure"
    },
    {
        "Category": "Security Level",
        "Quantum Approach": "Theoretically perfect (information-theoretic)",
        "Classical Approach": "Very high (computationally secure with proper key sizes)"
    }
]

# Prepare data with proper abbreviations for 15-character limit
quantum_values = []
classical_values = []

for item in data:
    # Quantum approach abbreviations
    q_text = item["Quantum Approach"]
    if "BB84" in q_text:
        q_abbr = "BB84 QKD Proto"
    elif "AES-256 with quantum" in q_text:
        q_abbr = "AES-256 Q-keys"
    elif "Information-theoretic" in q_text:
        q_abbr = "Info-theoretic"
    elif "Quantum channel" in q_text:
        q_abbr = "Q channel/ent"
    elif "Qiskit" in q_text:
        q_abbr = "Qiskit/Q hw"
    elif "High - requires" in q_text:
        q_abbr = "High complex"
    elif "Quantum computers" in q_text:
        q_abbr = "Q computers"
    elif "Slower" in q_text:
        q_abbr = "Slower (sim)"
    elif "Limited" in q_text:
        q_abbr = "Limited avail"
    elif "Theoretically" in q_text:
        q_abbr = "Perfect secure"
    else:
        q_abbr = q_text[:15]
    
    # Classical approach abbreviations
    c_text = item["Classical Approach"]
    if "CSPRNG" in c_text:
        c_abbr = "CSPRNG"
    elif "AES-256 with classically" in c_text:
        c_abbr = "AES-256 C-keys"
    elif "Computational security" in c_text:
        c_abbr = "Computational"
    elif "RSA-OAEP" in c_text:
        c_abbr = "RSA-OAEP exch"
    elif "Standard cryptographic" in c_text:
        c_abbr = "Std crypto libs"
    elif "Low - uses" in c_text:
        c_abbr = "Low complex"
    elif "Standard computing" in c_text:
        c_abbr = "Std hardware"
    elif "Fast - optimized" in c_text:
        c_abbr = "Fast optimized"
    elif "Ready - deployable" in c_text:
        c_abbr = "Ready deploy"
    elif "Very high" in c_text:
        c_abbr = "Very high sec"
    else:
        c_abbr = c_text[:15]
    
    quantum_values.append(q_abbr)
    classical_values.append(c_abbr)

# Create category names (use exact names from instructions)
categories = [item["Category"] for item in data]

# Create the table with exact column headers as requested
fig = go.Figure(data=[go.Table(
    columnwidth=[1.2, 1.2, 1.2],
    header=dict(
        values=['<b>Category</b>', '<b>Quantum Approach</b>', '<b>Classical Approach</b>'],
        fill_color='#1FB8CD',
        align="center",
        font=dict(color='white', size=14),
        height=45
    ),
    cells=dict(
        values=[categories, quantum_values, classical_values],
        fill_color=[['#f8f9fa']*10, ['#e3f2fd']*10, ['#fff3e0']*10],
        align=["left", "left", "left"],
        font=dict(size=11),
        height=45
    ))
])

fig.update_layout(
    title="Quantum vs Classical Voting Systems"
)

fig.write_image("quantum_classical_comparison.png")