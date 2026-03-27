

---

# SSE Prototype: IND-CKA2 Inverted Index

1. This project implements a secure, sublinear searchable encryption scheme designed for cloud-native Key-Value environments. It ensures that a "Honest-but-Curious" cloud provider can facilitate searches over encrypted data without learning the contents of the documents, the keywords being searched, or the frequency of those keywords. 
2. This `README.md` serves as the technical documentation for the **IND-CKA2 Searchable Symmetric Encryption (SSE)** prototype. This implementation is based on the cryptographic principles of the **CGK+** and **CK** constructions detailed in the provided survey on provably secure searchable encryption.

## 1. Implementation Overview & Adjustments

The prototype implements an **Encrypted Inverted Index** using a linked-list-of-nodes approach. 

### 1.1 Key Cryptographic Techniques:
* **PRFs and PRPs**: We use HMAC-SHA256 to derive deterministic "trapdoors" $f_y(w)$ and memory addresses $\pi_z(w)$, ensuring the server cannot predict where data is stored.
* **Chained Encryption**: Each node in the index is encrypted with a unique key. The key to decrypt node $i+1$ is stored inside the encrypted payload of node $i$.
* **IND-CKA2 Security (Adaptive Padding)**: To protect against adaptive attacks—where an adversary chooses queries based on previous results—we implemented a **Padding Strategy**. Every keyword's result list is padded to a uniform length using dummy identifiers. This hides the "result size" leakage.

### 1.2 Final Refinements:
* **Cloud Mapping**: The implementation was adjusted to handle JSON-like document structures rather than raw text, mapping metadata fields (e.g., `status:active`) to searchable tokens.
* **Type Safety**: We enforced strict `bytes` type-narrowing to resolve Pylance/Static Analysis errors regarding `None` types during the linked-list traversal.

---

## 2. File Functionality

| File | Responsibility |
| :--- | :--- |
| **`crypto_utils.py`** | Contains the mathematical backbone: HMAC-SHA256 for PRF/Trapdoors and Fernet (AES-128-CBC) for node/document encryption. |
| **`client.py`** | The "Data Owner" logic. Handles index building (`BuildIndex`), keyword extraction, and result decryption. It is the only entity that knows the Master Key. |
| **`server.py`** | The "Cloud Provider" logic. It performs the `Search` operation by traversing encrypted pointers. It lacks the keys to see the content. |
| **`main.py`** | The orchestration script. It generates synthetic data and runs the test suite to demonstrate functionality. |
| **`requirements.txt`** | Minimal dependencies list (primarily `cryptography`). |

---

## 3. Testing the Implementation

### 3.1 Instructions

To demonstrate the prototype, follow these steps:

1.  **Environment Setup**:
    ```bash
    python -m venv sse_env
    source sse_env/bin/activate  # Windows: sse_env\Scripts\activate
    pip install -r requirements.txt
    ```

2.  **Run the Test Suite**:
    ```bash
    python main.py
    ```

### 3.2 What to Look For in the Output:
* **Indistinguishable Result Sizes**: Notice that the server always returns the same number of "encrypted node matches" for every query, regardless of whether the keyword exists or how many documents it actually appears in. This confirms the **IND-CKA2 padding** is working.
* **Zero-Knowledge Search**: The server logs will show hexadecimal addresses and encrypted payloads, demonstrating it has no visibility into the plaintext metadata.

---

## 4. Shortcomings & Limitations (From the Paper)

While this implementation meets the high bar of IND-CKA2 security, the survey (Bösch et al.) identifies several inherent challenges:

* **Search/Access Pattern Leakage**: Even with IND-CKA2, the server learns the **Search Pattern** (when the same query is repeated) and the **Access Pattern** (which specific encrypted memory blocks are accessed). Mitigating this usually requires ORAM (Oblivious RAM), which is significantly slower.
* **Static vs. Dynamic**: This prototype is a **static** scheme. Adding or deleting documents in a truly secure way without leaking info usually requires rebuilding portions of the index or utilizing complex "Forward Secure" constructions.
* **The Asymmetric Gap**: The paper notes that while IND-CKA2 is achievable and efficient in this symmetric setting, achieving it in **Public Key Encryption with Keyword Search (PEKS)** remains an open efficiency challenge.

---

### License
This project is licensed under the **MIT License**. See the `LICENSE` file for details.

> **Next Steps**: implementing a **dynamic** update feature (adding/deleting docs); exploring how to mitigate **access pattern leakage** using a simplified ORAM simulation