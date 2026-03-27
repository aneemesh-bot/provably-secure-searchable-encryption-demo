"""
client.py

This module implements the Data Owner (Client) logic for the SSE scheme.
It is responsible for:
1. Extracting metadata tokens from raw documents.
2. Encrypting the actual document payloads.
3. Building the CGK+/CK Padded Inverted Index (Array A and Table T).
4. Enforcing IND-CKA2 security by padding all keyword lists to the same 
   maximum length with 'DUMMY_DOC' entries to hide statistical frequencies.
5. Generating secure search trapdoors for queries.
"""

import os
from collections import defaultdict
from crypto_utils import CryptoUtils

class CloudSSEClient:
    def __init__(self):
        # Master key for PRF (token generation)
        self.master_key = os.urandom(32) 
        # Key for encrypting the actual document payloads
        self.doc_key = CryptoUtils.generate_key() 

    def extract_searchable_tokens(self, document: dict) -> list:
        """Converts Key-Value document metadata into flat searchable tokens."""
        tokens = []
        for key, value in document.items():
            if key != "content": 
                tokens.append(f"{key}:{value}".lower())
        return tokens

    def BuildIndex(self, database: dict):
        """
        Implements the CGK+/CK padded inverted index for IND-CKA2 security.
        """
        encrypted_docs = {}
        inverted_index = defaultdict(list)

        # 1. Encrypt docs & extract searchable metadata tokens
        for doc_id, doc_data in database.items():
            encrypted_docs[doc_id] = CryptoUtils.encrypt_data(self.doc_key, doc_data)
            tokens = self.extract_searchable_tokens(doc_data)
            for token in tokens:
                inverted_index[token].append(doc_id)

        # 2. IND-CKA2 Padding: Hide statistical frequencies
        max_len = max((len(docs) for docs in inverted_index.values()), default=0)
        for token in inverted_index:
            while len(inverted_index[token]) < max_len:
                inverted_index[token].append("DUMMY_DOC")

        T = {} # Lookup Table (Entry points)
        A = {} # Node Array (Linked lists)

        # 3. Build the encrypted linked structures
        for token, docs in inverted_index.items():
            search_token = CryptoUtils.prf(self.master_key, token)
            
            next_key = CryptoUtils.generate_key()
            next_addr = os.urandom(16).hex()
            
            # Store the entry pointer in T
            T[search_token] = {"addr": next_addr, "key": next_key.decode('utf-8')}

            for i, doc_id in enumerate(docs):
                current_key = next_key
                current_addr = next_addr
                
                # Setup pointers for the subsequent node
                if i < len(docs) - 1:
                    next_key = CryptoUtils.generate_key()
                    next_addr = os.urandom(16).hex()
                else:
                    next_key = None
                    next_addr = None

                node_payload = {
                    "doc_id": doc_id, 
                    "next_addr": next_addr,
                    "next_key": next_key.decode('utf-8') if next_key else None
                }

                # ENFORCEMENT: Tell Pylance current_key is strictly bytes here
                if current_key is None:
                    raise RuntimeError("Encountered None key during node encryption.")

                # Encrypt and store the node in A
                A[current_addr] = CryptoUtils.encrypt_data(current_key, node_payload)

        return encrypted_docs, T, A

    def GenerateTrapdoor(self, search_query: str) -> str:
        """Creates an oblivious search token for a specific query."""
        return CryptoUtils.prf(self.master_key, search_query.lower())