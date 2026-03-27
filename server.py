"""
server.py

This module simulates the Honest-but-Curious Cloud Server.
It strictly holds encrypted data (Table T and Array A) and knows nothing 
about the underlying cryptographic keys or the padding mechanics. 
Its sole responsibility is to receive a search trapdoor from the client 
and obliviously traverse the encrypted linked list to return matched nodes.
"""

from crypto_utils import CryptoUtils

class CloudSSEServer:
    def __init__(self, T: dict, A: dict):
        self.T = T  # Lookup Table (e.g., cached in Redis)
        self.A = A  # Encrypted Node Array (e.g., in DynamoDB)

    def Search(self, trapdoor_token: str) -> list:
        """Obliviously traverses the encrypted linked list."""
        if trapdoor_token not in self.T:
            return []

        results = []
        entry = self.T[trapdoor_token]
        current_addr = entry["addr"]
        current_key = entry["key"].encode('utf-8')

        # ENFORCEMENT: Check both address and key to satisfy static type checkers
        while current_addr is not None and current_key is not None:
            encrypted_node = self.A.get(current_addr)
            if not encrypted_node:
                break
            
            # Decrypt the current node to find the doc_id and the next link
            node = CryptoUtils.decrypt_data(current_key, encrypted_node)
            results.append(node["doc_id"])
            
            current_addr = node["next_addr"]
            current_key = node["next_key"].encode('utf-8') if node["next_key"] else None

        return results