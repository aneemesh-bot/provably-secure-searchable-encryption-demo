"""
main.py

This is the orchestration and simulation script for the SSE prototype.
It initializes synthetic cloud document data, triggers the client-side 
index building and encryption, simulates network deployment to the server, 
and runs end-to-end search queries to verify both correctness and 
the IND-CKA2 padding mechanism.
"""

from client import CloudSSEClient
from server import CloudSSEServer
from crypto_utils import CryptoUtils

def main():
    # 1. Prepare Synthetic Data (Key-Value Metadata)
    print("Initializing Synthetic Database...")
    synthetic_cloud_db = {
        "doc_001": {"type": "report", "department": "finance", "status": "active", "content": "Q3 revenues are up 20%."},
        "doc_002": {"type": "report", "department": "hr", "status": "archived", "content": "Employee onboarding guides."},
        "doc_003": {"type": "invoice", "department": "finance", "status": "active", "content": "Vendor payment for software licenses."}
    }

    client = CloudSSEClient()
    
    # 2. Upload Phase: Client builds index and encrypts data
    print("\n[CLIENT] Building IND-CKA2 Index...")
    encrypted_docs, T, A = client.BuildIndex(synthetic_cloud_db)
    print(f"[CLIENT] Index built. Sending {len(encrypted_docs)} encrypted docs, {len(T)} T-entries, and {len(A)} A-nodes to server.")
    
    # Simulate deploying to the cloud
    server = CloudSSEServer(T, A)

    # 3. Comprehensive Testing Phase
    test_queries = [
        "status:active",          # Exists (doc_001, doc_003)
        "department:finance",     # Exists (doc_001, doc_003)
        "type:report",            # Exists (doc_001, doc_002)
        "department:marketing",   # Does NOT exist
        "status:pending"          # Does NOT exist
    ]

    print("\n--- RUNNING TEST CASES ---")
    for query in test_queries:
        print(f"\n[CLIENT] Generating trapdoor for query: '{query}'")
        trapdoor = client.GenerateTrapdoor(query)
        
        print("[SERVER] Executing oblivious search...")
        encrypted_results = server.Search(trapdoor)
        print(f"[SERVER] Returned {len(encrypted_results)} encrypted node matches.")
        
        print("[CLIENT] Processing results and stripping IND-CKA2 padding...")
        final_documents = []
        for doc_id in encrypted_results:
            if doc_id != "DUMMY_DOC":
                decrypted_doc = CryptoUtils.decrypt_data(client.doc_key, encrypted_docs[doc_id])
                final_documents.append((doc_id, decrypted_doc))
                
        print(f"--- RESULTS FOR '{query}' ---")
        if not final_documents:
            print(" -> No matches found.")
        else:
            print(f" -> Matches Found: {len(final_documents)}")
            for doc_id, doc in final_documents:
                print(f"    - {doc_id} | Dept: {doc['department']} | Type: {doc['type']} | Status: {doc['status']}")


if __name__ == "__main__":
    main()