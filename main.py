import hashlib
import json
from datetime import datetime

class CertificateBlock:
    def __init__(self, index, timestamp, cert_data, previous_hash, nonce=0):
        self.index = index
        self.timestamp = timestamp
        self.cert_data = cert_data
        self.previous_hash = previous_hash
        self.nonce = nonce
        self.hash = self.calculate_hash()
    
    def calculate_hash(self):
        block_string = f"{self.index}{self.timestamp}{self.cert_data}{self.previous_hash}{self.nonce}"
        return hashlib.sha256(block_string.encode()).hexdigest()
    
    def mine_block(self, difficulty=2):
        target = '0' * difficulty
        while self.hash[:difficulty] != target:
            self.nonce += 1
            self.hash = self.calculate_hash()
        return self.hash
    
    def to_dict(self):
        return {
            'index': self.index,
            'timestamp': self.timestamp,
            'certificate': self.cert_data,
            'previous_hash': self.previous_hash,
            'nonce': self.nonce,
            'hash': self.hash
        }

class CertificateBlockchain:
    def __init__(self, difficulty=2):
        self.chain = []
        self.difficulty = difficulty
        self.certificates = {}
        self.create_genesis_block()
    
    def create_genesis_block(self):
        genesis_block = CertificateBlock(0, str(datetime.now()), "Genesis Block - Certificate Verification System", "0")
        genesis_block.mine_block(self.difficulty)
        self.chain.append(genesis_block)
    
    def get_latest_block(self):
        return self.chain[-1]
    
    def add_certificate(self, cert_data):
        previous_block = self.get_latest_block()
        new_index = previous_block.index + 1
        new_timestamp = str(datetime.now())
        new_block = CertificateBlock(new_index, new_timestamp, cert_data, previous_block.hash)
        new_block.mine_block(self.difficulty)
        self.chain.append(new_block)
        
        cert_id = cert_data.split('|')[0]
        self.certificates[cert_id] = {
            'block_index': new_index,
            'hash': new_block.hash,
            'data': cert_data
        }
        return new_block
    
    def verify_certificate(self, cert_id):
        if cert_id in self.certificates:
            cert_info = self.certificates[cert_id]
            block = self.chain[cert_info['block_index']]
            if block.hash == block.calculate_hash():
                return True, cert_info
        return False, None
    
    def is_chain_valid(self):
        for i in range(1, len(self.chain)):
            current_block = self.chain[i]
            previous_block = self.chain[i - 1]
            
            if current_block.hash != current_block.calculate_hash():
                return False
            
            if current_block.previous_hash != previous_block.hash:
                return False
        
        return True
    
    def to_json(self):
        return json.dumps([block.to_dict() for block in self.chain], indent=2)

def main():
    print("=" * 70)
    print("BLOCKCHAIN-BASED STUDENT CERTIFICATE VERIFICATION SYSTEM")
    print("=" * 70)
    
    blockchain = CertificateBlockchain(difficulty=2)
    print(f"\n✓ Genesis block created with hash: {blockchain.chain[0].hash[:16]}...")
    
    try:
        with open('certificates.txt', 'r') as file:
            certificates = file.readlines()
    except FileNotFoundError:
        print("Error: certificates.txt not found!")
        return
    
    print(f"\n📜 Processing {len(certificates)} certificate(s)...\n")
    
    for cert in certificates:
        cert = cert.strip()
        if cert:
            parts = cert.split('|')
            cert_id, name, course = parts[0], parts[1], parts[2]
            print(f"Adding Certificate {cert_id}: {name} - {course}")
            block = blockchain.add_certificate(cert)
            print(f"  → Mined with nonce: {block.nonce}")
            print(f"  → Block hash: {block.hash[:32]}...")
    
    print(f"\n🔐 Blockchain validation: {'VALID ✓' if blockchain.is_chain_valid() else 'INVALID ✗'}")
    
    print("\n" + "=" * 70)
    print("CERTIFICATE VERIFICATION TEST")
    print("=" * 70)
    
    test_certs = ["CERT001", "CERT003", "CERT999"]
    for cert_id in test_certs:
        is_valid, cert_info = blockchain.verify_certificate(cert_id)
        if is_valid:
            print(f"\n✓ {cert_id}: VERIFIED")
            print(f"  Data: {cert_info['data']}")
            print(f"  Block: #{cert_info['block_index']}")
        else:
            print(f"\n✗ {cert_id}: NOT FOUND - Invalid Certificate")
    
    try:
        with open('verification_report.txt', 'w') as file:
            file.write("=" * 70 + "\n")
            file.write("BLOCKCHAIN CERTIFICATE VERIFICATION REPORT\n")
            file.write("=" * 70 + "\n\n")
            
            for block in blockchain.chain:
                file.write(f"Block #{block.index}\n")
                file.write(f"  Timestamp: {block.timestamp}\n")
                file.write(f"  Certificate: {block.cert_data}\n")
                file.write(f"  Previous Hash: {block.previous_hash}\n")
                file.write(f"  Nonce: {block.nonce}\n")
                file.write(f"  Hash: {block.hash}\n")
                file.write("-" * 70 + "\n\n")
            
            file.write(f"\nTotal Certificates: {len(blockchain.chain) - 1}\n")
            file.write(f"Blockchain Valid: {blockchain.is_chain_valid()}\n\n")
            
            file.write("=" * 70 + "\n")
            file.write("JSON REPRESENTATION\n")
            file.write("=" * 70 + "\n\n")
            file.write(blockchain.to_json())
        
        print(f"\n✓ Verification report saved to verification_report.txt")
        print(f"✓ Total blocks in chain: {len(blockchain.chain)}")
        
    except Exception as e:
        print(f"Error writing report: {e}")
    
    print("\n" + "=" * 70)
    print("VERIFICATION COMPLETE!")
    print("=" * 70)

if __name__ == "__main__":
    main()
