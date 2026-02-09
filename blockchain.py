# blockchain.py - Simple blockchain implementation for voting system

import json
import hashlib
import time
from datetime import datetime

class Block:
    """Individual block in the blockchain."""
    
    def __init__(self, index, data, previous_hash, timestamp=None):
        self.index = index
        self.data = data
        self.previous_hash = previous_hash
        self.timestamp = timestamp or time.time()
        self.nonce = 0
        self.hash = self.calculate_hash()
    
    def calculate_hash(self):
        """Calculate SHA-256 hash of block contents."""
        block_string = json.dumps({
            "index": self.index,
            "data": self.data,
            "previous_hash": self.previous_hash,
            "timestamp": self.timestamp,
            "nonce": self.nonce
        }, sort_keys=True)
        return hashlib.sha256(block_string.encode()).hexdigest()
    
    def mine_block(self, difficulty):
        """Mine block by finding hash with required number of leading zeros."""
        target = "0" * difficulty
        
        while self.hash[:difficulty] != target:
            self.nonce += 1
            self.hash = self.calculate_hash()
        
        print(f"Block mined: {self.hash}")
    
    def to_dict(self):
        """Convert block to dictionary for JSON serialization."""
        return {
            "index": self.index,
            "data": self.data,
            "previous_hash": self.previous_hash,
            "timestamp": self.timestamp,
            "nonce": self.nonce,
            "hash": self.hash
        }
    
    @classmethod
    def from_dict(cls, block_dict):
        """Create block from dictionary."""
        block = cls(
            block_dict["index"],
            block_dict["data"],
            block_dict["previous_hash"],
            block_dict["timestamp"]
        )
        block.nonce = block_dict["nonce"]
        block.hash = block_dict["hash"]
        return block

class SimpleBlockchain:
    """Simple blockchain implementation for voting records."""
    
    def __init__(self, difficulty=4, chain_file=None):
        self.difficulty = difficulty
        self.chain_file = chain_file
        self.chain = []
        
        # Load existing chain or create genesis block
        if chain_file and self.load_chain():
            print(f"Loaded blockchain with {len(self.chain)} blocks")
        else:
            self.create_genesis_block()
    
    def create_genesis_block(self):
        """Create the first block in the chain."""
        genesis_data = {
            "message": "Genesis Block - Classical Voting System",
            "timestamp": datetime.now().isoformat(),
            "type": "genesis",
            "crypto_method": "Classical"
        }
        
        genesis_block = Block(0, genesis_data, "0")
        genesis_block.mine_block(self.difficulty)
        self.chain.append(genesis_block)
        self.save_chain()
    
    def get_latest_block(self):
        """Get the most recent block in the chain."""
        return self.chain[-1]
    
    def add_block(self, data):
        """Add a new block to the chain."""
        previous_block = self.get_latest_block()
        new_index = previous_block.index + 1
        
        # Add metadata to data
        enhanced_data = {
            **data,
            "block_index": new_index,
            "created_at": datetime.now().isoformat(),
            "crypto_system": "Classical"
        }
        
        new_block = Block(new_index, enhanced_data, previous_block.hash)
        new_block.mine_block(self.difficulty)
        
        self.chain.append(new_block)
        self.save_chain()
        
        print(f"Added block {new_index} to blockchain")
        return new_block
    
    def is_valid(self):
        """Validate the entire blockchain."""
        for i in range(1, len(self.chain)):
            current_block = self.chain[i]
            previous_block = self.chain[i - 1]
            
            # Check if current block's hash is valid
            if current_block.hash != current_block.calculate_hash():
                print(f"Invalid hash at block {i}")
                return False
            
            # Check if current block points to previous block
            if current_block.previous_hash != previous_block.hash:
                print(f"Invalid previous hash at block {i}")
                return False
        
        return True
    
    def save_chain(self):
        """Save blockchain to file."""
        if not self.chain_file:
            return False
        
        try:
            chain_data = {
                "chain": [block.to_dict() for block in self.chain],
                "difficulty": self.difficulty,
                "last_updated": datetime.now().isoformat(),
                "crypto_method": "Classical"
            }
            
            with open(self.chain_file, 'w') as f:
                json.dump(chain_data, f, indent=2)
            
            return True
        except Exception as e:
            print(f"Failed to save blockchain: {e}")
            return False
    
    def load_chain(self):
        """Load blockchain from file."""
        if not self.chain_file:
            return False
        
        try:
            with open(self.chain_file, 'r') as f:
                chain_data = json.load(f)
            
            self.chain = [Block.from_dict(block_dict) for block_dict in chain_data["chain"]]
            self.difficulty = chain_data.get("difficulty", self.difficulty)
            
            return True
        except FileNotFoundError:
            return False
        except Exception as e:
            print(f"Failed to load blockchain: {e}")
            return False
    
    def get_blocks_by_type(self, block_type):
        """Get all blocks of a specific type."""
        return [
            block for block in self.chain 
            if isinstance(block.data, dict) and block.data.get("block_type") == block_type
        ]
    
    def get_vote_blocks(self):
        """Get all blocks containing vote data."""
        return self.get_blocks_by_type("vote")
    
    def search_blocks(self, search_criteria):
        """Search blocks based on criteria."""
        results = []
        
        for block in self.chain:
            if isinstance(block.data, dict):
                match = True
                for key, value in search_criteria.items():
                    if block.data.get(key) != value:
                        match = False
                        break
                
                if match:
                    results.append(block)
        
        return results
    
    def get_chain_stats(self):
        """Get blockchain statistics."""
        vote_blocks = self.get_vote_blocks()
        
        return {
            "total_blocks": len(self.chain),
            "vote_blocks": len(vote_blocks),
            "genesis_block": self.chain[0].to_dict() if self.chain else None,
            "latest_block": self.chain[-1].to_dict() if self.chain else None,
            "chain_valid": self.is_valid(),
            "difficulty": self.difficulty,
            "crypto_method": "Classical"
        }

# Test the blockchain implementation
if __name__ == "__main__":
    print("Testing Simple Blockchain for Voting System...")
    
    # Create blockchain
    blockchain = SimpleBlockchain(difficulty=2)
    
    # Add some test vote blocks
    test_votes = [
        {
            "voter_id": "VOTER_001",
            "party_name": "Test Party A",
            "vote_hash": "abc123",
            "block_type": "vote"
        },
        {
            "voter_id": "VOTER_002", 
            "party_name": "Test Party B",
            "vote_hash": "def456",
            "block_type": "vote"
        }
    ]
    
    for vote in test_votes:
        blockchain.add_block(vote)
    
    # Test blockchain validation
    print(f"Blockchain valid: {blockchain.is_valid()}")
    
    # Get statistics
    stats = blockchain.get_chain_stats()
    print(f"Blockchain stats: {json.dumps(stats, indent=2)}")
    
    # Search for vote blocks
    vote_blocks = blockchain.get_vote_blocks()
    print(f"Found {len(vote_blocks)} vote blocks")
    
    print("✅ Blockchain implementation test completed!")