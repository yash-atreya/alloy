searchState.loadedDescShard("alloy_consensus", 0, "alloy-consensus\nReceipt envelope, as defined in EIP-2718.\nA basic blob data.\nThis represents a set of blobs, and its corresponding …\nAn error that can occur when validating a TxEip4844Variant.\nAn array of 48 bytes. Represents an untrusted (potentially …\nCustom trusted setup.\nDefault mainnet trusted setup.\nOmmer root of empty list.\nRoot hash of an empty trie.\nReceipt envelope with type flag 2, containing a EIP-1559 …\nEIP-1559 transaction type.\nA <code>TxEip1559</code> tagged with type 2.\nEIP-1559 transaction\nReceipt envelope with type flag 1, containing a EIP-2930 …\nEIP-2930 transaction type.\nA <code>TxEip2930</code> tagged with type 1.\nEIP-2930 transaction\nReceipt envelope with type flag 2, containing a EIP-4844 …\nEIP-4844 transaction type.\nA TxEip4844 tagged with type 3. An EIP-4844 transaction …\nEIP-4844 transaction\nKZG settings.\nEthereum Block header\nProof validation failed.\nAn error returned by <code>c_kzg</code>.\nReceipt envelope with no type flag.\nLegacy transaction type.\nAn untagged <code>TxLegacy</code>.\nLegacy transaction\nUsing a standalone TxEip4844 instead of the …\nThe inner transaction is not a blob transaction.\nReceipt containing result of transaction execution.\nReceipt envelope, as defined in EIP-2718.\n<code>Receipt</code> with calculated bloom filter.\nSealeable objects.\nA consensus hashable item, with its memoized hash.\nBuild a <code>BlobTransactionSidecar</code> from an arbitrary amount of …\nA strategy for coding and decoding data into sidecars. …\nA signable transaction.\nA transaction with a signature and hash seal.\nSimple coder that only uses the last 31 bytes of each …\nRepresents a minimal EVM transaction.\nA transaction with a priority fee (EIP-1559).\nTransaction with an <code>AccessList</code> (EIP-2930).\nEIP-4844 Blob Transaction\nA standalone transaction with blob hashes and max blob fee.\nEIP-4844 Blob Transaction\nEIP-4844 Blob Transaction\nA transaction with a sidecar, which contains the blob …\nThe Ethereum EIP-2718 Transaction Envelope.\nLegacy transaction.\nReceipt is the result of a transaction execution.\nEthereum <code>TransactionType</code> flags as specified in EIPs 2718, …\nThe TypedTransaction enum represents all Ethereum …\nThe versioned hash is incorrect.\nThe accessList specifies a list of addresses and storage …\nThe accessList specifies a list of addresses and storage …\nThe accessList specifies a list of addresses and storage …\nA scalar representing EIP1559 base fee which can move up …\nThe 160-bit address to which all fees collected from the …\nThe total amount of blob gas consumed by the transactions …\nIt contains a vector of fixed size hash(32 bytes)\nThe blob data.\nReturns the bloom filter for the logs in the receipt. This …\nGet <code>chain_id</code>.\nEIP-155: Simple replay attack protection\nAdded as EIP-pub 155: Simple replay attack protection\nAdded as EIP-pub 155: Simple replay attack protection\nAdded as EIP-155: Simple replay attack protection\nCode a slice of data into the builder.\nThe coder to use for ingesting and decoding data.\nThe blob commitments.\nEthereum protocol-related constants\nReturns the cumulative gas used in the block after this …\nGas used\nDecode all slices of data from the blobs.\nA scalar value corresponding to the difficulty level of …\nUtilities for working with EIP-4844 field elements and …\nRLP-encodes the transaction for signing.\nA running total of blob gas consumed in excess of the …\nAn arbitrary byte array containing data relevant to this …\nFinish the sidecar, and commit to the data. This method …\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nGet <code>gas_limit</code>.\nA scalar value equal to the current limit of gas …\nA scalar value equal to the maximum amount of gas that …\nA scalar value equal to the maximum amount of gas that …\nA scalar value equal to the maximum amount of gas that …\nA scalar value equal to the maximum amount of gas that …\nGet <code>gas_price</code>.\nA scalar value equal to the number of Wei to be paid per …\nA scalar value equal to the number of Wei to be paid per …\nA scalar value equal to the total gas used in transactions …\nReturns the KZG settings.\nCalculate the seal hash, this may be slow.\nThe receipt envelope.\nThe blob array we will code data into\nThe inner item\nGet <code>data</code>.\nInput has two uses depending if transaction is Create or …\nInput has two uses depending if transaction is Create or …\nInput has two uses depending if transaction is Create or …\nInput has two uses depending if transaction is Create or …\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nConvert to a signed transaction by adding a signature and …\nReturns the logs emitted by this transaction.\nLog send from contracts.\nThe Bloom filter composed from indexable information …\nThe bloom filter.\nMax fee per data gas\nA scalar value equal to the maximum amount of gas that …\nA scalar value equal to the maximum amount of gas that …\nMax Priority fee that transaction is paying\nMax Priority fee that transaction is paying\nA 256-bit hash which, combined with the nonce, proves that …\nCreates a new instance from a byte array.\nCreates a new blob from a byte array.\nGet <code>nonce</code>.\nA 64-bit value which, combined with the mixhash, proves …\nA scalar value equal to the number of transactions sent by …\nA scalar value equal to the number of transactions sent by …\nA scalar value equal to the number of transactions sent by …\nA scalar value equal to the number of transactions sent by …\nA scalar value equal to the number of ancestor blocks. The …\nThe Keccak 256-bit hash of the ommers list portion of this …\nThe hash of the parent beacon block’s root is included …\nThe Keccak 256-bit hash of the parent block’s header, in …\nOutputs the length of the signature RLP encoding for the …\nThe blob proofs.\nThe receipt.\nThe Keccak 256-bit hash of the root node of the trie …\nCalculate the number of field elements required to store …\nIts hash.\nSets <code>chain_id</code>.\nThe sidecar.\nThe Keccak 256-bit hash of the root node of the state …\nIf transaction is executed successfully.\nReturns true if the transaction was successful.\nA scalar value equal to the reasonable output of Unix’s …\nGet <code>to</code>.\nThe 160-bit address of the message call’s recipient or, …\nThe 160-bit address of the message call’s recipient or, …\nThe 160-bit address of the message call’s recipient.\nThe 160-bit address of the message call’s recipient or, …\nThe Keccak 256-bit hash of the root node of the trie …\nThe actual transaction.\nThe transaction type.\nGet <code>value</code>.\nA scalar value equal to the number of Wei to be …\nA scalar value equal to the number of Wei to be …\nA scalar value equal to the number of Wei to be …\nA scalar value equal to the number of Wei to be …\nThe Keccak 256-bit hash of the withdrawals list portion of …\nThe versioned hash we expected\nThe versioned hash we got\nThe address for the beacon roots contract defined in …\nTestnet genesis hash.\nOmmer root of empty list.\nTransactions root of empty receipts set.\nRoot hash of an empty trie.\nTransactions root of empty transactions set.\nWithdrawals root of empty withdrawals set.\nMultiplier for converting ether to wei.\nMultiplier for converting finney (milliether) to wei.\nBase goerli genesis hash.\nGoerli genesis hash.\nOptimism goerli genesis hash.\nMultiplier for converting gwei to wei.\nHolesky genesis hash.\nKeccak256 over empty array.\nThe Ethereum mainnet genesis hash.\nMaximum extra data size in a block after genesis\nMultiplier for converting mgas to gas.\nThe first four bytes of the call data for a function call …\nSepolia genesis hash.\nA wrapper for a slice of bytes that is a whole, valid …\nDetermine whether a slice of bytes can be contained in a …\nCalculate the number of field elements required to store …\nCalculate the number of field elements required to store …\nOmmer root of empty list.\nRoot hash of an empty trie.\nEthereum Block header\nA scalar representing EIP1559 base fee which can move up …\nThe 160-bit address to which all fees collected from the …\nReturns the blob fee for <em>this</em> block according to the …\nThe total amount of blob gas consumed by the transactions …\nA scalar value corresponding to the difficulty level of …\nA running total of blob gas consumed in excess of the …\nAn arbitrary byte array containing data relevant to this …\nReturns the argument unchanged.\nA scalar value equal to the current limit of gas …\nA scalar value equal to the total gas used in transactions …\nHeavy function that will calculate hash of data and will …\nCalls <code>U::from(self)</code>.\nChecks if the header is empty - has no transactions and no …\nThe Bloom filter composed from indexable information …\nA 256-bit hash which, combined with the nonce, proves that …\nCalculate base fee for next block according to the …\nReturns the blob fee for the next block according to the …\nCalculate excess blob gas for the next block according to …\nA 64-bit value which, combined with the mixhash, proves …\nA scalar value equal to the number of ancestor blocks. The …\nThe Keccak 256-bit hash of the ommers list portion of this …\nCheck if the ommers hash equals to empty hash list.\nThe hash of the parent beacon block’s root is included …\nThe Keccak 256-bit hash of the parent block’s header, in …\nThe Keccak 256-bit hash of the root node of the trie …\nCalculate a heuristic for the in-memory size of the Header.\nThe Keccak 256-bit hash of the root node of the state …\nA scalar value equal to the reasonable output of Unix’s …\nCheck if the transaction root equals to empty root.\nThe Keccak 256-bit hash of the root node of the trie …\nThe Keccak 256-bit hash of the withdrawals list portion of …\nReceipt is the result of a transaction execution.\nReturns the bloom filter for the logs in the receipt. This …\nReturns the bloom filter for the logs in the receipt, if …\nReturns the bloom filter for the logs in the receipt, if …\nReturns the cumulative gas used in the block after this …\nReturns the logs emitted by this transaction.\nReturns true if the transaction was successful.\nReceipt envelope, as defined in EIP-2718.\nReturns the cumulative gas used at this receipt.\nReturns the argument unchanged.\nThe receipt envelope.\nCalls <code>U::from(self)</code>.\nReturns whether this is a legacy receipt (type 0)\nReturn true if the transaction was successful.\nReturn the receipt logs.\nReturn the receipt’s bloom.\nCalculate the length of the rlp payload of the network …\nReturns the success status of the receipt’s transaction.\nThe transaction type.\nReceipt envelope with type flag 2, containing a EIP-1559 …\nReceipt envelope with type flag 1, containing a EIP-2930 …\nReceipt envelope with type flag 2, containing a EIP-4844 …\nReceipt envelope with no type flag.\nReceipt envelope, as defined in EIP-2718.\nReturn the inner receipt. Currently this is infallible, …\nReturn the inner receipt with bloom. Currently this is …\nReturns the cumulative gas used at this receipt.\nReturns the argument unchanged.\nGet the length of the inner receipt in the 2718 encoding.\nCalls <code>U::from(self)</code>.\nReturn true if the transaction was successful.\nReturn the receipt logs.\nReturn the receipt’s bloom.\nCalculate the length of the rlp payload of the network …\nReturns the success status of the receipt’s transaction.\nReturn the <code>TxType</code> of the inner receipt.\nReceipt containing result of transaction execution.\n<code>Receipt</code> with calculated bloom filter.\nCalculates <code>Log</code>’s bloom filter. this is slow operation …\nGas used\nDecodes the receipt payload\nEncodes the receipt data.\nReturns the argument unchanged.\nReturns the argument unchanged.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nConsume the structure, returning the receipt and the bloom …\nConsume the structure, returning only the receipt\nLog send from contracts.\nThe bloom filter.\nCreate new ReceiptWithBloom\nThe receipt.\nReturns the rlp header for the receipt payload.\nIf transaction is executed successfully.\nCalculates the bloom filter for the receipt and returns …\nSealeable objects.\nA consensus hashable item, with its memoized hash.\nReturns the argument unchanged.\nCalculate the seal hash, this may be slow.\nGeth the hash (alias for <code>Self::seal</code>).\nGet the inner item.\nThe inner item\nCalls <code>U::from(self)</code>.\nDecompose into parts.\nInstantiate without performing the hash. This should be …\nGet the hash.\nIts hash.\nSeal the object by calculating the hash. This may be slow.\nSeal the object by calculating the hash. This may be slow.\nInstantiate an unchecked seal. This should be used with …\nInstantiate an unchecked seal. This should be used with …\nA transaction with a signature and hash seal.\nReturns the argument unchanged.\nReturns a reference to the transaction hash.\nCalls <code>U::from(self)</code>.\nSplits the transaction into parts.\nInstantiate from a transaction and signature. Does not …\nRecover the signer of the transaction\nReturns a reference to the signature.\nCalculate the signing hash for the transaction.\nReturns the transaction without signature.\nReturns a reference to the transaction.\nA basic blob data.\nAn array of 48 bytes. Represents an untrusted (potentially …\nA signable transaction.\nRepresents a minimal EVM transaction.\nGet <code>chain_id</code>.\nRLP-encodes the transaction for signing.\nRLP-encodes the transaction for signing it. Used to …\nRLP-encodes the transaction for signing it. Used to …\nGet <code>gas_limit</code>.\nGet <code>gas_price</code>.\nGet <code>data</code>.\nConvert to a signed transaction by adding a signature and …\nGet <code>nonce</code>.\nOutputs the length of the signature RLP encoding for the …\nSets <code>chain_id</code>.\nSet <code>chain_id</code> if it is not already set. Checks that the …\nSet <code>chain_id</code> if it is not already set. Checks that the …\nCalculate the signing hash for the transaction.\nCalculate the signing hash for the transaction.\nGet <code>to</code>.\nGet <code>value</code>.\nA transaction with a priority fee (EIP-1559).\nThe accessList specifies a list of addresses and storage …\nEIP-155: Simple replay attack protection\nDecodes the inner TxEip1559 fields from RLP bytes.\nReturns the effective gas price for the given <code>base_fee</code>.\nEncodes only the transaction’s fields into the desired …\nEncodes the transaction from RLP bytes, including the …\nReturns what the encoded length should be, if the …\nReturns the argument unchanged.\nA scalar value equal to the maximum amount of gas that …\nInput has two uses depending if transaction is Create or …\nCalls <code>U::from(self)</code>.\nA scalar value equal to the maximum amount of gas that …\nMax Priority fee that transaction is paying\nA scalar value equal to the number of transactions sent by …\nCalculates a heuristic for the in-memory size of the …\nThe 160-bit address of the message call’s recipient or, …\nGet transaction type\nA scalar value equal to the number of Wei to be …\nTransaction with an <code>AccessList</code> (EIP-2930).\nThe accessList specifies a list of addresses and storage …\nAdded as EIP-pub 155: Simple replay attack protection\nDecodes the inner TxEip2930 fields from RLP bytes.\nEncodes only the transaction’s fields into the desired …\nEncodes the transaction from RLP bytes, including the …\nReturns what the encoded length should be, if the …\nReturns the argument unchanged.\nA scalar value equal to the maximum amount of gas that …\nA scalar value equal to the number of Wei to be paid per …\nInput has two uses depending if transaction is Create or …\nCalls <code>U::from(self)</code>.\nA scalar value equal to the number of transactions sent by …\nCalculates a heuristic for the in-memory size of the …\nThe 160-bit address of the message call’s recipient or, …\nGet transaction type.\nA scalar value equal to the number of Wei to be …\nA basic blob data.\nThis represents a set of blobs, and its corresponding …\nAn error that can occur when validating a TxEip4844Variant.\nAn array of 48 bytes. Represents an untrusted (potentially …\nProof validation failed.\nAn error returned by <code>c_kzg</code>.\nUsing a standalone TxEip4844 instead of the …\nThe inner transaction is not a blob transaction.\nEIP-4844 Blob Transaction\nA standalone transaction with blob hashes and max blob fee.\nEIP-4844 Blob Transaction\nEIP-4844 Blob Transaction\nA transaction with a sidecar, which contains the blob …\nThe versioned hash is incorrect.\nThe accessList specifies a list of addresses and storage …\nReturns the total gas for all blobs in this transaction.\nIt contains a vector of fixed size hash(32 bytes)\nThe blob data.\nAdded as EIP-pub 155: Simple replay attack protection\nThe blob commitments.\nDecodes the inner BlobTransactionSidecar fields from RLP …\nDecodes the inner TxEip4844Variant fields from RLP bytes.\nDecodes the inner BlobTransactionSidecar fields from RLP …\nReturns the effective gas price for the given <code>base_fee</code>.\nEncodes the inner BlobTransactionSidecar fields as RLP …\nEncodes only the transaction’s fields into the desired …\nEncodes the EIP-4844 transaction in RLP for signing.\nEncodes the inner BlobTransactionSidecar fields as RLP …\nEncodes the transaction from RLP bytes, including the …\nEncodes the transaction from RLP bytes, including the …\nReturns what the encoded length should be, if the …\nOutputs the RLP length of the BlobTransactionSidecar …\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nConstructs a new TxEip4844WithSidecar from a TxEip4844 and …\nA scalar value equal to the maximum amount of gas that …\nInput has two uses depending if transaction is Create or …\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nConsumes the TxEip4844WithSidecar and returns the inner …\nConsumes the TxEip4844WithSidecar and returns the inner …\nConsumes the TxEip4844WithSidecar and returns the inner …\nCalculates the versioned hash for a KzgCommitment\nMax fee per data gas\nA scalar value equal to the maximum amount of gas that …\nMax Priority fee that transaction is paying\nConstructs a new BlobTransactionSidecar from a set of …\nA scalar value equal to the number of transactions sent by …\nOutputs the length of the signature RLP encoding for the …\nThe blob proofs.\nGet access to the inner sidecar BlobTransactionSidecar.\nThe sidecar.\nCalculates a heuristic for the in-memory size of the …\nCalculates a size heuristic for the in-memory size of the …\nThe 160-bit address of the message call’s recipient.\nGet access to the inner tx TxEip4844.\nGet access to the inner tx TxEip4844.\nThe actual transaction.\nGet the transaction type.\nGet transaction type\nGet the transaction type.\nUtilities for working with EIP-4844 field elements and …\nVerifies that the transaction’s blob data, commitments, …\nVerifies that the given blob data, commitments, and proofs …\nVerifies that the transaction’s blob data, commitments, …\nA scalar value equal to the number of Wei to be …\nReturns the versioned hash for the blob at the given …\nReturns an iterator over the versioned hashes of the …\nThe versioned hash we expected\nThe versioned hash we got\nA builder for creating a <code>BlobTransactionSidecar</code>.\nBuild a <code>BlobTransactionSidecar</code> from an arbitrary amount of …\nA strategy for coding and decoding data into sidecars. …\nSimple coder that only uses the last 31 bytes of each …\nAllocate enough space for the required number of new field …\nGet a reference to the blobs currently in the builder.\nThe blobs in the sidecar.\nBuild the sidecar from the data, with default (Ethereum …\nBuild the sidecar from the data with the provided settings.\nCode a slice of data into the builder.\nThe coder to use for ingesting and decoding data.\nGet a mutable reference to the current blob.\nDecode all slices of data from the blobs.\nDecode an some bytes from an iterator of valid FEs.\nThe number of field elements that we have ingested, total.\nGet a mutable reference to the field element at the given …\nGet the number of used field elements in the current blob.\nFinish the sidecar, and commit to the data. This method …\nNo-op\nGet the index of the first unused field element in the …\nGet the number of unused field elements that have been …\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nInstantiate a new builder with the provided coder.\nInstantiate a new builder with the provided coder and …\nCreate a new builder from a slice of data.\nCreate a new builder from a slice of data by calling …\nIngest a slice of data into the builder.\nIngest a partial FE into the current blobs.\nIngest a field element into the current blobs.\nThe blob array we will code data into\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCheck if the builder is empty.\nCheck if the builder is empty.\nCalculate the length of used field elements IN BYTES in …\nCalculate the length of bytes used by field elements in …\nCreate a new builder, and push an empty blob to it. This …\nInstantiate a new builder and new coder instance.\nGet a mutable reference to the next unused field element.\nPush an empty blob to the builder.\nCalculate the number of field elements required to store …\nTake the blobs from the builder, without committing them …\nCreate a new builder, preallocating room for <code>capacity</code> …\nCreate a new builder with a pre-allocated capacity. This …\nA wrapper for a slice of bytes that is a whole, valid …\nDetermine whether a slice of bytes can be contained in a …\nReturns the argument unchanged.\nCalls <code>U::from(self)</code>.\nCalculate the number of field elements required to store …\nCalculate the number of field elements required to store …\nInstantiate a new <code>WholeFe</code> from a slice of bytes, if it is …\nEIP-1559 transaction type.\nA <code>TxEip1559</code> tagged with type 2.\nEIP-2930 transaction type.\nA <code>TxEip2930</code> tagged with type 1.\nEIP-4844 transaction type.\nA TxEip4844 tagged with type 3. An EIP-4844 transaction …\nLegacy transaction type.\nAn untagged <code>TxLegacy</code>.\nThe Ethereum EIP-2718 Transaction Envelope.\nEthereum <code>TransactionType</code> flags as specified in EIPs 2718, …\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturn the length of the inner txn, <strong>without a type byte</strong>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nReturn the RLP payload length of the network-serialized …\nReturn the hash of the inner Signed\nReturn the <code>TxType</code> of the inner txn.\nThe EIP-2718 transaction type.\nLegacy transaction.\nAdded as EIP-155: Simple replay attack protection\nDecode the RLP fields of the transaction, without decoding …\nOutputs the length of EIP-155 fields. Only outputs a …\nEncodes EIP-155 arguments into the desired buffer. Only …\nEncodes only the transaction’s fields into the desired …\nEncodes the transaction from RLP bytes, including the …\nReturns what the encoded length should be, if the …\nReturns the argument unchanged.\nA scalar value equal to the maximum amount of gas that …\nA scalar value equal to the number of Wei to be paid per …\nInput has two uses depending if transaction is Create or …\nCalls <code>U::from(self)</code>.\nA scalar value equal to the number of transactions sent by …\nCalculates a heuristic for the in-memory size of the …\nThe 160-bit address of the message call’s recipient or, …\nA scalar value equal to the number of Wei to be …\nEIP-1559 transaction\nEIP-2930 transaction\nEIP-4844 transaction\nLegacy transaction\nThe TypedTransaction enum represents all Ethereum …\nReturn the inner EIP-1559 transaction if it exists.\nReturn the inner EIP-2930 transaction if it exists.\nReturns the argument unchanged.\nCalls <code>U::from(self)</code>.\nReturn the inner legacy transaction if it exists.\nReturn the <code>TxType</code> of the inner txn.")