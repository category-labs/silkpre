// Validator Staking Precompile for Category Client


// State Management in DB
// How state is handled is proposed in main issue. To summarize
// we can just use consecutive slots in the db. 

// Changes to block preprocessing 
// Assuming that rewards and slashing are included in execution blocks,
// there will neccessarily be some changes to the pre-processing phase 
// of blocks to include these transactions. 


//  States and Sets
    deposit_request
    	blspubkey: BLSPubkey   // 48 Bytes
	    secppubkey: SecpPubkey // 33 Bytes
	    withdrawal_credentials:// 32 Bytes
	    amount: Gwei           // 32 Bytes
	    blssignature: Signature(blspubkey,withdrawal_credentials,amount)  //48 Bytes
        secpsignature: Signature(blspubkey,withdrawal_credentials,amount) //64 Bytes
    //  is this capable of a replay attack? 

    withdraw_request
	    blspubkey: BLSPubkey    // 48 Bytes
	    secppubkey: SecpPubkey  // 33 Bytes 
		amount: uint64          // 32 Bytes

    reward_request:
        blspubkey: BLSPubkey    // 48 Bytes
	    secppubkey: SecpPubkey  // 33 Bytes 
		amount: uint64          // 32 Bytes

    slashing_request:
        blspubkey: BLSPubkey    // 48 Bytes
	    secppubkey: SecpPubkey  // 33 Bytes 
		amount: uint64          // 32 Bytes

    // Example of Slashing evidence 
    // https://github.com/category-labs/category-internal/issues/846
    
    validator_info
        blspubkey: BLSPubkey     // 48 Bytes
	    secppubkey: SecpPubkey   // 33 Bytes
        withdrawal_credentials:  // 32 Bytes
		balance: uint64          // 32 Bytes // These fields depend on  
        reward_balance: uint64   // 32 Bytes // how rewards are distributed



    deposit_queue
    withdrawal_queue 
    validator_set


//Note 1: Precompile should not have a callback function. 

//Note 2: Balance accounting is based on 1e18.
//        To maintain system solvency rounding should be done in 
//        favor of precompile. I.E there is perhaps some amount of 
//        gas contain in this precompile in perpetuity. 


//  External Processes (Write)
    
    // A validator calls this function to request to join the validator set. This 
    // effects the deposit_queue.
    void deposit
    // Invariants  
    // precompile.balance_after == precompile.balance_before + msg.balance
    // deposit_queue.size_after == deposit_queue.size_before + 1 
    // validator.balance_after == caller.balance_before + msg.balance
    
    // A validator calls this function to request to leave the validator set. This 
    // effects the withdrawal_queue.
    void withdrawal
    // Invariants  
    // withdrawal_queue.size_after == withdrawal.size_before + 1 

    // The following functions depend on how rewards are collected. Another option is  
    // that deposit and withdraw can be overloaded to include increase_stake, decrease_stake

    // A validator in val_set calls this function to increase their active stake 
    void increase_stake

    // A validator in val_set calls this function to increase their active stake 
    void decrease_stake

    // A validator in val_set calls this function to claim rewards 
    void claim_block_rewards 

    // end of optional functions

//  Internal Processes

    // Execution calls at terminal block of an epoch. This updates the validator_set with 
    // the applicable subset of deposit_queue. 
    void _system_process_deposit_queue_epoch_end
    
    // Execution calls at terminal block of an epoch. This updates the validator_set with 
    // the applicable subset of withdrawal_queue. 
    void _system_process_add_withdrawal_request_epoch_end

    // Execution calls at initial block of an epoch. This updates the validator_set with 
    // the applicable subset of deposit_queue. 
    void _system_process_deposit_queue_epoch_begin

    // Execution calls at initial block of an epoch. This updates the validator_set with 
    // the applicable subset of withdrawal_queue. 
    void _system_process_add_withdrawal_request_epoch_begin
    
    // Execution calls at end of block execution. This updates the balance of the leader 
    // whose block was finalized.
    void _system_process_block_rewards

    // Execution calls at end of block execution. This verifies the submitted evidence and updates 
    // the state of the slashed validator.
    void _system_process_slash_stake


// Optional Genesis Functions
    // Define the genesis set of validators
    void setGenesisSet();
    
    // Define the genesis set of Delegators
    void setGenesisDelegation();



//  External Processes (Read)

    getdepositrequests()
    getwithdrawalrequest()

    getTotalActiveStake
    getTotalStake
    getValidatorSetCurrentEpoch
    getValidatorSetNextEpoch
    getStake(pubkey, pubkey)
    
    getValidator() 
    getValidatorID()
    getValidatorPubkeys()    

    isSlashed();
    getStatus()

    
    
        
    
