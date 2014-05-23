
StarCoin - a decendent of Novacoin/PPCoin with Pow/PoS. It combines the great features from Luckycoin (random blocks) and Florincoin (transaction message). It is the first PoW/PoS coin supporting random blocks.

Version 1.7.0

After the time-wrap bug hit Starcoin at block 777855 again and finally stoped the network from producing new blocks the following changes to the protocol were implemented:

1) The ActualSpacing is bound by 2 seconds and TargetTimespan, i.e. 15 minutes
2) The PoW/PoS ratio is set to 1:3 (compare to the original one 1:12) to allow more PoW blocks as anyway for the last half of year the PoS was already broken.
3) The block trust scoring algorithm changed to target 3 PoW blocks among past 12 blocks.

Release Notes:

The Windows binary provided is native Win64 application cross-built using linux mingw64 environment.
It is built with BerkeleyDB 4.8.30 and openssl-1.0.1g. The builtin CPU miner in above mentioned build should not work due to some incompatibility between mingw64 and original scrypt implementation. Though, mingw32 version should work just fine. Feel free to build one if you need this functionality.



The official website is: www.starcoin.info

 
FEATURES:
- PoW/PoS
- Scrypt
- 30 second block time
- Transaction Messaging
- 100 coins per block
- Difficulty Retargets every block
- 4 transaction confirmations
- 70 minted block confirmations
- mining halves every year (1,051,200 blocks)
- Total 227,334,008 coins 


BONUS BLOCKS (All Random)
- 1/120 chance 200-800 coins/block (every hour)
- 1/1440 chance 2000-8000 coins/block (twice per day)
- 1/20,000 chance 10,000-30,000 coins/block (once per week)
- 1/250,000 chance 100,000 coins/block (once per quarter)


Ports:
- Connection: 18216
- RPC: 18217


