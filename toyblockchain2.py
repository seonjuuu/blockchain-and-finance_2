from toychain import *
from ecdsa import *

sswuCoin = blockchain()

dA, qxA, qyA = ecdsa_keygen()
dB, qxB, qyB = ecdsa_keygen()

addr1 = base58encode(qxA)
print("Q:",addr1,"/",len(addr1))
addr1 = addr1+base58encode(qyA)
print("Q1:",addr1[:44])

addr2 = base58encode(qxB)
addr2 = addr2+base58encode(qyB)

print("addr1:",addr1)
print("addr2:",addr2)

tx1= transaction(addr1,addr2,100)
tx2= transaction(addr2,addr1,50)
tx1.signTransaction(dA) #addr1 priv
tx2.signTransaction(dB)

sswuCoin.addTransactions(tx1)
sswuCoin.addTransactions(tx2)

sswuCoin.printBlockchain()
sswuCoin.mineMempool(addr2,'231201')
sswuCoin.printBlockchain()

print("addr1 balance:",sswuCoin.getBalance(addr1))
print("addr2 balance:",sswuCoin.getBalance(addr2))

#print(tx1.isTransValid(addr1))




