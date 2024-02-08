import hashlib
from ecdsa import *

class transaction:
    def __init__(self, fromAddr,toAddr, amount):
        self.fromAddr = fromAddr #str
        self.toAddr = toAddr #str
        self.amount = amount #int
        self.data = fromAddr+toAddr+hex(amount)[2:]
        self.sig =''
    
    def signTransaction(self,priv):
        r,s = ecdsa_siggen(self.data,priv)
        self.sig = hex(r)[2:]+hex(s)[2:]
        self.rlen = len(hex(r)[2:])
        self.slen = len(hex(s)[2:])
        
    #과제  
    def isTransValid(self, pub):
        if len(self.sig) == 0:
            print('no signature')
            return 0

        r = int(self.sig[:self.rlen],16)%n
        s = int(self.sig[self.rlen:],16)%n

        qx = pub[:44]
        qy = pub[44:]

        qx = base58_to_hex(qx)
        qy = base58_to_hex(qy)

        qx = int(qx, 16)%n
        qy = int(qy, 16)%n
        

        if ecdsa_verify(self.data, r, s, qx, qy) == 0:
            return 0

        return 1
        
        
        ####(r,s)->검증
        # r = self.sig[:self.rlen] -> integer
        # s = self.sig[sig.rlen:] -> integer
        # pub -> base58로 인코딩되어있는것을 다시 디코딩 / qx,qy 분해해서 넣어줌
        #if ecdsa_verify(self.data,r,s,qx,qy)==0:
        # 검증실패        
        # return 0 
      


class block:
    def __init__(self,timestamp,trans,prehash):
        self.timestamp = timestamp
        self.trans = trans
        self.prehash = prehash
        self.nonce=0
        self.hash = self.calchash()
    
    def calchash(self):
        #전체 string이라 가정
        nstr = hex(self.nonce)
        nstr = nstr[2:]
        
        data = ''
        for i in self.trans:
            data = data + i.data
            
        msg=self.timestamp+data+self.prehash+nstr
        msg=msg.encode()
        msg=hashlib.sha256(msg).hexdigest()

        return msg
    
    def merkleroot(self):
        tmp=[]
        for i in self.trans:
            tmp.append(i.data)
        if len(tmp)&1!=0:
            tmp.append(tmp[len(tmp)-1])
            
        done=0
        cnt = len(tmp)>>1
        while done == 0:
            for i in range(0,cnt):
                for i in range(0,cnt):
                    h=tmp[i<<1]+tmp[(i<<1)+1]
                    h=h.encode()
                    h=hashlib.sha256(h).hexdigest()
                    tmp[i]=h
                if cnt==1:
                    done=1
                else:
                    done=0
                    if cnt&1!=0:
                        tmp[cnt]+tmp[cnt-1]
                        cnt=cnt+1
                        cnt=cnt>>1
                    else:
                        cnt=cnt>>1
                        
        return tmp[0]  
      
    def mineblock(self,difficulty):
        nonce=0
        msg = self.hash
        
        cmp=''
        for i in range(0,difficulty):
            cmp = cmp+'0' #if difficulty=4 -> '0000'
        
        data=self.merkleroot()
        print("data:",data)
            
        while (msg[:difficulty]!=cmp):
            nonce=nonce+1
            nstr=hex(nonce)
            nstr = nstr[2:]
            msg = self.timestamp+data+self.prehash+nstr
            msg = msg.encode()
            msg = hashlib.sha256(msg).hexdigest()
        self.hash = msg
        self.nonce = nonce

class blockchain:
    def __init__(self):
        self.chain=[]
        gen_block = block('20231111',[transaction('0','0',100)],'0')
        self.chain.append(gen_block)
        self.len =1
        self.mempool=[]
        self.difficulty=4
        self.reward = 100
                    
                     
    def mineMempool(self,rewardAddr,timestamp):
        newblock = block(timestamp,self.mempool,'') # mempool안에 모든 transaction을 mine 함
        newblock.prehash = self.getlatestblock().hash
        newblock.mineblock(self.difficulty)
        self.chain.append(newblock)
        self.len = self.len +1
        self.mempool=[]
        self.mempool.append(transaction('0',rewardAddr,self.reward))
        
    def addTransactions(self,trans):
        if trans.isTransValid(trans.fromAddr)==1:
            self.mempool.append(trans)
                    
    def getlatestblock(self):
        return self.chain[self.len-1]
    
    def addBlock(self,timestamp,data,difficulty):
        newblock = block(timestamp,data,'')
        newblock.prehash = self.getlatestblock().hash
        newblock.mineblock(difficulty)
        self.chain.append(newblock)
        self.len = self.len +1
        
    def getBalance(self,addr):
        balance =0
        for i in self.chain:
            for j in i.trans:
                if j.fromAddr == addr:
                    balance = balance - j.amount
                if j.toAddr ==addr:
                    balance = balance + j.amount
        return balance
        
    def isChainValid(self):
        for i in range(1, self.len):
            currBlock = self.chain[i]
            preBlock = self.chain[i-1]
            if currBlock.hash != currBlock.calchash():
                return 0
            if currBlock.prehash != preBlock.hash:
                return 0
        return 1
    
    def printBlock(self,idx):
        print("Block index:",idx)
        print("timestamp:",self.chain[idx].timestamp)
        print("data:",self.chain[idx].data)
        print("prehash:",self.chain[idx].prehash)
        print("hash:",self.chain[idx].hash)
        print("")
        
    def printBlockchain(self):
        for i in range(0,self.len):
            print("Block index:",i)
            print("timestamp:",self.chain[i].timestamp)
            print("==transactions==")
            cnt = 0
            for j in self.chain[i].trans:
                print("* transaction no #",cnt)
                print(" from:", j.fromAddr)
                print(" to:",j.toAddr)
                print(" amount:",j.amount)
                print(" sig:",j.sig)
                cnt=cnt+1
            print("==============")    
            print("prehash:",self.chain[i].prehash)
            print("hash:",self.chain[i].hash)
            print("nonce:",self.chain[i].nonce)
            print("")
        print("mempool:",self.mempool)

