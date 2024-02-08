####
import hashlib
class block:
    def __init__(self,timestamp,data,prehash):
        self.timestamp = timestamp
        self.data = data
        self.prehash = prehash
        self.nonce=0
        self.hash = self.calchash()
        
    def mineblock(self,difficulty):
        #과제(timestamp를 int값으로 입력받아 string으로 변환)
        start=0
        prefix = str(self.timestamp)+self.data+self.prehash
        msg = prefix+'0'
        msg = msg.encode()
        msg = hashlib.sha256(msg).hexdigest()
        
        cmp=''
        for i in range(0,difficulty):
            cmp = cmp+'0' #if difficulty=4 -> '0000'
            
        while (msg[:difficulty]!=cmp):
            start=start+1
            nstr=hex(start)
            nstr = nstr[2:]
            msg = prefix+nstr
            msg = msg.encode()
            msg = hashlib.sha256(msg).hexdigest()
        self.hash = msg
        self.nonce = start
        
    
    def calchash(self):
        #과제(timestamp를 int값으로 입력받아 string으로 변환)
        nstr = hex(self.nonce)
        nstr = nstr[2:]
        msg=str(self.timestamp)+self.data+self.prehash+nstr
        msg=msg.encode()
        msg=hashlib.sha256(msg).hexdigest()

        return msg

class blockchain:
    def __init__(self):
        self.chain=[]
        gen_block = block(231111,'genesis','0')
        gen_block.mineblock(4)
        self.chain.append(gen_block)
        self.len =1
        
    def getlatestblock(self):
        return self.chain[self.len-1]
    
    def addBlock(self,timestamp,data,difficulty):
        newblock = block(timestamp,data,'')
        newblock.prehash = self.getlatestblock().hash
        newblock.mineblock(difficulty)
        self.chain.append(newblock)
        self.len = self.len +1
        
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
            print("data:",self.chain[i].data)
            print("prehash:",self.chain[i].prehash)
            print("hash:",self.chain[i].hash)
            print("nonce:",self.chain[i].nonce)
            print("")

sswuCoin = blockchain()
sswuCoin.addBlock(20231112,'1000',4)
sswuCoin.printBlockchain()

print("is block valid?:", sswuCoin.isChainValid())
    
