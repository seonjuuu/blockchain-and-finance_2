txt='483045022100d2dc378542d152d6f568b5c8e491d809f3a634fc690092b29c44795e0fd69cf5022032a86e22b7b86295b98000e01e7918c5b22a70fcfa7c97ed05a0544f0478e58e014104f5aa8ea9a29b5629c4e833d5431e2313cabd46f4dbcc69770fc513d7b35f980f7159a911f967dcf73cb15a8c8bb7b382b66963d3a5244bdb2e7698afb319c882'

def str_to_hex(n):
    tmp = '0x'+n
    return(int(tmp,16)<<1)

sigLength = txt[0:2] #한바이트를 끊기위해서는 2개씩 끊어야함
print("Siglength:", sigLength)
sigLength = str_to_hex(sigLength)
#signature
Sig = txt[2:2+(sigLength<<1)]
PubKey = txt[(2+(sigLength<<1)):]

seq = Sig[:2]
print("seqence:",seq)
Sig = Sig[2:]
slen = Sig[:2]
print("script leng=real sig len",slen)
Sig = Sig[2:] #Tag
tag = Sig[:2]
print("Tag:",tag)
Sig = Sig[2:]
rlen = Sig[:2]
print("rlen:",rlen)
rlen = str_to_hex(rlen)  # r의 길이는 정해지지않아서 모름 -> rlen을 이용하여 rlen을 hex로 바꿔줘서 그만큼의 길이를 뗴어주면 = r 
Sig = Sig[2:] #Sigr
r = Sig[:rlen]   
Sig = Sig[rlen:]
print('r',r)
tag = Sig[:2]
print("tag s:",tag)
Sig = Sig[2:]
slen = Sig[:2]
print("slen:",slen)
Sig = Sig[2:]
slen = str_to_hex(slen)
s = Sig[:slen]
print("s:",s)
htype = Sig[slen:]
print("hash type:",htype)

# publickey
plen = PubKey[:2]
print("plen",plen)
pk = PubKey[2:]
print("pk:",pk)
