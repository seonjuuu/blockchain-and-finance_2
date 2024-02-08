import time
import hashlib
import binascii
import random
import datetime

#Domain parameters
p=0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f
n=0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141
gx=0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798 
gy=0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8

# y^2=x^3+ax+b
a=0
b=7


# 0 : on curve
# 1 : not on curve 
def is_oncurve(x,y):
    t0 = (x**3+a*x+b)%p
    t1 = (y**2)%p
    if t0==t1:
        return 0
    else:
        return 1


def bin_extgcd(x,y):
    tx = x
    ty = y
    g=1
    while tx&1==0 and ty&1==0:
        tx = tx>>1
        ty = ty>>1
        g = g<<1
    u = tx
    v = ty
    A = 1
    B = 0
    C = 0
    D = 1
    flag =0

    while flag==0:
        while u&1==0:
            u=u>>1
            if A&1==0 and B&1==0:
                A=A>>1
                B=B>>1
            else:
                A=(A+ty)>>1
                B=(B-tx)>>1
        while v&1==0:
            v=v>>1
            if C&1==0 and D&1==0:
                C=C>>1
                D=D>>1
            else:
                C=(C+ty)>>1
                D=(D-tx)>>1
        if u>=v:
            u=u-v
            A=A-C
            B=B-D
        else:
            v=v-u
            C=C-A
            D=D-B        
        if u==0:
            a=C
            b=D
            flag =1
        else:
            flag =0
    
    
    return a, b, (g*v)

# x^-1 mod q
def mod_inv(x,q):
    xinv,_ , _ = bin_extgcd(x,q)
    return xinv

#print(mod_inv(3,7))

#R=P+Q
def pt_add(px,py, qx,qy):
    #lambda = t0/t1
    t0 = (py-qy)
    t1 = (px-qx)
    t1inv = mod_inv(t1,p)# t1^-1

    t0 = (t0*t1inv)%p
    rx = (t0**2-px-qx)%p
    ry = (t0*(px-rx)-py)%p
    return rx, ry

#R=2P
def pt_dbl(px, py):
    #3px^2
    t0 = px**2  #px^2
    t1 = t0+t0 # 2px^2
    t1 = (t1 + t0)%p #3px^2

    t0 = (py+py)%p
    t0inv = mod_inv(t0, p)
    #t0*t0inv ==1
    #print("chk: ",(t0*t0inv)%p)
    t0 = (t1*t0inv)%p

    rx = (t0**2-px-px)%p
    ry = (t0*(px-rx)-py)%p

    return rx, ry


def pt_dbl_proj(x,y,z):
    rx = 2*x*y*z*(9*(x**3)-8*(y**2)*z)
    rx = rx%p

    ry = -27*(x**6)+36*(x**3)*(y**2)*z-8*(y**4)*(z**2)
    ry = ry%p

    rz = 8*(y**3)*(z**3)
    rz = rz%p

    return rx, ry, rz

def pt_add_proj(X,Y,Z, x,y,z):

    oX = (Z*x - X*z)*(-((Z*x)**3 - X*((Z*x)**2)*z - (Z**3)*(y**2)*z - (X**2)*Z*x*(z**2) + 2*Y*(Z**2)*y*(z**2) + (X*z)**3 - (Y**2)*Z*(z**3)))
    oY = ((Z**4)*(x**3)*y - 2*Y*(Z**3)*(x**3)*z - (Z**4)*(y**3)*z + 3*X*Y*(Z**2)*(x**2)*(z**2) - 3*(X**2)*(Z**2)*x*y*(z**2) + 3*Y*(Z**3)*(y**2)*(z**2) + 2*(X**3)*Z*y*(z**3) - 3*(Y**2)*(Z**2)*y*(z**3) - (X**3)*Y*(z**4) + (Y**3)*Z*(z**4))
    oZ = ((Z*x - X*z)**3*Z*z)

    oX=oX%p
    oY=oY%p
    oZ=oZ%p

    return oX, oY, oZ

def kmul(k, X, Y, Z):
    tx = X
    ty = Y
    tz = Z
    kbit = k.bit_length()
    i = 1
    i = i <<(kbit-2)
    while(i!=0):
        chk = (k&i)
        tx, ty, tz = pt_dbl_proj(tx, ty, tz)
        if(chk): #chk!=0, 현재 비트 1
            tx, ty, tz = pt_add_proj(tx, ty, tz,X, Y,Z)
    #        print("bit :  1")
        i= i>>1
    return tx, ty, tz



def dec_to_little_endian_str(n,tlen):
    n_str = hex(n)
    n_str = n_str[2:]
    while len(n_str)  != (tlen<<1):
        n_str = '0' + n_str
    ret=''
    for i in range(len(n_str)-1,-1,-2):
        ret = ret+n_str[i-1]
        ret = ret+n_str[i]
    return ret

def hex_to_little_endian_str(n,tlen):
    n_str = n
    while len(n_str)  != (tlen):
        n_str = '0' + n_str
    ret=''
    for i in range(len(n_str)-1,-1,-2):
        ret = ret+n_str[i-1]
        ret = ret+n_str[i]
    return ret
   
def base58_to_hex(n):
    b58="123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    tmp = n
    tmp = tmp[::-1]
    exp =0
    ret =0
    for i in tmp:
        idx = b58.find(i)
        ret = ret + idx*(58**exp)
        exp=exp+1
    return hex(ret)[2:]

def wallet_to_pub(n):
    pub = n[2:len(n)-8]
    return pub , (len(pub)>>1)
    


### ECDSA ###

def ecdsa_keygen():
    # 개인키 선택
    d = random.randrange(1,n)
    # 공개키 연산 Q = [d]G
    X,Y,Z = kmul(d, gx, gy, 1)
    zinv=mod_inv(Z,p)

    Qx=(X*zinv)%p
    Qy=(Y*zinv)%p
    
    return d, Qx, Qy

def ecdsa_siggen(m, d):
    emsg = m.encode()
    h = hashlib.sha256(emsg).hexdigest()
    h = int(h,16)
    flag=0
    while flag==0:
        k = random.randrange(1, n) #step 2
        X,Y,Z = kmul(k, gx, gy, 1) #X/Z, Y/Z
        zinv=mod_inv(Z,p) #Z^-1
        x1 = (X*zinv)%p
        r = x1%n
        if r!=0:
            flag = 1
            kinv = mod_inv(k,n)
            s = (h+r*d)%n
            s = (s*kinv)%n
            if s!=0:
                flag =1
            else:
                flag=0
    return r,s

def ecdsa_verify(m,r,s,qx,qy):
    emsg = m.encode()
    h = hashlib.sha256(emsg).hexdigest()
    h = int(h,16)
    sinv = mod_inv(s,n)
    u1 = (h*sinv)%n
    u2 = (r*sinv)%n
    X, Y, Z = kmul(u1, gx, gy, 1)
    X2,Y2,Z2 = kmul(u2,qx,qy,1)
    Zinv = mod_inv(Z,p)
    u1x = (X*Zinv)%p
    u1y = (Y*Zinv)%p
    Zinv = mod_inv(Z2,p)
    u2x = (X2*Zinv)%p
    u2y = (Y2*Zinv)%p
    rx, _ = pt_add(u1x,u1y,u2x,u2y)
    if (r%n) ==(rx%n):
        return 1
    else:
        return 0

def form_length(n):
    tmp=n
    while len(tmp)!=64:
        tmp = '0'+tmp
    return tmp

incnt = 2
inn0=['7b46bff49c3eeb7b10c37aca0b930e06bae473f99f34e9c9f45451653847ed6b',0]
inn1=['7b46bff49c3eeb7b10c37aca0b930e06bae473f99f34e9c9f45451653847ed6b',1]
def tx_in(incnt, *inn):
    ver='01000000'
    in_str = dec_to_little_endian_str(incnt,1)
    head = ver+in_str
    ret=[]
    for i in range(0, incnt):
        a=""
        tmp=hex_to_little_endian_str(inn[i][0],len(inn[i][0]))
        a=a+tmp
        tmp=dec_to_little_endian_str(inn[i][1],4)
        a=a+tmp
        ret.append(a)
    return head, ret
head, inn = tx_in(1, inn0)

out1=[0.03664619,'mt6URnuGsPZxDAPYLEBypA4BBbZ36cH9yv']
out2=[0.0172902,'mvqjQUERnKZbH9knpka5HEsQ9eraQrEQQa']

def tx_out(outcnt, *out):
    ret=dec_to_little_endian_str(outcnt,1)

    for i in range(0, outcnt):
        a=''
        val = int(out[i][0]*(10**8))
        val = dec_to_little_endian_str(val,8)
        tmp = base58_to_hex(out[i][1])
        pub, publen =wallet_to_pub(tmp)
        spkey = '76a9' +dec_to_little_endian_str(publen,1)+pub+'88ac'
        slen = len(spkey)>>1
        slen = dec_to_little_endian_str(slen,1)
        a = val +slen + spkey
        ret = ret+a
    ret =ret+'00000000' #locktime
    return ret

out = tx_out(2,out1,out2)

def gen_script_sig(r,s,qx,qy):
    seq='0x30'
    tag='0x02'
    rtmp =hex(r)[2:]
    rtmp =form_length(rtmp)
    stmp =hex(s)[2:]
    stmp =form_length(stmp)
    rlen = dec_to_little_endian_str(len(rtmp)>>1,1)
    slen = dec_to_little_endian_str(len(stmp)>>1,1)
    script = tag +rlen + rtmp +tag + slen +stmp
    script_len = dec_to_little_endian_str(len(script)>>1,1)
    script = seq + script_len + script + '01'
    siglen = len(script)>>1
    siglen = dec_to_little_endian_str(siglen,1)

    qxtmp = hex(qx)[2:]
    qytmp = hex(qy)[2:]
    qxtmp =form_length(qxtmp)
    qytmp = form_length(qytmp)
    pkey = '04'+qxtmp +qytmp
    plen = len(pkey)>>1
    plen = dec_to_little_endian_str(plen,1)

    script = siglen + script + plen + pkey
    total_len = len(script)>>1
    total_len = dec_to_little_endian_str(total_len,1)

    return total_len, script

def gen_txid(head, inn, out, add, d, qx, qy):
    tlen_list=[]
    script_list=[]
    addlen = len(add)>>1
    addlen = dec_to_little_endian_str(addlen,1)
    for i in range(0, len(inn)):
        msg=""
        for j in range(0, i):
            msg = msg + inn[j] + '00'+'ffffffff'
        msg = msg + inn[i] +addlen + add +'ffffffff'

        for j in range(i+1,len(inn)):
            msg = msg + inn[j] +'00'+'ffffffff'
        msg = head + msg
        msg = msg + out + '01000000'
        r,s = ecdsa_siggen(msg,d)
        tlen, script = gen_script_sig(r,s,qx,qy)
        tlen_list.append(tlen)
        script_list.append(script)
    # txid 생성을 위한 msg 생성
    txid=head
    for i in range(0,len(inn)):
        txid = txid+inn[i]
        txid = txid + tlen_list[i]
        txid = txid + script_list[i]+'ffffffff'
    txid = txid + out +'01000000'
    # hash 두번
    txid = txid.encode()
    txid = hashlib.sha256(txid).hexdigest()
    txid = int(txid,16)
    txid = hex(txid)[2:].encode()
    txid = hashlib.sha256(txid).hexdigest()

    return txid

d, qx, qy = ecdsa_keygen()
myadd ='76a9147943d227e90eed9549503b32ae140b8a12ff44ae88ac'
print(gen_txid(head, inn, out, myadd, d, qx, qy))

tx1='aff1d8261a5ac26d4749d4fae47eddda0e0845e63b2f8850462d75c6e050075e'
tx2='aff1d8261a5ac26d4749d4fae47eddda0e0845e63b2f8850462d75c6e0500799'
tx3='aff1d8261a5ac26d4749d4fae47eddda0e0845e63b2f8850462d75c6e0500aaa'

def gen_merkle_root(*txid):
    tmp=[]
    for i in range(0, len(txid)):
        tmp.append(txid[i])
    if len(tmp)&1!=0:
        tmp.append(txid[len(txid)-1])
    rnd = len(tmp)>>1

    while rnd !=1:
        cnt=0
        for i in range(0, rnd):
            msg = tmp[(i<<1)]+tmp[(i<<1)+1]
            msg = msg.encode()
            msg = hashlib.sha256(msg).hexdigest()
            msg = int(msg,16)
            msg = hex(msg)[2:].encode()
            msg = hashlib.sha256(msg).hexdigest()
            tmp[cnt]=msg
            cnt=cnt+1
        chk = rnd&1
        rnd = rnd>>1
    print("chk:",chk)
    msg = tmp[0]+tmp[1]
    msg = msg.encode()
    msg = hashlib.sha256(msg).hexdigest()
    msg = int(msg,16)
    msg = hex(msg)[2:].encode()
    ret = hashlib.sha256(msg).hexdigest()   

    if chk==1:
        msg = ret +tmp[2]
        msg = msg.encode()
        msg = hashlib.sha256(msg).hexdigest()
        msg = int(msg,16)
        msg =hex(msg)[2:].encode()
        ret = hashlib.sha256(msg).hexdigest()
    return ret

## 6시작
def dbl_sha(msg):
    h = bytes.fromhex(msg)
    #print("h:",h)
    h = hashlib.sha256(h).hexdigest()
    h = bytes.fromhex(h)
    h = hashlib.sha256(h).hexdigest()
    return h

msg = 'abcd' #0xabcd

#링크
head = '00c0972d87bd61a769b6f77a6a20712dfaee83ba0aa39fae122c27ba37000000000000008511af2524a61cd5979c775900a34bb3ffc224e373c93f269819a04ee368dcc4b58f2765e0926719481df6c6'
res = '0000000000000039b3f01eb4a72f82bd464657194ce6e855daa8d5cc433b490d'

tmp = dbl_sha(head)
tmp = (hex_to_little_endian_str(tmp,len(tmp)))
print(tmp)

def little_to_big(n):
    ret=''
    for i in range(len(n)-1,-1,-2):
        ret = ret + n[i-1]
        ret = ret + n[i]
    return ret
#print(little_to_big(tmp))

def print_headerinfo(head):
    tmp = head
    ver = tmp[:8]
    ver = little_to_big(ver)
    tmp = tmp[8:]
    pre_hash = tmp[:64]
    pre_hash = little_to_big(pre_hash)
    tmp = tmp[64:]
    mroot = tmp[:64]
    mroot = little_to_big(mroot)
    tmp = tmp[64:]
    ntime = tmp[:8]
    ntime = little_to_big(ntime)
    rtime = '0x'+ntime
    rtime = int(rtime,16) #rtime을 16진수로 변형
    rtime = datetime.datetime.utcfromtimestamp(rtime)
    tmp = tmp[8:]
    nbits = tmp[:8]
    nbits = little_to_big(nbits)
    tmp = tmp[8:]
    nonce = little_to_big(tmp)

    print('=== header info ===')
    print("version: ", ver)
    print("previous hash: ", pre_hash)
    print("Merkle root: ", mroot)
    print("time: ", rtime)
    print("nbits: ", nbits)
    print("nonce: ", nonce)
    
    return ver, pre_hash, mroot, ntime, nbits, nonce 

ver, pre_hash, mroot, ntime, nbits, nonce = print_headerinfo(head)

def set_bit(nbits):
    nbit_len = nbits[:2]
    nbit_len = '0x'+nbit_len
    nbit_len = int(nbit_len,16)
    
    tmp = nbits[2:]
    while len(tmp) != (nbit_len<<1):
        tmp = tmp+'00'
    while len(tmp) != 64:
        tmp = '00'+tmp
    return tmp

def calc_diff(nbits):
    gen = '1d00ffff'
    gen_target = set_bit(gen)
    gen_target = '0x'+gen_target
    gen_target = int(gen_target,16)
    
    curr_target = set_bit(nbits)
    curr_target = '0x'+curr_target
    curr_target = int(curr_target,16)
    
    return gen_target/curr_target
print('difficulty:',calc_diff(nbits))

start = '0x'+nonce
start = int(start,16)
start = start-10

def find_nonce(ver, pre_hash, mroot, ntime, nbits, start): #nonce대신start넣어줌 
    
    ver_t = hex_to_little_endian_str(ver,len(ver))
    pre_ht = hex_to_little_endian_str(pre_hash,len(pre_hash))
    mroot_t = hex_to_little_endian_str(mroot,len(mroot))
    ntime_t = hex_to_little_endian_str(ntime, len(ntime))
    nbits_t = hex_to_little_endian_str(nbits, len(nbits))

    ct = set_bit(nbits)
    ct = '0x' + ct
    ct = int(ct,16)
    for i in range(0,20):
        tmp = start + i      # tmp는 nonce 후보 (i가 10일때 나와야함)
        tmp = dec_to_little_endian_str(tmp,4)
        
        #header 조립
        tmp_h = ver_t + pre_ht + mroot_t + ntime_t + nbits_t + tmp
        tmp_h = dbl_sha(tmp_h)
        tmp_h = hex_to_little_endian_str(tmp_h,len(tmp_h))
        
        num = '0x' + tmp_h
        num = int(num,16)
        
        if(num<ct):
            print("tmp_h:",tmp_h)
            print("nonce", little_to_big(tmp))
find_nonce(ver, pre_hash, mroot, ntime, nbits, start)            
