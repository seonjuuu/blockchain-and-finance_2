import time
import hashlib
import binascii
import random

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


d, qx, qy = ecdsa_keygen() #키생성
r,s = ecdsa_siggen("abc",d)
print("ECDSA VERIFY:",ecdsa_verify("abc",r,s,qx,qy))

# n은 string 형태로
def form_length(n):
    tmp=n
    while len(tmp)!=64:
        tmp = '0'+tmp
    return tmp

a='345'
print("result :",form_length(a))


##4시작
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
    tmp = n
    while len(tmp)!= (tlen):
        tmp = '0' + tmp
    ret=''
    for i in range(len(tmp)-1,-1,-2):
        ret = ret+tmp[i-1]
        ret = ret+tmp[i]
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

tmp =305419896 #0x(12)(34)(56)(78) -> (78)(56)(34)(12)
print(dec_to_little_endian_str(tmp,4))

# Transaction input
# Version (4byte) | input cnt (1byte) | previous txid | output idx (4byte) | scriptlen(x) | scriptsig(x) | seqence (4byte)
ver = '01000000'
incnt = dec_to_little_endian_str(1,1)
pre_txid ='7b46bff49c3eeb7b10c37aca0b930e06bae473f99f34e9c9f45451653847ed6b'
pre_txid = hex_to_little_endian_str(pre_txid,len(pre_txid))
oidx = dec_to_little_endian_str(0,4)
seq = 'ffffffff'

#Transaction output
ocnt = dec_to_little_endian_str(2,1)

#output 0
val0 = int(0.03664619*(10**8)) #BTC -> Satoshi
val0 = dec_to_little_endian_str(val0,8)
add0 ='mt6URnuGsPZxDAPYLEBypA4BBbZ36cH9yv'
add0 = base58_to_hex(add0)
pub0, plen0 = wallet_to_pub(add0)
spub0 = '76a9' + dec_to_little_endian_str(plen0,1) + pub0 + '88ac'
slen0 = len(spub0)>>1
slen0 = dec_to_little_endian_str(slen0,1)

out0 = val0+slen0+spub0

#output 1
val1 = int(0.0172902*(10**8))
val1 = dec_to_little_endian_str(val1,8)
add1 = 'mvqjQUERnKZbH9knpka5HEsQ9eraQrEQQa'
add1 = base58_to_hex(add1)
pub1, plen1 = wallet_to_pub(add1)
spub1 = '76a9' + dec_to_little_endian_str(plen1,1) + pub1 + '88ac'
slen1 = len(spub1)>>1
slen1 = dec_to_little_endian_str(slen1,1)

out1 = val1+slen1+spub1

locktime = '00000000'
myadd = '76a9147943d227e90eed9549503b32ae140b8a12ff44ae88ac'
ladd = len(myadd)>>1
ladd = dec_to_little_endian_str(ladd,1)


# Transaction input
# Ver(4byte)|input cnt(1byte)|previous txid|output idx(4byte)|scriptlen(x)=>ladd|scriptsig(x)=>myadd|seq(4byte)
# |ocnt|out0|out1|locktime|01000000

prefix = ver + incnt + pre_txid + oidx
out = ocnt + out0 + out1 + locktime + '01000000'

msg = prefix + ladd + myadd + seq +out
print("msg:",msg)

d, qx, qy = ecdsa_keygen()
r,s = ecdsa_siggen(msg,d)

#script sig
#Siglength (1byte)|seq (0x03)|scriptlen|tag|rlen|r|tag|s|slen|hashtype (0x01)|publen|pubkey (04qxqy)
#Siglength = seq ~ hashtype
#scriptlen = tag|r|rlen|tag|s|slen
script_seq = '03'
tag='02'
r =hex(r)[2:]
r=form_length(r)
rlen = len(r)>>1
rlen = dec_to_little_endian_str(rlen,1)

s = hex(s)[2:]
s=form_length(s)
slen = len(s)>>1
slen = dec_to_little_endian_str(slen,1)

tmp0 = tag + r + rlen + tag + s + slen
script_len = len(tmp0)>>1
script_len = dec_to_little_endian_str(script_len,1)

tmp1 = script_seq+script_len+tmp0+'01'
siglen = len(tmp1)>>1
siglen = dec_to_little_endian_str(siglen,1)

#pubkey
qx = hex(qx)[2:]
qx = form_length(qx)
qy = hex(qy)[2:]
qy = form_length(qy)
pubkey = '04'+qx+qy
publen = len(pubkey)>>1
publen = dec_to_little_endian_str(publen,1)

scriptSig = siglen + tmp1 + publen + pubkey
total_len = len(scriptSig)>>1
total_len = dec_to_little_endian_str(total_len,1)

# Ver(4byte)|input cnt(1byte)|previous txid|output idx(4byte)|scriptlen(x)=>ladd|scriptsig(x)=>myadd|seq(4byte)
# |ocnt|out0|out1|locktime|01000000

tmp2 = prefix + total_len + scriptSig + seq + out

print(tmp2)

#final -> txid
tmp2 = tmp2.encode()
h=hashlib.sha256(tmp2).hexdigest()
h=int(h,16)
h=hex(h)[2:].encode()
txid=hashlib.sha256(h).hexdigest()

print("txid:",txid)