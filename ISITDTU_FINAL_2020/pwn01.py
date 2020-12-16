from pwn import *
import hmac
from ctypes import CDLL

p = process("./service")
# gdb.attach(p,'''b *secret+370
# 	c''')
libc = CDLL("libc.so.6")

def genString(length):
	data=[0]*length
	print_data="abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
	for i in range(0,length):
		data[i]=print_data[libc.rand()%52]
	return "".join(data)
def getSecret(data):
	list_data=[]
	for i in range(0,100000):
		libc.srand(i)
		uid=genString(10)
		public_key=genString(16)
		challenge=genString(16)
		secret=genString(16)
		s=0
		for j in range(0,len(data)):
			if public_key[j]==data[j]:
				s+=1
		if s>15:
			list_data.append(uid)
			list_data.append(public_key)
			list_data.append(challenge)
			list_data.append(secret)
	return list_data



def signup(username,pwd):
	p.sendline("1")
	p.sendline(username)
	p.sendline(pwd)

def signin(username,password):
	list_data=[]
	p.sendline("2")
	p.sendline(username)
	p.recvuntil("Publickey: ")
	public_key=p.recvuntil("\n").strip()
	print "public key =", public_key
	p.recvuntil("Challenge: ")
	challenge= p.recvuntil("\n").strip()
	print "challenge: ", challenge
	h4=hmac.new(public_key,password + challenge).hexdigest().upper()
	print "hmac =",h4
	p.sendline(h4)
	list_data.append(public_key)
	list_data.append(challenge)
	list_data.append(h4)
	return list_data
def secret(key):
	p.sendline("4")
	print "session len = ",len(session.strip())
	p.sendline(session.strip())
	h5 = hmac.new(list_data[2],list_data[1]+"secret").hexdigest().upper()
	print h5
	p.sendline(h5)
	secret_data=getSecret(public_key)
	print "secret",secret_data[3]
	p.sendline(secret_data[3])
signup("a","a")
list_data=signin("a","a")
print "info login = ",list_data
p.recvuntil("Session uid: ")
session=p.recvuntil("\n").strip()
print "session =",session
public_key=list_data[0]
# p.sendline(session)
secret(public_key)





# print priv_key+"\n"

p.interactive()