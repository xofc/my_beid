mybeid_sign: mybeid_sign.c
	gcc -o mybeid_sign -I /usr/include/PCSC mybeid_sign.c -lpcsclite

clean:
	rm mybeid_sign *.bin *.sig
