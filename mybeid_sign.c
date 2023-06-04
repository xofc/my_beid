#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <termios.h>
#include <unistd.h>
#include <winscard.h>

#define	ALGO	0x20	/* 20/37 - 29/37 */
#define KEY	0x83	/* 12/37 - 29/37 */
#define TOFILL	0x00	/* placeholder */

void usage(char *prog_name, char *str)
	{
	fprintf(stderr, "%s: %s\n", prog_name, str);
	fprintf(stderr, "\tusage: '%s <name> -k <key> -a <algo> -d <hash> [-o <sigfile>]\n", prog_name);
	}
void xdump(char *str, u_char *ucp, int len)
	{
	int	i;

	printf("%s: ", str);
	for (i = 0; i < len; i++)
		printf("%02X ", *ucp++);
	printf("\n");
	}
/*
** hex2bin("0123abcd", produces {0x12, 0x34, 0xab, 0xcd} ) and returns 4 
*/
int hex2bin(char *str, unsigned char *ucp)
	{
	char	c;
	u_char	nib;
	int	len = 0;

	c &= ~0x20; /* to lower cases */
	while (c = *str++)
		{
		len += 1;
		if (c >= '0' && c <= '9')
			nib = (c - '0');
		else if (c >= 'a' && c <= 'f')
			nib = (c - 'a' + 10);
		else	return(-1);
	/* second nibble */
		nib <<= 4;
		if (! (c = *str++))
			return(-1);
		if (c >= '0' && c <= '9')
			nib += (c - '0');
		else if (c >= 'a' && c <= 'f')
			nib += (c - 'a' + 10);
		else	return(-1);
		*ucp++ = nib;
		}
	return(len);
	}
int save(char *fname, unsigned char *ucp, int len)
	{
	FILE *stream;

	if ((stream = fopen(fname, "w+")) == NULL)
		{
		perror(fname);
		exit(-1);
		}
	if (fwrite(ucp, len, 1, stream) != 1)
		{
		perror("fwrite");
		exit(-1);
		}
	fclose(stream);
	}
SCARDHANDLE beid_card_init()
	{
	SCARDCONTEXT	hContext;
	SCARDHANDLE	hCard;
	DWORD		dwActiveProtocol;
	DWORD		dwReaderLen, dwState, dwProt, atr_len;
	LONG		err;
	char		szReader[MAX_BUFFER_SIZE];
	BYTE		atr_buf[MAX_BUFFER_SIZE];

	if (err = SCardEstablishContext(SCARD_SCOPE_SYSTEM, NULL, NULL, &hContext))
		{
		fprintf(stderr, "Failed to establish context: %s\n", pcsc_stringify_error(err));
		exit(1);
		}
	/* printf("Context ok\n");	/**/
	dwReaderLen = sizeof(szReader);
	if (err = SCardListReaders(hContext, NULL, szReader, &dwReaderLen))
		{
		fprintf(stderr, "Failed to list readers: %s\n", pcsc_stringify_error(err));
		SCardReleaseContext(hContext);
		exit(1);
		}
	/* printf("List ok\n");	/**/
	if (err = SCardConnect(hContext, szReader, SCARD_SHARE_SHARED, SCARD_PROTOCOL_T0 | SCARD_PROTOCOL_T1, &hCard, &dwActiveProtocol))
		{
		fprintf(stderr, "Failed to connect to card: %s\n", pcsc_stringify_error(err));
		SCardReleaseContext(hContext);
		exit(1);
		}
	/* printf("Connected hCard=0x%08x dwActiveProtocol=0x%08x\n", (unsigned int) hCard, (unsigned int) dwActiveProtocol);	/**/
	dwReaderLen = sizeof(szReader);
	atr_len = sizeof(atr_buf);
		/* https://learn.microsoft.com/en-us/windows/win32/api/winscard/nf-winscard-scardstatusa */
	if (err = SCardStatus(hCard, szReader, &dwReaderLen, &dwState, &dwProt, atr_buf, &atr_len))
		{
		fprintf(stderr, "Failed to get status: %s\n", pcsc_stringify_error(err));
		SCardDisconnect(hCard, SCARD_LEAVE_CARD);
		SCardReleaseContext(hContext);
		exit(1);
		}
	/* printf("Status ok\n");	/**/
	return(hCard);
	}
int beid_get_card_data(SCARDHANDLE sch)
	{
	u_char 	apdu[] = { 0x80, 0xe4, 0x00, 0x00, 0x1C};	/* p.50/54 v1.8 */
	u_char	buf[256];
	DWORD	len = sizeof(buf);
	LONG	err;

printf("beid_get_card_data()\n");
	if (err = SCardTransmit(sch, SCARD_PCI_T0, apdu, sizeof(apdu), NULL, buf, &len))
		{
		fprintf(stderr, "Failed to transmit beid_get_card_data : (0x%lx) %s\n", err, pcsc_stringify_error(err));
		return(1);
		}
	xdump("beid_get_card_data", buf, len);
	return(0);
	}
int beid_mse_set(SCARDHANDLE sch, int algo_nr, int priv_key_nr)	/* p.29/37 */
	{
	u_char 	apdu[] = { 0x00, 0x22, 0x41, 0xb6, 0x05 ,   0x04, 0x80, ALGO, 0x84, KEY};	/* 29/37 - 45/54 */
	u_char	buf[256];
	DWORD	len = sizeof(buf);
	LONG	err;

	apdu[7] = algo_nr;
	apdu[9] = priv_key_nr;
	if (err = SCardTransmit(sch, SCARD_PCI_T0, apdu, sizeof(apdu), NULL, buf, &len))
		{
		fprintf(stderr, "Failed to transmit beid_mse_set : (0x%lx) %s\n", err, pcsc_stringify_error(err));
		return(1);
		}
	xdump("beid_mse_set", buf, len);
	return(0);
	}
int beid_mvp_verify(SCARDHANDLE sch, char *pinstr)
	{ /* 00:20:00:01:08:24:12:34:ff:ff:ff:ff:ff */
	u_char 	apdu[] = { 0x00, 0x20, 0x00, 0x01, 0x08, 0x24, TOFILL, TOFILL, 0xff, 0xff, 0xff, 0xff, 0xff};
	u_char	buf[256];
	DWORD	len = sizeof(buf);
	LONG	err;

	hex2bin(pinstr, apdu+6);
	if (err = SCardTransmit(sch, SCARD_PCI_T0, apdu, sizeof(apdu), NULL, buf, &len))
		{
		fprintf(stderr, "Failed to transmit beid_mvp_verify : (0x%lx) %s\n", err, pcsc_stringify_error(err));
		return(1);
		}
	xdump("beid_mvp_verify", buf, len);
	return(0);
	}
int beid_pso_cds(SCARDHANDLE sch, char *hash_strp)	/* Perform Security Operation:Compute Digital Signature p.32/37 */
	{
	u_char 	apdu[256] = { 0x00, 0x2A, 0x9E, 0x9A, /* 0x05, 'b', 'a', 'b', 'a', 'r', 0x00};  */
			0x20, 0x35, 0xFA, 0x2D, 0xC8, 0x5C, 0xCD, 0x33, 0x76, 0x85, 0x1A, 0x70, 0x30, 0xC8, 0xC8, 0x2C, 0x2E, 0xEF, 0xB2, 0x4B, 0x20, 0x1B, 0x52, 0x44, 0xA6, 0x37, 0x5F, 0x5A, 0xB9, 0xFE, 0x23, 0xD8, 0x35};
	u_char	buf[512], filename_buf[256];
	DWORD	len = sizeof(buf);
	LONG	err;

	apdu[4] = hex2bin(hash_strp, apdu + 5);
//			printf("beid_pso_cds(%s; len=%ld - %d - %ld)\n", hash_strp, strlen(hash_strp), apdu[4], sizeof(apdu));
	sprintf(filename_buf, "%s.bin", hash_strp);
	save(filename_buf, apdu+5, 32);
	if (err = SCardTransmit(sch, SCARD_PCI_T0, apdu, 6 + apdu[4], NULL, buf, &len))
		{
		fprintf(stderr, "Failed to transmit beid_pso_cds : (0x%lx) %s\n", err, pcsc_stringify_error(err));
		return(1);
		}
	xdump("beid_pso_cds", buf, len);
	return(0);
	}
int beid_get_sig_response(SCARDHANDLE sch, char *hash_strp)
	{
	u_char 	apdu[] = { 0x00, 0xC0, 0x00, 0x00, 0x00 };	/* 19/37 */
	u_char	buf[512], filename_buf[256];
	DWORD	len = sizeof(buf);
	LONG	err;

	if (err = SCardTransmit(sch, SCARD_PCI_T0, apdu, sizeof(apdu), NULL, buf, &len))
		{
		fprintf(stderr, "Failed to transmit beid_get_response : (0x%lx) %s\n", err, pcsc_stringify_error(err));
		return(1);
		}
	xdump("beid_get_response", buf, len);
	sprintf(filename_buf, "%s.sig", hash_strp);
	save(filename_buf, buf, len - 2);
	return(0);
	}
int bad_key(int key)
	{
	if ((key != 0x82) && (key != 0x83))
		return(1);
	else	return(0);
	}
int bad_algo(int algo)
	{
	int	i;

	for (i = 0; i < 6; i++)
		{
		if (algo == (1 << i))
			return(0);
		}
	return(1);
	}
int get_hash(char *hash_hex, u_char *hash_bin)
	{
	}
char *get_pin()
	{
	static char pinbuf[8];
	struct termios termios;

	tcgetattr(0, &termios);
	termios.c_lflag &= ~ECHO;	/* don't display the PIN while typing */
	tcsetattr(0, 0, &termios);
	fprintf(stdout, "PIN: ");
	fgets(pinbuf, 5, stdin);
	termios.c_lflag |= ECHO;
	tcsetattr(0, 0, &termios);
xdump("pin-", pinbuf, 6);
	return(pinbuf);
	}
int main(int argc, char *argv[])
	{
	int	opt;
	SCARDHANDLE hCard;
	int	algo;
	int	key;
	int	hash_len;
	char 	*hash_str;
	u_char	hash_buf[256];
	char	*sig_name = "signature.sig";

	key = 0x82;		/* default = Authentication key */
	algo = (1 << 5);	/* default = 0x20 sha256 */
	while ((opt = getopt(argc, argv, "sa:d:o:")) != -1)
		{
		switch(opt)
			{
			case 's':	/* non-repudiation key to sign (default = authentication key) */
				key = 0x83;
				break;
			case 'a':	/* algorithm 0..6 */
				algo = optarg[0] - '0';
				if (algo < 0 || algo > 6)
					{
					usage(argv[0], "Bad algorithm. should be 0..6 (default is 5)");
					exit(-1);
					}
				algo = (1 << algo);
				break;
			case 'd':	/* hash to sign */
				hash_str = optarg;
				break;
			case 'o':	/* output signature file */
				sig_name = optarg;
				break;
			default:
				usage(argv[0], "Bad option\n");
				exit(-1);
				break;
			}
		}
	hCard = beid_card_init();
	beid_mse_set(hCard, algo, key);
	beid_mvp_verify(hCard, get_pin());
	beid_pso_cds(hCard, hash_str);
	beid_get_sig_response(hCard, hash_str);
exit(0);
	SCardDisconnect(hCard, SCARD_LEAVE_CARD);
/*	SCardReleaseContext(hContext);		/**/
	exit(0);
	}
