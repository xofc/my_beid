#!/bin/bash
#
# sudo apt-get install opensc
#	reads the beid files
#
opensc-explorer <<END
cd df01
get 4031 4031-id_rn.bin
get 4032 4032-sgn_rn.bin
get 4033 4033-id_address.bin
get 4034 4034-sgn_rn.bin
get 4035 4035-id_photo.jpg
get 4038 4038-puk_7_ca.bin
get 4039 4039-pref.bin

cd ..
cd df00
get 5031 5031-odf.bin
get 5032 5032-token_info.bin
get 5034 5034-aodf.bin
get 5035 5035-pr_kdf.bin
get 5037 5037-cdf.bin
get 5038 5038-cert_2_auth.der
get 5039 5039-cert_3_sign.der
get 503a 503a-cert_4_ca.der
get 503b 503b-cert_6_root.der
get 503c 503c-cert_8_rn.der
END

