#./configure --enable-debug \
#	--enable-nfqueue \
#	--enable-non-bundled-htp \
#	--with-libhtp-includes=/usr/local/include/htp \
#	--with-libhtp-libraries=/usr/local/lib

./configure --enable-debug \
	--enable-nfqueue \
	--enable-non-bundled-htp \
	--with-libhtp-includes=/usr/local/include/htp \
	--with-libhtp-libraries=/usr/local/lib \
	--with-libjansson-includes=/usr/local/include \
	--with-libjansson-libraries=/usr/local/lib \
	--with-libinjection-libraries=/home/coanor/git/github/libinjection/src \
	--with-libinjection-includes=/home/coanor/git/github/libinjection/src \
	CFLAGS="-O0 -g -g3" \

	#--enable-unittests 

