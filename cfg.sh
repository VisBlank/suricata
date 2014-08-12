#./configure --enable-debug \
#	--enable-nfqueue \
#	--enable-non-bundled-htp \
#	--with-libhtp-includes=/usr/local/include/htp \
#	--with-libhtp-libraries=/usr/local/lib

./autogen.sh
./configure --enable-debug \
	--enable-nfqueue \
	--enable-lua \
	--enable-non-bundled-htp \
	--with-libhtp-includes=/usr/local/include/htp \
	--with-libhtp-libraries=/usr/local/lib \
	--with-libjansson-includes=/usr/local/include \
	--with-libjansson-libraries=/usr/local/lib \
	--with-libinjection-libraries=/usr/local/lib \
	--with-libinjection-includes=/usr/local/include \
	--with-libndpi-libraries=/usr/local/lib \
	--with-libndpi-includes=/usr/local/include/libndpi-1.4.99/libndpi \
	--with-liblua-includes=/usr/include/lua5.1 \
	--with-liblua-libraries=/usr/lib/i386-linux-gnu \
	#--enable-unittests 

make
