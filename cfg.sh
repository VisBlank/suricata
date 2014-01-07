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
    --enable-unittests 
