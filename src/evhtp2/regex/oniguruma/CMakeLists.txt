CONFIGURE_FILE(
	${CMAKE_CURRENT_SOURCE_DIR}/config.h.in
	${EVHTP_DEPS_INSTALL}/include/evhtp2/regex/oniguruma/oniguruma-config.h
)

set(O_SOURCES regint.h regparse.h regenc.h st.h
regerror.c regparse.c regext.c regcomp.c regexec.c reggnu.c
regenc.c regsyntax.c regtrav.c regversion.c st.c
regposix.c regposerr.c
enc/unicode.c enc/ascii.c enc/utf8.c
enc/utf16_be.c enc/utf16_le.c
enc/utf32_be.c enc/utf32_le.c
enc/euc_jp.c enc/sjis.c enc/iso8859_1.c
enc/iso8859_2.c  enc/iso8859_3.c
enc/iso8859_4.c  enc/iso8859_5.c
enc/iso8859_6.c  enc/iso8859_7.c
enc/iso8859_8.c  enc/iso8859_9.c
enc/iso8859_10.c enc/iso8859_11.c
enc/iso8859_13.c enc/iso8859_14.c
enc/iso8859_15.c enc/iso8859_16.c
enc/euc_tw.c enc/euc_kr.c enc/big5.c
enc/gb18030.c enc/koi8_r.c enc/cp1251.c)

add_target_sources(libevhtp ${O_SOURCES})
