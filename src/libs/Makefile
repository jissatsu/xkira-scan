CC=gcc
RN=-Wall

lib:
	@if [ ! -e libxstr.a ]; then\
		$(CC) $(RN) -c xscan_str.c;\
		ar rcs libxstr.a xscan_str.o;\
	fi