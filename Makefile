CC=gcc
RN=-Wall
LIBS=-lnet -lpthread -lpcap -lxstr
LDIR=src/libs
LIBDIR=/usr/local/include
ODIR=obj
EXECPATH=/usr/bin
EXEC=kira-scan

ifeq ($(DEBUG),1)
	override DEBUG=-DDEBUG
else
	override DEBUG=
endif

build:
	chmod +x build.sh
	./build.sh

objs:
	@if [ ! -d $(ODIR) ]; then\
		mkdir $(ODIR);\
	fi

	$(CC) $(RN) -c src/main.c -o $(ODIR)/main.o $(DEBUG)
	$(CC) $(RN) -c src/banner.c -o $(ODIR)/banner.o $(DEBUG)
	$(CC) $(RN) -c src/kira-scan.c -o $(ODIR)/kira-scan.o $(DEBUG)
	$(CC) $(RN) -c src/init.c -o $(ODIR)/init.o $(DEBUG)
	$(CC) $(RN) -c src/xscan_sniffer.c -o $(ODIR)/xscan_sniffer.o $(DEBUG)
	$(CC) $(RN) -c src/stats.c -o $(ODIR)/stats.o $(DEBUG)
	$(CC) $(RN) -c src/sleep.c -o $(ODIR)/sleep.o $(DEBUG)
	$(CC) $(RN) -c src/net.c -o $(ODIR)/net.o $(DEBUG)
	$(CC) $(RN) -c src/output/output.c -o $(ODIR)/output.o $(DEBUG)

all:
	make -C $(LDIR) lib
	make build;
	make objs;
	$(CC) $(RN) \
	$(ODIR)/main.o \
	$(ODIR)/banner.o \
	$(ODIR)/kira-scan.o \
	$(ODIR)/init.o \
	$(ODIR)/xscan_sniffer.o \
	$(ODIR)/stats.o \
	$(ODIR)/sleep.o \
	$(ODIR)/net.o \
	$(ODIR)/output.o \
	-o $(EXECPATH)/$(EXEC) \
	$(LIBS) \
	-L$(LDIR) \
	-I$(LIBDIR);

	chmod +x $(EXECPATH)/$(EXEC)

clean:
	rm -f $(ODIR)/*.o

.PHONY: objs, build, all, clean