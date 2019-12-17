CC=gcc
RN=-Wall
LIBS=-lnet -lpthread -lpcap -lxstr
LDIR=src/libs
ODIR=obj
DEBUG=-DDEBUG
EXECPATH=/usr/bin
EXEC=kira-scan

objs:
	@if [ ! -d $(ODIR) ]; then\
		mkdir $(ODIR);\
	fi

	$(CC) $(RN) -c src/main.c -o $(ODIR)/main.o
	$(CC) $(RN) -c src/banner.c -o $(ODIR)/banner.o
	$(CC) $(RN) -c src/kira-scan.c -o $(ODIR)/kira-scan.o
	$(CC) $(RN) -c src/init.c -o $(ODIR)/init.o
	$(CC) $(RN) -c src/xscan_sniffer.c -o $(ODIR)/xscan_sniffer.o
	$(CC) $(RN) -c src/stats.c -o $(ODIR)/stats.o
	$(CC) $(RN) -c src/sleep.c -o $(ODIR)/sleep.o
	$(CC) $(RN) -c src/net.c -o $(ODIR)/net.o
	$(CC) $(RN) -c src/output/output.c -o $(ODIR)/output.o

all:
	make -C $(LDIR) lib
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
	$(LIBS) -L$(LDIR);

	chmod +x $(EXECPATH)/$(EXEC)

clean:
	rm -f $(ODIR)/*.o

.PHONY: objs, all, clean