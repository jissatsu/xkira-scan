CC=gcc
RN=-Wall
LIBS=-lnet -lpthread -lpcap -lxstr
LDIR=-Lsrc/libs
ODIR=src/obj
DEBUG=-DDEBUG
EXECPATH=/usr/bin
EXEC=kira-scan

obj:
	$(CC) $(RN) -c src/main.c -o $(ODIR)/main.o -DDEBUG
	$(CC) $(RN) -c src/banner.c -o $(ODIR)/banner.o -DDEBUG
	$(CC) $(RN) -c src/kira-scan.c -o $(ODIR)/kira-scan.o -DDEBUG
	$(CC) $(RN) -c src/init.c -o $(ODIR)/init.o -DDEBUG
	$(CC) $(RN) -c src/xscan_sniffer.c -o $(ODIR)/xscan_sniffer.o -DDEBUG
	$(CC) $(RN) -c src/stats.c -o $(ODIR)/stats.o -DDEBUG
	$(CC) $(RN) -c src/sleep.c -o $(ODIR)/sleep.o -DDEBUG
	$(CC) $(RN) -c src/net.c -o $(ODIR)/net.o -DDEBUG
	$(CC) $(RN) -c src/output/output.c -o $(ODIR)/output.o -DDEBUG

all:
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
	$(LIBS) $(LDIR);

	chmod +x $(EXECPATH)/$(EXEC)

clean:
	rm -f $(ODIR)/*.o
