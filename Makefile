
CFLAGS	= -Wall -O2
APPS	= pam-test

all: $(APPS)

pam-test: pam-test.o
	$(CC) -o $@ pam-test.o -lpam

clean:
	rm -f *.o $(APPS)
