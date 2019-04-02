#LINK_OPT = -g -L/usr/lib64/ -lssl 
LINK_OPT = -g -lcrypto -lpbc -lgmp  -L/usr/lib64/ -I/usr/local/src/pbc-0.5.14/include/

all:
	#g++ -g main.cpp -o test $(LINK_OPT)
	g++ -std=c++0x PMCQueryScheme.cpp -O1 -o PMCQueryScheme $(LINK_OPT)

clean:
	rm -f *.o
	rm -f PMCQueryScheme 
