COMPILER         = g++
OPTIMIZATION_OPT = -O1
OPTIONS          =  -w -std=c++0x $(OPTIMIZATION_OPT) -g -o 
LINKER_OPT       =  -L/usr/lib64/ -lcrypto -lpbc -lgmp 
INCLUDE_OPT	 = 	-I./include -I/usr/local/src/pbc-0.5.14/include/ 
SRC_FILE	 = ./*.cpp
BIN_DIR		 = .
TARGET		 = PMCQueryScheme

BUILD_LIST = $(BIN_DIR)/$(TARGET)

all: $(BUILD_LIST)

$(BUILD_LIST):$(SRC_FILE)
	$(COMPILER)  $(OPTIONS) $(BUILD_LIST) $(SRC_FILE) $(INCLUDE_OPT) $(LINKER_OPT) 

strip_bin :
	strip -s PMCQueryScheme

clean:
	rm -f $(BIN_DIR)/PMCQueryScheme 

