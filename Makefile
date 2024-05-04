# Flags for compilation
OPTIM_FLAGS = -O0 -O1 -O2 -O3
DEBUG_FLAGS = -g -Wall
PROD_FLAGS = -s
THREAD_FLAGS = -lpthread
SODIUM_FLAGS = -lsodium
MYSQL_FLAGS = -lmysqlclient
# Define source directory
SRC = src

# Define build directory
BIN = bin

# Build all the executables and link in production mode
all-prod: base-prod security-prod database-prod request-prod network-prod init-prod main-prod
	@echo "Linking final app"
	gcc -o $(BIN)/server $(BIN)/main.o $(BIN)/init.o $(BIN)/network.o $(BIN)/request.o $(BIN)/database.o $(BIN)/security.o $(BIN)/base.o $(PROD_FLAGS) $(MYSQL_FLAGS) $(SODIUM_FLAGS) $(THREAD_FLAGS)
	@chmod 100 $(BIN)/server
	@echo "done"

# Build all the executables and link in debug mode
all-debug: base-debug security-debug database-debug request-debug network-debug init-debug main-debug
	@echo "Linking final app"
	gcc -o $(BIN)/final $(BIN)/main.o $(BIN)/init.o $(BIN)/network.o $(BIN)/request.o $(BIN)/database.o $(BIN)/security.o $(BIN)/base.o $(DEBUG_FLAGS) $(MYSQL_FLAGS) $(SODIUM_FLAGS) $(THREAD_FLAGS)
	@chmod +x $(BIN)/final
	@echo "done"

# Compile main.c
main-prod: $(SRC)/main.c
	@echo "Compiling main file"
	gcc $(PROD_FLAGS) -c $(SRC)/main.c -o $(BIN)/main.o

# Compile main.c in debug mode
main-debug: $(SRC)/main.c
	@echo "Compiling main file in debug mode"
	gcc $(DEBUG_FLAGS) -c $(SRC)/main.c -o $(BIN)/main.o

# Compile init.c
init-prod: $(SRC)/init.c
	@echo "Compiling init file"
	gcc $(PROD_FLAGS) -c $(SRC)/init.c -o $(BIN)/init.o

# Compile init.c in debug mode
init-debug: $(SRC)/init.c
	@echo "Compiling init file in debug mode"
	gcc $(DEBUG_FLAGS) -c $(SRC)/init.c -o $(BIN)/init.o

# Compile network.c
network-prod: $(SRC)/network.c
	@echo "Compiling network file"
	gcc $(PROD_FLAGS) -c $(SRC)/network.c -o $(BIN)/network.o

# Compile network.c in debug mode
network-debug: $(SRC)/network.c
	@echo "Compiling network file in debug mode"
	gcc $(DEBUG_FLAGS) -c $(SRC)/network.c -o $(BIN)/network.o

# Compile request.c
request-prod: $(SRC)/request.c
	@echo "Compiling request file"
	gcc $(PROD_FLAGS) -c $(SRC)/request.c -o $(BIN)/request.o

# Compile request.c in debug mode
request-debug: $(SRC)/request.c
	@echo "Compiling request file in debug mode"
	gcc $(DEBUG_FLAGS) -c $(SRC)/request.c -o $(BIN)/request.o

# Compile database.c
database-prod: $(SRC)/database.c
	@echo "Compiling database file"
	gcc $(PROD_FLAGS) -c $(SRC)/database.c -o $(BIN)/database.o

# Compile database.c in debug mode
database-debug: $(SRC)/database.c
	@echo "Compiling database file in debug mode"
	gcc $(DEBUG_FLAGS) -c $(SRC)/database.c -o $(BIN)/database.o

# Compile security.c
security-prod: $(SRC)/security.c
	@echo "Compiling security file"
	gcc $(PROD_FLAGS) -c $(SRC)/security.c -o $(BIN)/security.o

# Compile security.c in debug mode
security-debug: $(SRC)/security.c
	@echo "Compiling security file in debug mode"
	gcc $(DEBUG_FLAGS) -c $(SRC)/security.c -o $(BIN)/security.o

# Compile base.c
base-prod: $(SRC)/base.c
	@echo "Compiling base file"
	gcc $(PROD_FLAGS) -c $(SRC)/base.c -o $(BIN)/base.o

# Compile base.c in debug mode
base-debug: $(SRC)/base.c
	@echo "Compiling base file in debug mode"
	gcc $(DEBUG_FLAGS) -c $(SRC)/base.c -o $(BIN)/base.o

# Help section
help:
	@echo "Usage: make [target]"
	@echo ""
	@echo "Targets:"
	@echo "  all-prod        Build all executables in production mode"
	@echo "  all-debug       Build all executables in debug mode"
	@echo "  main-prod       Compile main.c in production mode"
	@echo "  main-debug      Compile main.c in debug mode"
	@echo "  init-prod       Compile init.c in production mode"
	@echo "  init-debug      Compile init.c in debug mode"
	@echo "  network-prod    Compile network.c in production mode"
	@echo "  network-debug   Compile network.c in debug mode"
	@echo "  request-prod    Compile request.c in production mode"
	@echo "  request-debug   Compile request.c in debug mode"
	@echo "  database-prod   Compile database.c in production mode"
	@echo "  database-debug  Compile database.c in debug mode"
	@echo "  security-prod   Compile security.c in production mode"
	@echo "  security-debug  Compile security.c in debug mode"
	@echo "  base-prod       Compile base.c in production mode"
	@echo "  base-debug      Compile base.c in debug mode"
	@echo "  clean           Clean up object files"
	@echo "  help            Display this help message"


# Clean up object files
clean:
	@echo "Cleaning up .o files"
	rm -f $(BIN)/*.o
