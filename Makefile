# Universidad Nacional Autónoma de México
# SSI/UNAM-CERT
# Plan de Becarios de Seguridad en Cómputo
# Octava Generación
# Project
# Makefile traffgen
# Compile: make
# Install: make install
# Uninstall: make clean
# Zamora Parra Zocoyotzin
# xzamora@bec.seguridad.unam.mx
# Tovar Balderas Sergio Anduin
# stovar@bec.seguridad.unam.mx

CC = gcc
SRC = traffgen.c
OBJ = traffgen
INSTALL=/usr/bin/install
BIN=/usr/local/bin
PERM = 755
USER = root
GROUP = root
OUT=bin/$(OBJ)
SRCMAN1 = traffgen.1
MAN1=/usr/local/man/man1

all: $(OBJ)
	$(CC) $(SRC) -o $(OBJ) 

install: traffgen
	$(INSTALL) -d $(BIN)
	$(INSTALL) -s -m $(PERM) -o $(USER) -g $(GROUP) $(OBJ) $(BIN)/$(OBJ)
	$(INSTALL) -d $(MAN1)
	$(INSTALL) -m $(PERM) $(SRCMAN1) $(MAN1)/$(SRCMAN1)

clean:
	rm -f $(OBJ)
	rm -f $(BIN)/$(OBJ)
	rm -f $(MAN1)/$(SRCMAN1)
