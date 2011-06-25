#
#   PrivateKnockc - Companion client for the PrivateKnockd Project
#   Copyright (C) 2011 - Juan Gabriel Calderon-Perez
#   Website: https://github.com/jgcalderonperez/privateknockc
#   Written by Juan Gabriel Calderon-Perez
#
#   This file is part of privateknockc.
#
#   privateknockc is free software: you can redistribute it and/or modify
#   it under the terms of the GNU General Public License as published by
#   the Free Software Foundation, either version 3 of the License, or
#   (at your option) any later version.
#
#   privateknockc is distributed in the hope that it will be useful,
#   but WITHOUT ANY WARRANTY; without even the implied warranty of
#   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#   GNU General Public License for more details.
#
#   You should have received a copy of the GNU General Public License
#   along with privateknockc. If not, see http://www.gnu.org/licenses/.
#

# Variables
CC = gcc

CFLAGS = -m32 -g -O3 -W -Wall -std=gnu99 -pedantic -Wbad-function-cast \
-Wcast-align -Wcast-qual -Wchar-subscripts -Winline -Wmissing-prototypes \
-Wnested-externs -Wpointer-arith -Wredundant-decls -Wshadow \
-Wstrict-prototypes -Wwrite-strings -Wformat-nonliteral -Wformat-security \
-ftrapv -lrt -Wno-unused

HEADER = privateknockc.h
SOURCES = main.c privateknockc.c
OBJECTS = main.o privateknockc.o
EXECUTABLE = privateknockc

%.o: %.c $(HEADER)
	$(CC) -c -o $@ $< $(CFLAGS) \

$(EXECUTABLE): $(OBJECTS)
	gcc -o $@ $^ $(CFLAGS)
	
clean:
	rm -f *.o
	rm -f $(EXECUTABLE)
	

