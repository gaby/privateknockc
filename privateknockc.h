/*
#   UDP Portknocking Client with RSA Encryption
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
*/

#define DEBUG 1             /* Comment this line to disable terminal output */
#define RSA_ENCRYPTION 1    /* Comment this line to disable RSA Encryption */

#ifndef __PRIVATEKNOCK_CLIENT_H
#define	__PRIVATEKNOCK_CLIENT_H

#ifdef	__cplusplus
extern "C" {
#endif

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <limits.h>
#include <dirent.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <time.h>
#include <ctype.h>
#include <signal.h>
#include <stdarg.h>
#include <signal.h>
#include <syslog.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <netinet/in.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <netdb.h>

#define COPYRIGHT   "\n\
-----------------------------------------------------------------------------\n\
-------PrivateKnockC - Companion client for the PrivateKnockd Project--------\n\
-----------------------------------------------------------------------------\n\
Copyright (C) 2011 - Juan Gabriel Calderon-Perez\n\
Website: https://github.com/jgcalderonperez/privateknockc\n\
Written by Juan Gabriel Calderon-Perez\n\
\n\
PrivateKnockC is free software: you can redistribute it and/or modify\n\
it under the terms of the GNU General Public License as published by\n\
the Free Software Foundation, either version 3 of the License, or\n\
(at your option) any later version.\n\
\n\
PrivateKnockC is distributed in the hope that it will be useful,\n\
but WITHOUT ANY WARRANTY; without even the implied warranty of\n\
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the\n\
GNU General Public License for more details.\n\
\n\
You should have received a copy of the GNU General Public License\n\
along with PrivateKnockC. If not, see http://www.gnu.org/licenses/ \n\
-----------------------------------------------------------------------------\n"

#define PROGRAM_NAME             "privateknockc"
#define AUTHOR                   "Juan Gabriel Calderon-Perez"
#define VERSION                  "1.0.0-alpha"
#define DIVIDER "-------------------------------------------------------------"
#define TRANSACTION_DELAY 3               /* Delay for requesting new sequence */
#define LINE_LENGTH 80                    /* Default line length size */
#define IP_SIZE 16                        /* IP Address size including \0 */
#define PORT_SIZE 6                       /* Port Number size including \0 */
#define SEQUENCE_SIZE 4                   /* Portknocking Sequence Size */
#define RSA_PUBKEY_E 17                   /* RSA Public Key E component*/
#define RSA_PUBKEY_N 209                  /* RSA Public Key N component*/
#define RSA_Data unsigned long

    /* -----------------------------------------------------------------
        State and Global Variables
    ----------------------------------------------------------------- */

    /* Structure for RSA Public Key */
    typedef struct RsaPubKey {
        unsigned long e;                            /* RsaPubKey E */
        unsigned long n;                            /* RsaPubKey N */
    } RsaPubKey;
    
    /* Structure for PrivateKnock Client State */
    typedef struct pkc_state {
        char srv_address [IP_SIZE];                 /* Server IP Address */
        char srv_port [PORT_SIZE];                  /* Server listening port */
        char * config_file;                         /* Config file name */
        uint16_t sequence[SEQUENCE_SIZE];           /* Port Sequence */
        uint32_t transaction_delay;                 /* Transaction Delay in seconds */
    } pkc_state;
    
    /* -----------------------------------------------------------------
        Function definitions
     * ----------------------------------------------------------------- */

    /* State Functions */
    void initialize_state (pkc_state * s);
    void validate_state (pkc_state * s);
    void print_state (pkc_state * s);
    void free_state (pkc_state * s);
    void set_server_address (pkc_state * s, char * srv_address);
    void set_server_port (pkc_state * s, char * srv_port);
    void set_config_file (pkc_state * s, char * config_file);
    void set_transaction_delay (pkc_state * s, char * delay);

    /* Config File */
    void load_config_file (pkc_state * s);
    void update_config_file (pkc_state * s);
    
    /* Port Knocking */
    void knock_server (pkc_state * s);
    bool request_new_sequence (pkc_state * s);
    
    /* RSA Encryption Functions */
    void rsa_encipher (RSA_Data plaintext, RSA_Data * ciphertext, RsaPubKey pubkey);
    
    /* Helpers Functions */
    void chop (char * token);
    
    /* Other functions */
    void try_msg (void);
    void fatal_error (pkc_state * s, const char * message);
    void process_command_line (int argc, char **argv, pkc_state * s);
    void pkclient_help (void);
    void signal_handler (int signal);

#ifdef	__cplusplus
}
#endif

#endif	/* __PRIVATEKNOCK_CLIENT_H */

