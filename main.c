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

#include "privateknockc.h"

void signal_handler (int current_signal)
{
    fprintf (stderr, "Caught signal %d \n", current_signal);
    syslog (LOG_ERR, "Caught signal %d \n", current_signal);
    closelog (); /* Closing System log */
    exit (0);
}

void try_msg (void)
{
    fprintf (stderr, "Try `%s -h` for more information.\n", PROGRAM_NAME);
}

void fatal_error (pkc_state * s, const char * message)
{
#ifdef DEBUG
    printf ("[*] Fatal Error: %s\n", message);
#endif

    syslog (LOG_ERR, "[*] Fatal Error: %s", message);
    closelog ();    /* Closing System log */
    free_state (s); /* free allocated memory */             
    
    exit (EXIT_FAILURE);
}

void pkclient_help (void)
{
    fprintf (stderr, "%s\n", DIVIDER);
    fprintf (stderr, "\n*-----PrivateKnock Client Help-----*\n\n");
    fprintf (stderr, "$ %s ", PROGRAM_NAME);
    fprintf (stderr, "[-V|-h [-s srv_address] [-p srv_port] [-c filename.conf] ]\n");
    fprintf (stderr, "\t -v  display copyright information.\n");
    fprintf (stderr, "\t -s  specify server address.\n");
    fprintf (stderr, "\t -p  specify server port number.\n");
    fprintf (stderr, "\t -c  specify configuration file.\n");
    fprintf (stderr, "\t -d  specify transaction delay (seconds).\n");
    fprintf (stderr, "%s Ver. %s \nBy %s\n", PROGRAM_NAME, VERSION, AUTHOR);
    fprintf (stderr, "%s\n\n", DIVIDER);
}

void process_command_line (int argc, char **argv, pkc_state * s)
{
    register int32_t i = 0x0;

    while ((i = getopt (argc, argv, "s:p:c:d:hv") ) != -1)
    {
        switch (i)
        {
            case 's':
                set_server_address (s, optarg);
                break;
            
            case 'p':
                set_server_port (s, optarg);
                break;

            case 'c':
                set_config_file (s, optarg);
                break;
                
            case 'h':
                pkclient_help ();
                exit (EXIT_SUCCESS);
            case 'd':
                set_transaction_delay (s, optarg);
                break;

            case 'v':
                fprintf (stderr, "%s", COPYRIGHT);
                exit (EXIT_SUCCESS);

            default:
                try_msg ();
                exit (EXIT_FAILURE);
        }
    }
}

int main (int argc, char **argv)
{
    struct pkc_state s;
    struct pkc_state * ptr_s = &s;

    /* Opening system log */
    openlog (PROGRAM_NAME, 0, LOG_AUTH);

    /* Registering Signal Handlers */
    signal (SIGKILL, (sighandler_t) signal_handler);
    signal (SIGINT, (sighandler_t) signal_handler);
    signal (SIGSTOP, (sighandler_t) signal_handler);
    
    initialize_state (ptr_s);
    
    process_command_line (argc, argv, ptr_s);

    validate_state (ptr_s);

    load_config_file (ptr_s);

#ifdef DEBUG
    print_state (ptr_s); /* Just for debugging */
#endif
    
    /* Sending UDP sequence to server */
    knock_server (ptr_s); 
    
    /* Transaction Delay */
    sleep (TRANSACTION_DELAY); /* Time between portknocking and requesting new sequence */
    /* Transaction Delay Ends */
    
    /* Request new sequence to server */
    if (request_new_sequence (ptr_s) == true)
    {
        /* Update configuration file with new port sequence */
        update_config_file (ptr_s);
    }
    
    free_state (ptr_s); /* Free allocated memory */

    closelog (); /* Closing system log */

    return (EXIT_SUCCESS);
}
