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

void chop (char * token)
{
    register uint32_t len = strlen (token);

    if (token[len - 1] == 0x0a)
    {
        if (token[len - 2] == 0x0d)
        {
            token[len - 2] = token[len - 1];
        }
        token[len - 1] = token[len];
    }
}

void initialize_state (pkc_state * s)
{
    memset (s->srv_address, '\0', IP_SIZE * sizeof(char));
    memset (s->srv_port, '\0', PORT_SIZE * sizeof(char));
    s->config_file = NULL;
    memset (s->sequence, 0x0, SEQUENCE_SIZE * sizeof (uint16_t));
    s->transaction_delay = 5; /* Default if not define via argv */
}

void print_state (pkc_state * s)
{
    register uint16_t it;

    fprintf (stderr, "%s\n", DIVIDER);
    fprintf (stderr, "*-----PrivateKnock Client State-----*\n");
    fprintf (stderr, "srv_address: %s\n", s->srv_address);
    fprintf (stderr, "srv_port: %s\n", s->srv_port);
    fprintf (stderr, "config_file: %s\n", s->config_file);
    fprintf (stderr, "port sequence: ");
    
    for (it = 0x0; it < SEQUENCE_SIZE; it++)
    {
        fprintf (stderr, "%i ", s->sequence[it]);
    }
    fprintf (stderr, "\n%s\n", DIVIDER);
}

void free_state (pkc_state * s)
{
    if (s->config_file != NULL)
    {
        free (s->config_file);
    }
}

void set_server_address (pkc_state * s, char * srv_address)
{
    chop (srv_address); /* Removes \n from string! */
    strncpy (s->srv_address, srv_address, IP_SIZE * sizeof(char));
}

void set_server_port (pkc_state * s, char * srv_port)
{
    chop (srv_port); /* Removes \n from string! */
    strncpy (s->srv_port, srv_port, PORT_SIZE * sizeof(char));
}

void set_config_file (pkc_state * s, char * config_file)
{
    register uint32_t argv_size = strlen(config_file);

    if((s->config_file = (char*)malloc (argv_size * sizeof(char))) != NULL)
    {
        chop (config_file); /* Removes \n from string! */
        strncpy (s->config_file, config_file, argv_size);
    }
    else
    {
        fatal_error (s, "No configuration file specified");
    }
}

void set_transaction_delay (pkc_state * s, char * delay)
{
    if (strtoul(delay, NULL, 10) < UINT32_MAX)
    {
        s->transaction_delay = strtoul(delay, NULL, 10);
    }
    else
    {
        fatal_error (s, "Invalid transaction delay value");
    }
}

void validate_state (pkc_state * s)
{
    if (s->config_file == NULL)
    {
        fatal_error (s, "No configuration file specified");
    }
    else
        if (s->srv_port[0] == '\0')
        {
            fatal_error (s, "No server port specified");
        }
        else
            if (s->srv_address[0] == '\0')
            {
                fatal_error (s, "No server address file specified");
            }
}

void load_config_file (pkc_state * s)
{
    FILE * fd = NULL;
    register uint32_t it;
    
    if (s->config_file == NULL)
    {
        fatal_error (s, "No configuration file specified");
    }
    
    /* Open configuration file for reading */
    if ((fd = fopen (s->config_file, "r")) == NULL)
    {
        fatal_error (s, "Config file cannot be open or not found.");
    }
    else
    {
    
#ifdef DEBUG
        fprintf (stderr, "Reading configuration file.\n");
#endif 

        /* Reading Port Sequence from Config File */
        for (it = 0; it < SEQUENCE_SIZE; it++)
        {
            if (fscanf (fd, "%hud", &s->sequence[it]) != 1)
            {
                fatal_error (s, "Loading sequence from config file.");
            }
        } 
        fclose (fd);
    }
}

void update_config_file (pkc_state *s)
{
    FILE * fd = NULL;
    register uint16_t it;
    
    if (s->config_file == NULL)
    {
        fatal_error (s, "No configuration file specified");
    }
    
    /* Open configuration file for writing */
    if ((fd = fopen (s->config_file, "w")) == NULL)
    {
        fatal_error (s, "Config file cannot be open or not found.");
    }
    else
    {
#ifdef DEBUG
        fprintf (stderr, "Updating configuration file.\n");
#endif    
    
        /* Write new port sequence to Config File */
        for (it = 0x0; it < SEQUENCE_SIZE; it++)
        {
            fprintf (fd, "%i ", s->sequence[it]);
        } 
        fclose (fd);
    }
}

void rsa_encipher (RSA_Data plaintext, RSA_Data * ciphertext, RsaPubKey pubkey)
{
    *ciphertext = 1;

    while (pubkey.e != 0) 
    {
        if (pubkey.e & 1) /* For each 1 in b */
        {
            *ciphertext = (*ciphertext * plaintext) % pubkey.n;
        }

        /* Compute pow for each bit */
        plaintext = (plaintext * plaintext) % pubkey.n;

        /* Shift to next bit */
        pubkey.e >>= 1;
    }
    return;
}

void knock_server (pkc_state * s)
{
    register uint16_t it;                               /* Iterator */
    int sockfd, n;                                      /* Server Socket */
    struct sockaddr_in srv_addr;                        /* Server sockaddr struct */
    uint32_t srv_len = sizeof (struct sockaddr_in);     /* Srv_addr length */
    char buffer [LINE_LENGTH];                          /* Packet Data */
    
#ifdef RSA_ENCRYPTION                                   /* Data for RSA Encryption */
    struct RsaPubKey pkc_pubkey;                        /* RSA Public Key Struct */
    RSA_Data packet_encrypt;                            /* Encrypted Data */
    pkc_pubkey.e = RSA_PUBKEY_E;                        /* RSA Public Key E component*/
    pkc_pubkey.n = RSA_PUBKEY_N;                        /* RSA Public Key N component*/
#endif
    
    if ((sockfd = socket (AF_INET, SOCK_DGRAM, 0)) < 0)
    {
        fatal_error (s, "Opening server socket.");
    }
    
    memset ((char *)&srv_addr, '\0', sizeof (srv_addr));
    srv_addr.sin_family = AF_INET;
    
    if (inet_aton (s->srv_address, &srv_addr.sin_addr) == 0) /* Assign IP Address */
    {
        fatal_error (s, "Invalid server address.");
    }
    
    /* Send Port Knocks to Server */
    for (it = 0; it < SEQUENCE_SIZE; it++)
    {
        memset (buffer, '\0', LINE_LENGTH * sizeof (char));
        srv_addr.sin_port = htons (s->sequence[it]); /* Assign Port from Sequence*/
    
#ifdef RSA_ENCRYPTION
        rsa_encipher ((RSA_Data)s->sequence[it], &packet_encrypt, pkc_pubkey);
        sprintf (buffer, "%lu", packet_encrypt);
#endif /* RSA_ENCRYPTION */

#ifdef DEBUG
        fprintf (stderr, "Sending Knock #: %i, Port: %i\n", it, s->sequence[it]);
#endif
    
        if ((n = sendto (sockfd, buffer, strlen (buffer), 0, 
                         (const struct sockaddr *)&srv_addr, srv_len)) < 0)
        {
            fatal_error (s, "Sending knock to server.");
        }
        sleep (1); /* Delay for avoiding packet loss */
    }
    close (sockfd);
}

bool request_new_sequence (pkc_state *s)
{
    register uint16_t it;                               /* Iterator */
    int sockfd, n;                                      /* Server Socket */
    struct timeval tv;                                  /* For timeout */
    struct sockaddr_in srv_addr;                        /* Server sockaddr struct */
    char * token;                                       /* For strtok */
    const char * delim = " ";                           /* Delimiter */
    char buffer [PORT_SIZE * SEQUENCE_SIZE + 1];        /* Holds new port sequence */
    
    if ((sockfd = socket (AF_INET, SOCK_STREAM, 0)) < 0)
    {
        fatal_error (s, "Opening server socket.");
    }
    
    /* Set socket recv/send timeout */
    tv.tv_sec = 5;
    tv.tv_usec = 0;
    if (setsockopt (sockfd, SOL_SOCKET, SO_RCVTIMEO, (char*)&tv, sizeof(struct timeval)))
    {
        fatal_error (s, "Setting socket options.");
    }
    
    if (setsockopt (sockfd, SOL_SOCKET, SO_SNDTIMEO, (char*)&tv, sizeof(struct timeval)))
    {
        fatal_error (s, "Setting socket options.");
    }
    
    memset ((char *)&srv_addr, '\0', sizeof (srv_addr));
    srv_addr.sin_family = AF_INET;
    srv_addr.sin_port = htons (atoi (s->srv_port)); /* Assign Port Number */
    
    if (inet_aton (s->srv_address, &srv_addr.sin_addr) == 0) /* Assign IP Address */
    {
        fatal_error (s, "Invalid server address.");
    }
    
#ifdef DEBUG
    fprintf (stderr, "Requesting new sequence from server: %s\n", s->srv_address);
#endif
    
    if (connect (sockfd, (struct sockaddr *) &srv_addr, sizeof (srv_addr)) < 0)
    {
        fatal_error (s, "Connecting to server.");
    }
    
    memset (buffer, '\0', PORT_SIZE * SEQUENCE_SIZE + 1);
    
    if ((n = recv(sockfd, buffer, PORT_SIZE * SEQUENCE_SIZE + 1, MSG_DONTWAIT)) < 0)
    {
        fatal_error (s, "Reading from socket.");
    }
    
    close (sockfd);
    
    if (strlen (buffer) != 0)
    {
#ifdef DEBUG
        fprintf (stderr, "Request Accepted, new sequence: %s\n", buffer);
#endif

        /* Now lets extract the new sequence from buffer */
        token = strtok (buffer, delim);
        
        for (it = 0x0; it < SEQUENCE_SIZE; it++)
        {
            s->sequence[it] = atoi (token);
            token = strtok (NULL, delim);
        } 
        return true;
    }
    else
    {
#ifdef DEBUG
        fprintf (stderr, "New sequence request failed.\n");
#endif
        return false;
    }
}




