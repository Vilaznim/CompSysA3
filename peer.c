#include <stdlib.h>
#include <stdio.h>
#include <math.h>
#include <netdb.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <string.h>
#include <time.h>

#ifdef __APPLE__
#include "./endian.h"
#else
#include <endian.h>
#endif

#include "./peer.h"

// prototypes for functions used only in this file
void get_signature(const void *password, int password_len, const char *salt, hashdata_t hash_out);
int send_register_message(const NetworkAddress_t *peer_address);
int parse_and_store_peer_list(const char *body, uint32_t body_len);
int send_retrieve_message(const NetworkAddress_t *peer_address, const char *filename);

/* Prototypes for newly added helpers (INFORM, error handling, concurrency helpers) */
int send_inform_to_network(const NetworkAddress_t *new_peer, const char *exclude_ip, uint32_t exclude_port);
int handle_inform_message(int connfd, uint32_t body_len);
int send_error_response(int connfd, uint32_t status, const char *msg);

void initialize_my_address(const char *my_ip, uint32_t my_port);
void network_init(void);
int network_add_peer(const NetworkAddress_t *addr);    /* returns 0 on success, -1 on error */
int network_find_index(const char *ip, uint32_t port); /* -1 if not found */

// Global variables to be used by both the server and client side of the peer.
// Note the addition of mutexs to prevent race conditions.
NetworkAddress_t *my_address;

NetworkAddress_t **network = NULL;
uint32_t peer_count = 0;
pthread_mutex_t network_mutex = PTHREAD_MUTEX_INITIALIZER;

/*
 * Function to act as thread for all required client interactions. This thread
 * will be run concurrently with the server_thread. It will start by requesting
 * the IP and port for another peer to connect to. Once both have been provided
 * the thread will register with that peer and expect a response outlining the
 * complete network. The user will then be prompted to provide a file path to
 * retrieve. This file request will be sent to a random peer on the network.
 * This request/retrieve interaction is then repeated forever.
 */
void *client_thread()
{
    char peer_ip[IP_LEN];
    fprintf(stdout, "Enter peer IP to connect to: ");
    fflush(stdout);
    if (!fgets(peer_ip, sizeof(peer_ip), stdin))
    {
        return NULL;
    }
    peer_ip[strcspn(peer_ip, "\n")] = '\0';

    // Clean up password string as otherwise some extra chars can sneak in.
    for (int i = strlen(peer_ip); i < IP_LEN; i++)
    {
        peer_ip[i] = '\0';
    }

    char peer_port[PORT_STR_LEN];
    fprintf(stdout, "Enter peer port to connect to: ");
    fflush(stdout);
    if (!fgets(peer_port, sizeof(peer_port), stdin))
    {
        return NULL;
    }
    peer_port[strcspn(peer_port, "\n")] = '\0';

    // Clean up password string as otherwise some extra chars can sneak in.
    for (int i = strlen(peer_port); i < PORT_STR_LEN; i++)
    {
        peer_port[i] = '\0';
    }

    NetworkAddress_t peer_address;
    memcpy(peer_address.ip, peer_ip, IP_LEN);
    peer_address.port = atoi(peer_port);

    /* Register with the bootstrap peer to get the network list */
    if (send_register_message(&peer_address) == 0)
    {
        fprintf(stdout, "Registration succeeded — got peer list; peer_count=%u\n", peer_count);
    }
    else
    {
        fprintf(stdout, "Registration failed\n");
    }

    /* Now prompt user for file(s) to retrieve from the network. This loop
     * will ask for a filename, then attempt to retrieve it from each known
     * peer (skipping ourselves) until one succeeds (exhaustive search). */
    char filepath[PATH_LEN];
    while (1)
    {
        fprintf(stdout, "Enter path of file to retrieve (or Ctrl-D to quit): ");
        fflush(stdout);
        if (!fgets(filepath, sizeof(filepath), stdin))
            break;
        filepath[strcspn(filepath, "\n")] = '\0';
        if (strlen(filepath) == 0)
            continue;

        /* copy the list of known peers under lock so we don't hold the lock while blocking */
        pthread_mutex_lock(&network_mutex);
        uint32_t n_peers = peer_count;
        if (n_peers == 0)
        {
            pthread_mutex_unlock(&network_mutex);
            fprintf(stdout, "No peers known to request from\n");
            continue;
        }

        NetworkAddress_t *cands = malloc(n_peers * sizeof(NetworkAddress_t));
        uint32_t cand_count = 0;
        for (uint32_t i = 0; i < n_peers; ++i)
        {
            if (strncmp(network[i]->ip, my_address->ip, IP_LEN) == 0 && network[i]->port == my_address->port)
                continue;
            cands[cand_count++] = *network[i];
        }
        pthread_mutex_unlock(&network_mutex);

        if (cand_count == 0)
        {
            free(cands);
            fprintf(stdout, "No remote peers available to request from\n");
            continue;
        }

        int got_it = 0;
        for (uint32_t i = 0; i < cand_count; ++i)
        {
            NetworkAddress_t *peer = &cands[i];
            fprintf(stdout, "Attempting retrieve from %s:%u ...\n", peer->ip, peer->port);
            if (send_retrieve_message(peer, filepath) == 0)
            {
                fprintf(stdout, "Retrieve succeeded from %s:%u\n", peer->ip, peer->port);
                got_it = 1;
                break;
            }
            else
            {
                fprintf(stdout, "No file at %s:%u, trying next peer\n", peer->ip, peer->port);
            }
        }
        free(cands);

        if (!got_it)
        {
            fprintf(stderr, "Retrieve failed: file not found on any known peer\n");
        }
    }

    printf("Client thread exiting\n");
    return NULL;
}

/*
 * Function to act as basis for running the server thread. This thread will be
 * run concurrently with the client thread, but is infinite in nature.
 *
 * TESTING NOTE: This is a minimal implementation to accept connections and
 * dispatch to handlers. In a full solution, you would:
 * - Loop infinitely accepting connections
 * - Spawn per-connection handlers (or use accept in a loop)
 * - Properly handle COMMAND_REGISTER, COMMAND_INFORM, COMMAND_RETRIEVE
 * - Validate all inputs before processing
 *
 * For now, we just listen and accept one connection for testing purposes.
 * Remove this stub and replace with full implementation before final submission.
 */
void *server_thread()
{
    char port_str[PORT_STR_LEN];
    snprintf(port_str, sizeof(port_str), "%u", my_address->port);

    fprintf(stdout, "[SERVER] Starting listener on port %s\n", port_str);
    int listenfd = compsys_helper_open_listenfd(port_str);
    if (listenfd < 0)
    {
        fprintf(stderr, "[SERVER] Failed to open listening socket\n");
        return NULL;
    }

    fprintf(stdout, "[SERVER] Listening; waiting for incoming connections...\n");

    /* Accept connections in loop */
    while (1)
    {
        struct sockaddr_storage clientaddr;
        socklen_t clientlen = sizeof(clientaddr);
        int connfd = accept(listenfd, (struct sockaddr *)&clientaddr, &clientlen);
        if (connfd < 0)
        {
            fprintf(stderr, "[SERVER] accept failed: %s\n", strerror(errno));
            continue;
        }

        fprintf(stdout, "[SERVER] Accepted connection\n");

        /* Read request header */
        unsigned char header[REQUEST_HEADER_LEN];
        if (compsys_helper_readn(connfd, header, REQUEST_HEADER_LEN) != REQUEST_HEADER_LEN)
        {
            fprintf(stderr, "[SERVER] Failed to read request header\n");
            close(connfd);
            continue;
        }

        /* Parse header */
        unsigned char *p = header;
        char ip[IP_LEN];
        memset(ip, 0, IP_LEN);
        memcpy(ip, p, IP_LEN);
        p += IP_LEN;

        uint32_t port = ntohl(*(uint32_t *)p);
        p += 4;
        hashdata_t sig;
        memcpy(sig, p, SHA256_HASH_SIZE);
        p += SHA256_HASH_SIZE;
        uint32_t command = ntohl(*(uint32_t *)p);
        p += 4;
        uint32_t body_len = ntohl(*(uint32_t *)p);

        fprintf(stdout, "[SERVER] Received: cmd=%u, ip=%s, port=%u, len=%u\n",
                command, ip, port, body_len);

        /* Validate inputs */
        if (!is_valid_ip(ip))
        {
            fprintf(stderr, "[SERVER] Invalid IP: %s\n", ip);
            send_error_response(connfd, STATUS_BAD_REQUEST, "Invalid IP");
            close(connfd);
            continue;
        }

        if (!is_valid_port(port))
        {
            fprintf(stderr, "[SERVER] Invalid port: %u\n", port);
            send_error_response(connfd, STATUS_BAD_REQUEST, "Invalid port");
            close(connfd);
            continue;
        }

        if (command != COMMAND_REGISTER && command != COMMAND_INFORM && command != COMMAND_RETREIVE)
        {
            fprintf(stderr, "[SERVER] Unknown command: %u\n", command);
            send_error_response(connfd, STATUS_BAD_REQUEST, "Unknown command");
            close(connfd);
            continue;
        }

        /* Dispatch based on command */
        if (command == COMMAND_REGISTER)
        {
            fprintf(stdout, "[SERVER] Handling REGISTER from %s:%u\n", ip, port);

            /* compute server salt and stored signature = SHA(client_signature || salt) */
            char server_salt[SALT_LEN];
            generate_random_salt(server_salt);

            unsigned char combined[SHA256_HASH_SIZE + SALT_LEN];
            memcpy(combined, sig, SHA256_HASH_SIZE);
            memcpy(combined + SHA256_HASH_SIZE, server_salt, SALT_LEN);
            hashdata_t stored_sig;
            get_data_sha(combined, stored_sig, SHA256_HASH_SIZE + SALT_LEN, SHA256_HASH_SIZE);

            /* build new peer record */
            NetworkAddress_t newpeer;
            memset(&newpeer, 0, sizeof(newpeer));
            memcpy(newpeer.ip, ip, IP_LEN);
            newpeer.port = port;
            memcpy(newpeer.salt, server_salt, SALT_LEN);
            memcpy(newpeer.signature, stored_sig, SHA256_HASH_SIZE);

            if (network_add_peer(&newpeer) != 0)
            {
                /* failed to add: send error reply */
                send_error_response(connfd, STATUS_OTHER, "Failed to add peer");
            }
            else
            {
                /* build reply body: copy current network entries under lock */
                pthread_mutex_lock(&network_mutex);
                uint32_t n = peer_count;
                uint32_t body_sz = n * PEER_ADDR_LEN;
                char *reply_body = NULL;
                if (body_sz > 0)
                {
                    reply_body = malloc(body_sz);
                    if (!reply_body)
                    {
                        pthread_mutex_unlock(&network_mutex);
                        send_error_response(connfd, STATUS_OTHER, "Out of memory");
                        goto reg_done;
                    }
                    for (uint32_t i = 0; i < n; ++i)
                    {
                        NetworkAddress_t *p = network[i];
                        char *rec = reply_body + i * PEER_ADDR_LEN;
                        memcpy(rec + 0, p->ip, IP_LEN);
                        uint32_t netport = htonl(p->port);
                        memcpy(rec + IP_LEN, &netport, 4);
                        memcpy(rec + IP_LEN + 4, p->salt, SALT_LEN);
                        memcpy(rec + IP_LEN + 4 + SALT_LEN, p->signature, SHA256_HASH_SIZE);
                    }
                }
                pthread_mutex_unlock(&network_mutex);

                /* compute block hash and build reply header */
                ReplyHeader_t reply;
                memset(&reply, 0, sizeof(reply));
                reply.length = htonl(body_sz);
                reply.status = htonl(STATUS_OK);
                reply.this_block = htonl(0);
                reply.block_count = htonl(1);
                if (body_sz > 0 && reply_body)
                {
                    hashdata_t block_hash;
                    get_data_sha((const void *)reply_body, block_hash, body_sz, SHA256_HASH_SIZE);
                    memcpy(reply.block_hash, block_hash, SHA256_HASH_SIZE);
                    memcpy(reply.total_hash, block_hash, SHA256_HASH_SIZE);
                }
                else
                {
                    memset(reply.block_hash, 0, SHA256_HASH_SIZE);
                    memset(reply.total_hash, 0, SHA256_HASH_SIZE);
                }

                /* send header then body */
                if (compsys_helper_writen(connfd, &reply, REPLY_HEADER_LEN) != REPLY_HEADER_LEN)
                {
                    fprintf(stderr, "[SERVER] Failed to write reply header\n");
                }
                else if (body_sz > 0 && reply_body)
                {
                    if (compsys_helper_writen(connfd, reply_body, body_sz) != (ssize_t)body_sz)
                    {
                        fprintf(stderr, "[SERVER] Failed to write reply body\n");
                    }
                }

                free(reply_body);

                /* Inform other peers (best-effort) */
                send_inform_to_network(&newpeer, newpeer.ip, newpeer.port);
            }
        reg_done:;
        }
        else if (command == COMMAND_INFORM)
        {
            fprintf(stdout, "[SERVER] Handling INFORM from %s:%u\n", ip, port);
            if (handle_inform_message(connfd, body_len) < 0)
            {
                fprintf(stderr, "[SERVER] Failed to handle INFORM\n");
            }
            /* no reply sent for INFORM */
        }
        else if (command == COMMAND_RETREIVE)
        {
            fprintf(stdout, "[SERVER] Received RETRIEVE\n");

            /* Read filename from body */
            if (body_len == 0 || body_len > PATH_LEN)
            {
                send_error_response(connfd, STATUS_MALFORMED, "Bad filename length");
                close(connfd);
                continue;
            }

            char fname[PATH_LEN + 1];
            memset(fname, 0, sizeof(fname));
            if (compsys_helper_readn(connfd, fname, body_len) != (ssize_t)body_len)
            {
                fprintf(stderr, "[SERVER] RETRIEVE: failed to read filename body\n");
                send_error_response(connfd, STATUS_MALFORMED, "Failed to read filename body");
                close(connfd);
                continue;
            }
            /* ensure NUL terminated */
            if (body_len >= PATH_LEN)
                fname[PATH_LEN] = '\0';
            else
                fname[body_len] = '\0';

            fprintf(stdout, "[SERVER] RETRIEVE request for '%s'\n", fname);

            /* try to open file relative to current directory */
            FILE *f = fopen(fname, "rb");
            if (!f)
            {
                fprintf(stderr, "[SERVER] RETRIEVE: file not found: %s\n", fname);
                send_error_response(connfd, STATUS_BAD_REQUEST, "File not found");
                close(connfd);
                continue;
            }

            /* determine file size */
            if (fseek(f, 0, SEEK_END) != 0)
            {
                fclose(f);
                send_error_response(connfd, STATUS_OTHER, "Seek failed");
                close(connfd);
                continue;
            }
            long fsize = ftell(f);
            if (fsize < 0)
            {
                fclose(f);
                send_error_response(connfd, STATUS_OTHER, "ftell failed");
                close(connfd);
                continue;
            }
            rewind(f);

            /* compute block sizing: payload per reply = MAX_MSG_LEN - REPLY_HEADER_LEN */
            uint32_t payload_per_block = MAX_MSG_LEN - REPLY_HEADER_LEN;
            if (payload_per_block == 0)
                payload_per_block = 1; /* sanity */

            uint32_t total_blocks = (uint32_t)((fsize + payload_per_block - 1) / payload_per_block);

            /* compute total hash of file */
            hashdata_t total_hash;
            get_file_sha(fname, total_hash, SHA256_HASH_SIZE);

            /* send each block as a separate reply message */
            for (uint32_t b = 0; b < total_blocks; ++b)
            {
                uint32_t to_read = payload_per_block;
                if ((long)to_read > fsize - (long)b * payload_per_block)
                    to_read = (uint32_t)(fsize - (long)b * payload_per_block);

                char *buf = malloc(to_read);
                if (!buf)
                {
                    fclose(f);
                    send_error_response(connfd, STATUS_OTHER, "Out of memory");
                    break;
                }

                if (fread(buf, 1, to_read, f) != to_read)
                {
                    free(buf);
                    fclose(f);
                    send_error_response(connfd, STATUS_OTHER, "Read failed");
                    break;
                }

                /* compute block hash */
                hashdata_t block_hash;
                get_data_sha(buf, block_hash, to_read, SHA256_HASH_SIZE);

                ReplyHeader_t rep;
                memset(&rep, 0, sizeof(rep));
                rep.length = htonl(to_read);
                rep.status = htonl(STATUS_OK);
                rep.this_block = htonl(b);
                rep.block_count = htonl(total_blocks);
                memcpy(rep.block_hash, block_hash, SHA256_HASH_SIZE);
                memcpy(rep.total_hash, total_hash, SHA256_HASH_SIZE);

                if (compsys_helper_writen(connfd, &rep, REPLY_HEADER_LEN) != REPLY_HEADER_LEN)
                {
                    fprintf(stderr, "[SERVER] RETRIEVE: failed to write reply header\n");
                    free(buf);
                    break;
                }

                if (to_read > 0)
                {
                    if (compsys_helper_writen(connfd, buf, to_read) != (ssize_t)to_read)
                    {
                        fprintf(stderr, "[SERVER] RETRIEVE: failed to write reply body\n");
                        free(buf);
                        break;
                    }
                }

                free(buf);
            }

            fclose(f);
        }

        close(connfd);
    }

    close(listenfd);
    return NULL;
}

void get_signature(const void *password, int password_len, const char *salt, hashdata_t hash_out)
{
    if (!password || !salt || !hash_out)
        return;

    // Combine password + salt (python uses password then salt)
    int combined_len = password_len + SALT_LEN;
    char *buf = malloc(combined_len);
    if (!buf)
    {
        fprintf(stderr, "get_signature: malloc failed\n");
        return;
    }

    memcpy(buf, password, password_len);
    memcpy(buf + password_len, salt, SALT_LEN);

    // compute SHA256
    get_data_sha(buf, hash_out, (uint32_t)combined_len, SHA256_HASH_SIZE);

    // clear sensitive data
    memset(buf, 0, combined_len);
    free(buf);
}

void initialize_my_address(const char *my_ip, uint32_t my_port)
{
    char passwd_buf[PASSWORD_LEN + 1];
    char *password_src = NULL;
    int password_len = 0;

#ifdef __unix__
    // POSIX: use getpass to avoid echoing the password
    char *gp = getpass("Enter remembered password: ");
    if (!gp)
    {
        fprintf(stderr, "initialize_my_address: getpass failed\n");
        return;
    }
    password_len = (int)strnlen(gp, PASSWORD_LEN);
    if (password_len > PASSWORD_LEN)
        password_len = PASSWORD_LEN;
    memcpy(passwd_buf, gp, password_len);
    passwd_buf[password_len] = '\0';
    password_src = passwd_buf;
#else
    // Fallback: visible input
    printf("Enter remembered password: ");
    if (!fgets(passwd_buf, sizeof(passwd_buf), stdin))
    {
        fprintf(stderr, "initialize_my_address: failed to read password\n");
        return;
    }
    passwd_buf[strcspn(passwd_buf, "\n")] = '\0';
    password_len = (int)strnlen(passwd_buf, PASSWORD_LEN);
    password_src = passwd_buf;
#endif

    // Generate salt and store (generate_random_salt fills SALT_LEN bytes)
    char salt_buf[SALT_LEN];
    generate_random_salt(salt_buf);
    memcpy(my_address->salt, salt_buf, SALT_LEN);

    // Compute signature = SHA256(password || salt) (matches Python reference)
    get_signature(password_src, password_len, my_address->salt, my_address->signature);

    // Store IP and port (ensure NUL termination of ip field)
    memset(my_address->ip, 0, IP_LEN);
    strncpy(my_address->ip, my_ip, IP_LEN - 1);
    my_address->port = my_port;

    // Wipe local password buffer
    memset(passwd_buf, 0, sizeof(passwd_buf));
}

//-----------------------------------------

/*
 * send_inform_to_network
 * ----------------------
 * Inform every known peer about a newly-joined peer. This function is
 * best-effort: it attempts to contact each peer in the local `network`
 * (except `exclude_ip:exclude_port` and ourselves) and sends a
 * COMMAND_INFORM message containing `new_peer` as the message body.
 *
 * Implementation notes / commentary (remove or rewrite as needed):
 * - We copy the list of peers while holding `network_mutex`, then
 *   release the mutex before performing blocking network I/O. This keeps
 *   the critical section small and avoids deadlocks.
 * - INFORM messages do not expect a reply, so we simply close the
 *   connection after writing the header+body.
 * - All integer fields sent on the wire are converted with htonl()/ntohl().
 *
 * Returns 0 on (overall) success. Individual peer failures are logged but
 * do not abort the function.
 */
int send_inform_to_network(const NetworkAddress_t *new_peer, const char *exclude_ip, uint32_t exclude_port)
{
    if (!new_peer)
        return -1;

    /* copy targets under lock */
    NetworkAddress_t *targets = NULL;
    uint32_t targets_count = 0;

    pthread_mutex_lock(&network_mutex);
    if (peer_count > 0)
    {
        targets = malloc(peer_count * sizeof(NetworkAddress_t));
        if (!targets)
        {
            pthread_mutex_unlock(&network_mutex);
            fprintf(stderr, "send_inform_to_network: malloc failed\n");
            return -1;
        }

        for (uint32_t i = 0; i < peer_count; ++i)
        {
            NetworkAddress_t *p = network[i];
            /* skip ourselves */
            if (strncmp(p->ip, my_address->ip, IP_LEN) == 0 && p->port == my_address->port)
                continue;
            // skip the registering peer (they already know)
            if (exclude_ip && strncmp(p->ip, exclude_ip, IP_LEN) == 0 && p->port == exclude_port)
                continue;

            memcpy(&targets[targets_count], p, sizeof(NetworkAddress_t));
            targets_count++;
        }
    }
    pthread_mutex_unlock(&network_mutex);

    // if no targets, nothing to do
    if (targets_count == 0)
    {
        free(targets);
        return 0;
    }

    /* Build request header for INFORM messages (sender's identity) */
    RequestHeader_t req;
    memset(&req, 0, sizeof(req));
    memcpy(req.ip, my_address->ip, IP_LEN);
    req.port = htonl(my_address->port);
    memcpy(req.signature, my_address->signature, SHA256_HASH_SIZE);
    req.command = htonl(COMMAND_INFORM);
    req.length = htonl(PEER_ADDR_LEN); /* body will be one peer record */

    // For each target, open connection and send header + body
    for (uint32_t i = 0; i < targets_count; ++i)
    {
        NetworkAddress_t *t = &targets[i];
        char portstr[PORT_STR_LEN];
        snprintf(portstr, sizeof(portstr), "%u", t->port);

        int fd = compsys_helper_open_clientfd(t->ip, portstr);
        if (fd < 0)
        {
            fprintf(stderr, "send_inform_to_network: connect failed to %s:%s\n", t->ip, portstr);
            continue;
        }

        // send header
        if (compsys_helper_writen(fd, &req, REQUEST_HEADER_LEN) != REQUEST_HEADER_LEN)
        {
            fprintf(stderr, "send_inform_to_network: write header failed to %s:%s\n", t->ip, portstr);
            close(fd);
            continue;
        }

        // send body: PEER_ADDR_LEN layout (ip, port(net), salt, signature)
        unsigned char body[PEER_ADDR_LEN];
        unsigned char *bp = body;
        memset(body, 0, sizeof(body));
        memcpy(bp, new_peer->ip, IP_LEN);
        bp += IP_LEN;
        uint32_t port_net = htonl(new_peer->port);
        memcpy(bp, &port_net, 4);
        bp += 4;
        memcpy(bp, new_peer->salt, SALT_LEN);
        bp += SALT_LEN;
        memcpy(bp, new_peer->signature, SHA256_HASH_SIZE);

        if (compsys_helper_writen(fd, body, PEER_ADDR_LEN) != PEER_ADDR_LEN)
        {
            fprintf(stderr, "send_inform_to_network: write body failed to %s:%s\n", t->ip, portstr);
            close(fd);
            continue;
        }

        // No reply expected for INFORM; close and continue
        close(fd);
    }

    free(targets);
    return 0;
}

/*
 * handle_inform_message
 * ---------------------
 * Process an incoming INFORM message. The message body is expected to be
 * exactly PEER_ADDR_LEN bytes and contain a single peer record. We parse
 * the peer info and attempt to add it to our local network using
 * network_add_peer(). No response is sent for INFORM messages.
 *
 * Implementation notes (commentary):
 * - This function reads the body synchronously from `connfd` using the
 *   provided robust read helper. If reading fails, the error is logged.
 * - The function is intentionally minimal: signature checking/auth is not
 *   performed here (you may add it later).
 */
int handle_inform_message(int connfd, uint32_t body_len)
{
    if (body_len != PEER_ADDR_LEN)
    {
        fprintf(stderr, "handle_inform_message: bad body_len=%u\n", body_len);
        return -1; // nothing to send back for INFORM
    }

    unsigned char body[PEER_ADDR_LEN];
    if (compsys_helper_readn(connfd, body, PEER_ADDR_LEN) != PEER_ADDR_LEN)
    {
        fprintf(stderr, "handle_inform_message: failed to read body\n");
        return -1;
    }

    NetworkAddress_t parsed;
    memset(&parsed, 0, sizeof(parsed));
    unsigned char *p = body;
    memcpy(parsed.ip, p, IP_LEN);
    p += IP_LEN;
    uint32_t netport;
    memcpy(&netport, p, 4);
    p += 4;
    parsed.port = ntohl(netport);
    memcpy(parsed.salt, p, SALT_LEN);
    p += SALT_LEN;
    memcpy(parsed.signature, p, SHA256_HASH_SIZE);

    /* Avoid adding ourselves */
    if (strncmp(parsed.ip, my_address->ip, IP_LEN) == 0 && parsed.port == my_address->port)
    {
        return 0;
    }

    if (network_add_peer(&parsed) == 0)
    {
        fprintf(stdout, "[INFO] Added peer via INFORM: %s:%u\n", parsed.ip, parsed.port);
    }
    else
    {
        fprintf(stderr, "[WARN] Failed to add peer from INFORM: %s:%u\n", parsed.ip, parsed.port);
    }

    return 0;
}

/*
 * send_error_response
 * -------------------
 * Build and send a standardized reply header indicating an error (status)
 * and an optional textual message body for diagnostic purposes. This is a
 * convenience helper to keep request handlers compact.
 *
 * Commentary for students: you can remove or rewrite this function, but it
 * demonstrates how to assemble a ReplyHeader_t and send a body. Integer
 * fields are converted to network order with htonl().
 */
int send_error_response(int connfd, uint32_t status, const char *msg)
{
    if (connfd < 0)
        return -1;

    uint32_t body_len = msg ? (uint32_t)strlen(msg) : 0;
    if (body_len > MAX_MSG_LEN)
        body_len = MAX_MSG_LEN;

    ReplyHeader_t hdr;
    memset(&hdr, 0, sizeof(hdr));
    hdr.length = htonl(body_len);
    hdr.status = htonl(status);
    hdr.this_block = htonl(0);
    hdr.block_count = htonl(1);
    /* block_hash and total_hash left zeroed for error responses */

    if (compsys_helper_writen(connfd, &hdr, REPLY_HEADER_LEN) != REPLY_HEADER_LEN)
    {
        fprintf(stderr, "send_error_response: failed to write header: %s\n", strerror(errno));
        return -1;
    }

    if (body_len > 0)
    {
        if (compsys_helper_writen(connfd, (void *)msg, body_len) != (ssize_t)body_len)
        {
            fprintf(stderr, "send_error_response: failed to write body: %s\n", strerror(errno));
            return -1;
        }
    }

    return 0;
}

// initialize network globals (do this at program start)
void network_init(void)
{
    // keep existing globals; just ensure starting clean
    network = NULL;
    peer_count = 0;
}

int network_find_index(const char *ip, uint32_t port)
{
    if (!network)
        return -1;
    pthread_mutex_lock(&network_mutex);
    for (uint32_t i = 0; i < peer_count; ++i)
    {
        if (strncmp(network[i]->ip, ip, IP_LEN) == 0 && network[i]->port == port)
        {
            pthread_mutex_unlock(&network_mutex);
            return (int)i;
        }
    }
    pthread_mutex_unlock(&network_mutex);
    return -1;
}

int network_add_peer(const NetworkAddress_t *addr)
{
    if (!addr)
        return -1;

    pthread_mutex_lock(&network_mutex);

    // avoid duplicates: check inline while holding mutex (no double-lock)
    for (uint32_t i = 0; i < peer_count; ++i)
    {
        if (strncmp(network[i]->ip, addr->ip, IP_LEN) == 0 && network[i]->port == addr->port)
        {
            pthread_mutex_unlock(&network_mutex);
            return 0; // already present
        }
    }

    NetworkAddress_t **tmp = realloc(network, (peer_count + 1) * sizeof(NetworkAddress_t *));
    if (!tmp)
    {
        fprintf(stderr, "network_add_peer: realloc failed\n");
        pthread_mutex_unlock(&network_mutex);
        return -1;
    }
    network = tmp;

    network[peer_count] = malloc(sizeof(NetworkAddress_t));
    if (!network[peer_count])
    {
        fprintf(stderr, "network_add_peer: malloc failed\n");
        pthread_mutex_unlock(&network_mutex);
        return -1;
    }

    memcpy(network[peer_count], addr, sizeof(NetworkAddress_t));
    peer_count++;
    pthread_mutex_unlock(&network_mutex);
    return 0;
}

//-----------------------------------------

int parse_and_store_peer_list(const char *body, uint32_t body_len)
{
    if (!body)
        return -1;
    if (body_len % PEER_ADDR_LEN != 0)
    {
        fprintf(stderr, "parse_and_store_peer_list: body_len %u not multiple of %d\n", body_len, PEER_ADDR_LEN);
        return -1;
    }

    uint32_t num_peers = body_len / PEER_ADDR_LEN;
    for (uint32_t i = 0; i < num_peers; ++i)
    {
        const char *rec = body + i * PEER_ADDR_LEN;
        NetworkAddress_t parsed;
        memset(&parsed, 0, sizeof(parsed));

        // layout: ip[IP_LEN], port[4 network-order], salt[SALT_LEN], signature[SHA256_HASH_SIZE]
        memcpy(parsed.ip, rec + 0, IP_LEN);
        uint32_t netport;
        memcpy(&netport, rec + IP_LEN, 4);
        parsed.port = ntohl(netport);
        memcpy(parsed.salt, rec + IP_LEN + 4, SALT_LEN);
        memcpy(parsed.signature, rec + IP_LEN + 4 + SALT_LEN, SHA256_HASH_SIZE);

        // avoid adding ourselves
        if (strncmp(parsed.ip, my_address->ip, IP_LEN) == 0 && parsed.port == my_address->port)
        {
            continue;
        }

        if (network_add_peer(&parsed) != 0)
        {
            fprintf(stderr, "parse_and_store_peer_list: failed to add peer %s:%u\n", parsed.ip, parsed.port);
            // keep going to try to add others
        }
    }

    return 0;
}

int send_register_message(const NetworkAddress_t *peer_address)
{
    if (!peer_address)
        return -1;

    RequestHeader_t req;
    memset(&req, 0, sizeof(req));
    memcpy(req.ip, my_address->ip, IP_LEN);
    req.port = htonl(my_address->port);
    memcpy(req.signature, my_address->signature, SHA256_HASH_SIZE);
    req.command = htonl(COMMAND_REGISTER);
    req.length = htonl(0); // no body

    char portstr[PORT_STR_LEN];
    snprintf(portstr, sizeof(portstr), "%d", peer_address->port);

    int fd = compsys_helper_open_clientfd((char *)peer_address->ip, portstr);
    if (fd < 0)
    {
        fprintf(stderr, "send_register_message: connect failed to %s:%s\n", peer_address->ip, portstr);
        return -1;
    }

    // write request header
    if (compsys_helper_writen(fd, &req, REQUEST_HEADER_LEN) != REQUEST_HEADER_LEN)
    {
        fprintf(stderr, "send_register_message: write request header failed\n");
        close(fd);
        return -1;
    }

    // read reply header
    ReplyHeader_t reply;
    if (compsys_helper_readn(fd, &reply, REPLY_HEADER_LEN) != REPLY_HEADER_LEN)
    {
        fprintf(stderr, "send_register_message: read reply header failed\n");
        close(fd);
        return -1;
    }

    uint32_t reply_length = ntohl(reply.length);
    uint32_t reply_status = ntohl(reply.status);

    if (reply_length > MAX_MSG_LEN)
    {
        fprintf(stderr, "send_register_message: reply length too large: %u\n", reply_length);
        close(fd);
        return -1;
    }

    if (reply_length > 0)
    {
        char *body = malloc(reply_length);
        if (!body)
        {
            close(fd);
            return -1;
        }
        if (compsys_helper_readn(fd, body, reply_length) != (ssize_t)reply_length)
        {
            fprintf(stderr, "send_register_message: read body failed\n");
            free(body);
            close(fd);
            return -1;
        }

        // validate hash
        hashdata_t computed;
        get_data_sha(body, computed, reply_length, SHA256_HASH_SIZE);
        if (memcmp(computed, reply.block_hash, SHA256_HASH_SIZE) != 0)
        {
            fprintf(stderr, "send_register_message: reply hash mismatch\n");
            free(body);
            close(fd);
            return -1;
        }

        if (reply_status != STATUS_OK)
        {
            fprintf(stderr, "send_register_message: reply status not OK: %u\n", reply_status);
            free(body);
            close(fd);
            return -1;
        }

        int res = parse_and_store_peer_list(body, reply_length);
        free(body);
        close(fd);
        return res;
    }

    close(fd);
    return (reply_status == STATUS_OK) ? 0 : -1;
}

/*
 * send_retrieve_message
 * ---------------------
 * Send a RETRIEVE request for `filename` to the target peer and
 * read the series of reply messages, reassembling them into a file
 * named "retrieved_<filename>" in the current directory.
 */
int send_retrieve_message(const NetworkAddress_t *peer_address, const char *filename)
{
    if (!peer_address || !filename)
        return -1;

    size_t fn_len = strnlen(filename, PATH_LEN);
    if (fn_len == 0 || fn_len > PATH_LEN)
        return -1;

    RequestHeader_t req;
    memset(&req, 0, sizeof(req));
    memcpy(req.ip, my_address->ip, IP_LEN);
    req.port = htonl(my_address->port);
    memcpy(req.signature, my_address->signature, SHA256_HASH_SIZE);
    req.command = htonl(COMMAND_RETREIVE);
    req.length = htonl((uint32_t)fn_len);

    char portstr[PORT_STR_LEN];
    snprintf(portstr, sizeof(portstr), "%u", peer_address->port);

    int fd = compsys_helper_open_clientfd((char *)peer_address->ip, portstr);
    if (fd < 0)
    {
        fprintf(stderr, "send_retrieve_message: connect failed to %s:%s\n", peer_address->ip, portstr);
        return -1;
    }

    /* write header then filename body */
    if (compsys_helper_writen(fd, &req, REQUEST_HEADER_LEN) != REQUEST_HEADER_LEN)
    {
        fprintf(stderr, "send_retrieve_message: write header failed\n");
        close(fd);
        return -1;
    }
    if (compsys_helper_writen(fd, filename, fn_len) != (ssize_t)fn_len)
    {
        fprintf(stderr, "send_retrieve_message: write body failed\n");
        close(fd);
        return -1;
    }

    /* read replies until we have all blocks */
    ReplyHeader_t reply;
    uint32_t expected_blocks = 0;
    char **blocks = NULL;
    uint32_t *block_lens = NULL;
    uint32_t received = 0;
    hashdata_t total_hash_expected;

    while (1)
    {
        if (compsys_helper_readn(fd, &reply, REPLY_HEADER_LEN) != REPLY_HEADER_LEN)
        {
            fprintf(stderr, "send_retrieve_message: read reply header failed\n");
            break;
        }

        uint32_t rlen = ntohl(reply.length);
        uint32_t rstatus = ntohl(reply.status);
        uint32_t rthis = ntohl(reply.this_block);
        uint32_t rcount = ntohl(reply.block_count);

        if (rstatus != STATUS_OK)
        {
            /* read optional body for diagnostics */
            if (rlen > 0)
            {
                char *msg = malloc(rlen + 1);
                if (msg && compsys_helper_readn(fd, msg, rlen) == (ssize_t)rlen)
                {
                    msg[rlen] = '\0';
                    fprintf(stderr, "send_retrieve_message: remote error status=%u msg=%s\n", rstatus, msg);
                }
                free(msg);
            }
            else
            {
                fprintf(stderr, "send_retrieve_message: remote error status=%u\n", rstatus);
            }
            break;
        }

        /* allocate structures on first reply */
        if (expected_blocks == 0)
        {
            expected_blocks = rcount;
            if (expected_blocks == 0)
            {
                fprintf(stderr, "send_retrieve_message: unexpected block_count=0\n");
                break;
            }
            blocks = calloc(expected_blocks, sizeof(char *));
            block_lens = calloc(expected_blocks, sizeof(uint32_t));
            if (!blocks || !block_lens)
            {
                fprintf(stderr, "send_retrieve_message: allocation failed\n");
                break;
            }
            memcpy(total_hash_expected, reply.total_hash, SHA256_HASH_SIZE);
        }

        /* read body */
        char *buf = NULL;
        if (rlen > 0)
        {
            buf = malloc(rlen);
            if (!buf)
            {
                fprintf(stderr, "send_retrieve_message: malloc failed for block %u\n", rthis);
                break;
            }
            if (compsys_helper_readn(fd, buf, rlen) != (ssize_t)rlen)
            {
                fprintf(stderr, "send_retrieve_message: failed to read block body\n");
                free(buf);
                break;
            }
        }

        /* validate block hash */
        hashdata_t computed;
        if (rlen > 0)
            get_data_sha(buf, computed, rlen, SHA256_HASH_SIZE);
        else
            memset(computed, 0, SHA256_HASH_SIZE);

        if (memcmp(computed, reply.block_hash, SHA256_HASH_SIZE) != 0)
        {
            fprintf(stderr, "send_retrieve_message: block hash mismatch for block %u\n", rthis);
            free(buf);
            break;
        }

        /* store block */
        if (rthis < expected_blocks && blocks[rthis] == NULL)
        {
            blocks[rthis] = buf;
            block_lens[rthis] = rlen;
            received++;
        }
        else
        {
            /* duplicate or out-of-range */
            free(buf);
        }

        /* if received all, reassemble */
        if (received == expected_blocks)
        {
            /* compute total size */
            uint32_t total_sz = 0;
            for (uint32_t i = 0; i < expected_blocks; ++i)
                total_sz += block_lens[i];

            char *all = malloc(total_sz);
            if (!all)
            {
                fprintf(stderr, "send_retrieve_message: out of memory assembling file\n");
                break;
            }
            uint32_t off = 0;
            for (uint32_t i = 0; i < expected_blocks; ++i)
            {
                if (block_lens[i] > 0)
                {
                    memcpy(all + off, blocks[i], block_lens[i]);
                    off += block_lens[i];
                }
            }

            /* verify total hash */
            hashdata_t got_total;
            get_data_sha(all, got_total, total_sz, SHA256_HASH_SIZE);
            if (memcmp(got_total, total_hash_expected, SHA256_HASH_SIZE) != 0)
            {
                fprintf(stderr, "send_retrieve_message: total hash mismatch\n");
                free(all);
                break;
            }

            /* write to file "retrieved_<filename>" */
            char outname[PATH_LEN + 32];
            snprintf(outname, sizeof(outname), "retrieved_%s", filename);
            FILE *of = fopen(outname, "wb");
            if (!of)
            {
                fprintf(stderr, "send_retrieve_message: failed to open output file %s\n", outname);
                free(all);
                break;
            }
            if (fwrite(all, 1, total_sz, of) != total_sz)
            {
                fprintf(stderr, "send_retrieve_message: failed to write output file\n");
                fclose(of);
                free(all);
                break;
            }
            fclose(of);
            fprintf(stdout, "send_retrieve_message: wrote %u bytes to %s\n", total_sz, outname);
            free(all);

            /* cleanup */
            for (uint32_t i = 0; i < expected_blocks; ++i)
                free(blocks[i]);
            free(blocks);
            free(block_lens);
            close(fd);
            return 0;
        }

        /* otherwise continue reading next reply header */
    }

    /* error cleanup */
    if (blocks)
    {
        for (uint32_t i = 0; i < expected_blocks; ++i)
            free(blocks[i]);
        free(blocks);
    }
    free(block_lens);
    close(fd);
    return -1;
}

int main(int argc, char **argv)
{
    // Users should call this script with a single argument describing what
    // config to use
    if (argc != 3)
    {
        fprintf(stderr, "Usage: %s <IP> <PORT>\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    /* allocate and zero the my_address structure (safety) */
    my_address = malloc(sizeof(*my_address));
    if (!my_address)
    {
        fprintf(stderr, "Failed to allocate my_address\n");
        exit(EXIT_FAILURE);
    }
    memset(my_address, 0, sizeof(*my_address));

    /* copy IP safely (ensure NUL) and set port */
    strncpy(my_address->ip, argv[1], IP_LEN - 1);
    my_address->port = (uint32_t)atoi(argv[2]);

    if (!is_valid_ip(my_address->ip))
    {
        fprintf(stderr, ">> Invalid peer IP: %s\n", my_address->ip);
        exit(EXIT_FAILURE);
    }

    if (!is_valid_port(my_address->port))
    {
        fprintf(stderr, ">> Invalid peer port: %d\n",
                my_address->port);
        exit(EXIT_FAILURE);
    }

    // Initialise identity: prompts once, generates salt, computes signature
    initialize_my_address(argv[1], my_address->port);

    /* initialize network globals */
    network_init();

    // Setup the server and client threads (start server first to avoid IO races)
    pthread_t client_thread_id;
    pthread_t server_thread_id;
    pthread_create(&server_thread_id, NULL, server_thread, NULL);
    pthread_create(&client_thread_id, NULL, client_thread, NULL);

    // Wait for them to complete.
    pthread_join(client_thread_id, NULL);
    pthread_join(server_thread_id, NULL);

    exit(EXIT_SUCCESS);
}