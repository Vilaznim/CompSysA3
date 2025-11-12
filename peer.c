#include <stdlib.h>
#include <stdio.h>
#include <math.h>
#include <netdb.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

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

int initialize_my_address(const char *my_ip, uint32_t my_port);
void network_init(void);
int network_add_peer(const NetworkAddress_t *addr);    /* returns 0 on success, -1 on error */
int network_find_index(const char *ip, uint32_t port); /* -1 if not found */

void *handle_server_request_thread(void *arg);
void handle_register_request(int connfd, const RequestHeader_t *req, const char *body, uint32_t body_len);
void send_response(int connfd, uint32_t status, const char *body, uint32_t body_len);

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
    scanf("%16s", peer_ip);

    // Clean up password string as otherwise some extra chars can sneak in.
    for (int i = strlen(peer_ip); i < IP_LEN; i++)
    {
        peer_ip[i] = '\0';
    }

    char peer_port[PORT_STR_LEN];
    fprintf(stdout, "Enter peer port to connect to: ");
    scanf("%16s", peer_port);

    // Clean up password string as otherwise some extra chars can sneak in.
    for (int i = strlen(peer_port); i < PORT_STR_LEN; i++)
    {
        peer_port[i] = '\0';
    }

    NetworkAddress_t peer_address;
    memcpy(peer_address.ip, peer_ip, IP_LEN);
    peer_address.port = atoi(peer_port);

    // attempt to register with the peer the user provided
    if (send_register_message(&peer_address) == 0)
    {
        printf("Registration succeeded — got peer list; peer_count=%u\n", peer_count);
    }
    else
    {
        printf("Registration failed\n");
    }

    // You should never see this printed in your finished implementation
    printf("Client thread done\n");

    return NULL;
}

/*
 * Function to act as basis for running the server thread. This thread will be
 * run concurrently with the client thread, but is infinite in nature.
 */
void *server_thread()
{
    char portstr[PORT_STR_LEN];
    snprintf(portstr, sizeof(portstr), "%u", my_address->port);

    int listenfd = compsys_helper_open_listenfd(portstr);
    if (listenfd < 0) {
        fprintf(stderr, "server_thread: open_listenfd failed for port %s\n", portstr);
        return NULL;
    }

    while (1) {
        struct sockaddr_storage clientaddr;
        socklen_t clientlen = sizeof(clientaddr);
        int connfd = accept(listenfd, (struct sockaddr *)&clientaddr, &clientlen);
        if (connfd < 0) {
            // transient errors should be ignored; log unexpected ones
            perror("accept");
            continue;
        }

        // pass the connfd to handler thread via malloc'd int
        int *pconn = malloc(sizeof(int));
        if (!pconn) { close(connfd); continue; }
        *pconn = connfd;
        pthread_t tid;
        if (pthread_create(&tid, NULL, handle_server_request_thread, pconn) != 0) {
            perror("pthread_create");
            free(pconn);
            close(connfd);
            continue;
        }
        // not joining; the handler will call pthread_detach on itself
    }

    // never reached normally
    close(listenfd);
    return NULL;
}

void *handle_server_request_thread(void *arg)
{
    pthread_detach(pthread_self());

    int connfd = *(int *)arg;
    free(arg);

    compsys_helper_state_t rstate;
    compsys_helper_readinitb(&rstate, connfd);

    RequestHeader_t req;
    ssize_t hr = compsys_helper_readnb(&rstate, &req, REQUEST_HEADER_LEN);
    if (hr != REQUEST_HEADER_LEN) {
        // malformed or closed connection
        close(connfd);
        return NULL;
    }

    /* debug: show incoming header info */
    {
        char tmp_ip[IP_LEN];
        memcpy(tmp_ip, req.ip, IP_LEN);
        tmp_ip[IP_LEN-1] = '\0';
        uint32_t tmp_port = ntohl(req.port);
        uint32_t tmp_cmd = ntohl(req.command);
        uint32_t tmp_len = ntohl(req.length);
        printf("Server: got header from %s:%u cmd=%u len=%u\n", tmp_ip, tmp_port, tmp_cmd, tmp_len);
    }

    uint32_t body_len = ntohl(req.length);
    if (body_len > MAX_MSG_LEN) {
        fprintf(stderr, "handler: incoming body_len too large: %u\n", body_len);
        close(connfd);
        return NULL;
    }

    char *body = NULL;
    if (body_len > 0) {
        body = malloc(body_len);
        if (!body) { close(connfd); return NULL; }
        if (compsys_helper_readnb(&rstate, body, body_len) != (ssize_t)body_len) {
            free(body); close(connfd); return NULL;
        }
    }

    uint32_t cmd = ntohl(req.command);
    if (cmd == COMMAND_REGISTER) {
        handle_register_request(connfd, &req, body, body_len);
    } else {
        // Unknown command: respond with STATUS_BAD_REQUEST
        send_response(connfd, STATUS_BAD_REQUEST, NULL, 0);
    }

    free(body);
    close(connfd);
    return NULL;
}

void handle_register_request(int connfd, const RequestHeader_t *req, const char *body, uint32_t body_len)
{
    (void)body;
    (void)body_len;
    // Extract IP and port from the request header
    char req_ip[IP_LEN];
    memcpy(req_ip, req->ip, IP_LEN);
    req_ip[IP_LEN - 1] = '\0'; // ensure NUL for string ops

    uint32_t req_port = ntohl(req->port);

    if (!is_valid_ip(req_ip) || !is_valid_port(req_port)) {
        send_response(connfd, STATUS_BAD_REQUEST, NULL, 0);
        return;
    }

    // Salt-and-hash the incoming signature before storing.
    // Incoming signature is in req->signature (SHA256_HASH_SIZE bytes).
    char server_salt[SALT_LEN];
    generate_random_salt(server_salt);

    char combined[SHA256_HASH_SIZE + SALT_LEN];
    memcpy(combined, req->signature, SHA256_HASH_SIZE);
    memcpy(combined + SHA256_HASH_SIZE, server_salt, SALT_LEN);

    hashdata_t stored_sig;
    get_data_sha(combined, stored_sig, SHA256_HASH_SIZE + SALT_LEN, SHA256_HASH_SIZE);

    // Build new NetworkAddress_t record
    NetworkAddress_t newpeer;
    memset(&newpeer, 0, sizeof(newpeer));
    memcpy(newpeer.ip, req->ip, IP_LEN);
    newpeer.port = req_port;
    memcpy(newpeer.salt, server_salt, SALT_LEN);
    memcpy(newpeer.signature, stored_sig, SHA256_HASH_SIZE);

    // Add to network (network_add_peer does locking). If already present, it returns 0.
    if (network_add_peer(&newpeer) != 0) {
        // Addition failed (allocation error...) — reply with error
        send_response(connfd, STATUS_OTHER, NULL, 0);
        return;
    }

    /* debug: log registration */
    {
        char nip[IP_LEN];
        memcpy(nip, newpeer.ip, IP_LEN);
        nip[IP_LEN-1] = '\0';
        printf("Server: Registered new peer %s:%u\n", nip, newpeer.port);
    }

    // Prepare reply body by copying current network entries under lock
    pthread_mutex_lock(&network_mutex);
    uint32_t n = peer_count;
    uint32_t body_sz = n * PEER_ADDR_LEN;
    char *reply_body = NULL;
    if (body_sz > 0) {
        reply_body = malloc(body_sz);
        if (!reply_body) {
            pthread_mutex_unlock(&network_mutex);
            send_response(connfd, STATUS_OTHER, NULL, 0);
            return;
        }
        for (uint32_t i = 0; i < n; ++i) {
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

    // Send OK response with peer list
    send_response(connfd, STATUS_OK, reply_body, body_sz);
    free(reply_body);
}

void send_response(int connfd, uint32_t status, const char *body, uint32_t body_len)
{
    ReplyHeader_t reply;
    memset(&reply, 0, sizeof(reply));
    reply.status = htonl(status);
    reply.length = htonl(body_len);

    /* single-message reply: this_block=0 (first block), block_count=1 */
    reply.this_block = htonl(0);
    reply.block_count = htonl(1);

    if (body_len > 0 && body != NULL) {
        hashdata_t block_hash;
        get_data_sha(body, block_hash, body_len, SHA256_HASH_SIZE);
        // For single-message reply total_hash == block_hash
        memcpy(reply.block_hash, block_hash, SHA256_HASH_SIZE);
        memcpy(reply.total_hash, block_hash, SHA256_HASH_SIZE);
    } else {
        memset(reply.block_hash, 0, SHA256_HASH_SIZE);
        memset(reply.total_hash, 0, SHA256_HASH_SIZE);
    }

    // write header
    if (compsys_helper_writen(connfd, &reply, REPLY_HEADER_LEN) != REPLY_HEADER_LEN) {
        // write failed
        return;
    }

    // write body if present
    if (body_len > 0 && body != NULL) {
        if (compsys_helper_writen(connfd, (void *)body, body_len) != (ssize_t)body_len) {
            // write failed
            return;
        }
    }
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

int initialize_my_address(const char *my_ip, uint32_t my_port)
{
    char passwd_buf[PASSWORD_LEN + 1];
    char *password_src = NULL;
    int password_len = 0;

#ifdef __unix__
    // POSIX: use getpass to avoid echoing the password
    char *gp = getpass("Enter password for this peer: ");
    if (!gp)
    {
        fprintf(stderr, "initialize_my_address: getpass failed\n");
        return -1;
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
        return -1;
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
    return 0;
}

//-----------------------------------------

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

    // allocate new element first to avoid leaving array expanded on failure
    NetworkAddress_t *elem = malloc(sizeof(NetworkAddress_t));
    if (!elem)
    {
        fprintf(stderr, "network_add_peer: malloc(elem) failed\n");
        return -1;
    }
    memcpy(elem, addr, sizeof(NetworkAddress_t));

    pthread_mutex_lock(&network_mutex);

    // avoid duplicates: check inline while holding mutex (no double-lock)
    for (uint32_t i = 0; i < peer_count; ++i)
    {
        if (strncmp(network[i]->ip, elem->ip, IP_LEN) == 0 && network[i]->port == elem->port)
        {
            pthread_mutex_unlock(&network_mutex);
            free(elem);
            return 0; // already present
        }
    }

    NetworkAddress_t **tmp = realloc(network, (peer_count + 1) * sizeof(NetworkAddress_t *));
    if (!tmp)
    {
        fprintf(stderr, "network_add_peer: realloc failed\n");
        pthread_mutex_unlock(&network_mutex);
        free(elem);
        return -1;
    }
    network = tmp;

    network[peer_count] = elem;
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

//-----------------------------------------

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
    if (initialize_my_address(argv[1], my_address->port) != 0) {
    fprintf(stderr, "Failed to initialize identity\n");
    exit(EXIT_FAILURE);
}

    /* initialize network globals */
    network_init();

    // Setup the server thread first so it is listening before client input
    pthread_t client_thread_id;
    pthread_t server_thread_id;
    pthread_create(&server_thread_id, NULL, server_thread, NULL);

    // small delay gives the server a moment to bind/listen before client prompts
    // (simple approach for testing; for production use a condition variable or explicit ready signal)
    sleep(1);

    pthread_create(&client_thread_id, NULL, client_thread, NULL);

    // Wait for them to complete.
    pthread_join(client_thread_id, NULL);
    pthread_join(server_thread_id, NULL);

    exit(EXIT_SUCCESS);
}