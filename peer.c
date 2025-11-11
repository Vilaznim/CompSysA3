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

void initialize_my_address(const char *my_ip, uint32_t my_port);
void network_init(void);
int network_add_peer(const NetworkAddress_t *addr); /* returns 0 on success, -1 on error */
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

        /* attempt to register with the peer the user provided */
    if (send_register_message(&peer_address) == 0) {
        printf("Registration succeeded — got peer list; peer_count=%u\n", peer_count);
    } else {
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
    // You should never see this printed in your finished implementation
    printf("Server thread done\n");

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
    /* POSIX: use getpass to avoid echoing the password */
    char *gp = getpass("Enter remembered password: ");
    if (!gp) {
        fprintf(stderr, "initialize_my_address: getpass failed\n");
        return;
    }
    password_len = (int)strnlen(gp, PASSWORD_LEN);
    if (password_len > PASSWORD_LEN) password_len = PASSWORD_LEN;
    memcpy(passwd_buf, gp, password_len);
    passwd_buf[password_len] = '\0';
    password_src = passwd_buf;
#else
    /* Fallback: visible input */
    printf("Enter remembered password: ");
    if (!fgets(passwd_buf, sizeof(passwd_buf), stdin)) {
        fprintf(stderr, "initialize_my_address: failed to read password\n");
        return;
    }
    passwd_buf[strcspn(passwd_buf, "\n")] = '\0';
    password_len = (int)strnlen(passwd_buf, PASSWORD_LEN);
    password_src = passwd_buf;
#endif

    /* Generate salt and store (generate_random_salt fills SALT_LEN bytes) */
    char salt_buf[SALT_LEN];
    generate_random_salt(salt_buf);
    memcpy(my_address->salt, salt_buf, SALT_LEN);

    /* Compute signature = SHA256(password || salt) (matches Python reference) */
    get_signature(password_src, password_len, my_address->salt, my_address->signature);

    /* Store IP and port (ensure NUL termination of ip field) */
    memset(my_address->ip, 0, IP_LEN);
    strncpy(my_address->ip, my_ip, IP_LEN - 1);
    my_address->port = my_port;

    /* Wipe local password buffer */
    memset(passwd_buf, 0, sizeof(passwd_buf));
}


//-----------------------------------------

/* initialize network globals (do this at program start) */
void network_init(void)
{
    /* keep existing globals; just ensure starting clean */
    network = NULL;
    peer_count = 0;
}

int network_find_index(const char *ip, uint32_t port)
{
    if (!network) return -1;
    pthread_mutex_lock(&network_mutex);
    for (uint32_t i = 0; i < peer_count; ++i) {
        if (strncmp(network[i]->ip, ip, IP_LEN) == 0 && network[i]->port == port) {
            pthread_mutex_unlock(&network_mutex);
            return (int)i;
        }
    }
    pthread_mutex_unlock(&network_mutex);
    return -1;
}

int network_add_peer(const NetworkAddress_t *addr)
{
    if (!addr) return -1;

    pthread_mutex_lock(&network_mutex);

    /* avoid duplicates */
    if (network_find_index(addr->ip, addr->port) != -1) {
        pthread_mutex_unlock(&network_mutex);
        return 0;
    }

    NetworkAddress_t **tmp = realloc(network, (peer_count + 1) * sizeof(NetworkAddress_t *));
    if (!tmp) {
        fprintf(stderr, "network_add_peer: realloc failed\n");
        pthread_mutex_unlock(&network_mutex);
        return -1;
    }
    network = tmp;

    network[peer_count] = malloc(sizeof(NetworkAddress_t));
    if (!network[peer_count]) {
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
    if (!body) return -1;
    if (body_len % PEER_ADDR_LEN != 0) {
        fprintf(stderr, "parse_and_store_peer_list: body_len %u not multiple of %d\n", body_len, PEER_ADDR_LEN);
        return -1;
    }

    uint32_t num_peers = body_len / PEER_ADDR_LEN;
    for (uint32_t i = 0; i < num_peers; ++i) {
        const char *rec = body + i * PEER_ADDR_LEN;
        NetworkAddress_t parsed;
        memset(&parsed, 0, sizeof(parsed));

        /* layout: ip[IP_LEN], port[4 network-order], salt[SALT_LEN], signature[SHA256_HASH_SIZE] */
        memcpy(parsed.ip, rec + 0, IP_LEN);
        uint32_t netport;
        memcpy(&netport, rec + IP_LEN, 4);
        parsed.port = ntohl(netport);
        memcpy(parsed.salt, rec + IP_LEN + 4, SALT_LEN);
        memcpy(parsed.signature, rec + IP_LEN + 4 + SALT_LEN, SHA256_HASH_SIZE);

        /* avoid adding ourselves */
        if (strncmp(parsed.ip, my_address->ip, IP_LEN) == 0 && parsed.port == my_address->port) {
            continue;
        }

        if (network_add_peer(&parsed) != 0) {
            fprintf(stderr, "parse_and_store_peer_list: failed to add peer %s:%u\n", parsed.ip, parsed.port);
            /* keep going to try to add others */
        }
    }

    return 0;
}

int send_register_message(const NetworkAddress_t *peer_address)
{
    if (!peer_address) return -1;

    RequestHeader_t req;
    memset(&req, 0, sizeof(req));
    memcpy(req.ip, my_address->ip, IP_LEN);
    req.port = htonl(my_address->port);
    memcpy(req.signature, my_address->signature, SHA256_HASH_SIZE);
    req.command = htonl(COMMAND_REGISTER);
    req.length = htonl(0); /* no body */

    char portstr[PORT_STR_LEN];
    snprintf(portstr, sizeof(portstr), "%d", peer_address->port);

    int fd = compsys_helper_open_clientfd((char *)peer_address->ip, portstr);
    if (fd < 0) {
        fprintf(stderr, "send_register_message: connect failed to %s:%s\n", peer_address->ip, portstr);
        return -1;
    }

    /* write request header */
    if (compsys_helper_writen(fd, &req, REQUEST_HEADER_LEN) != REQUEST_HEADER_LEN) {
        fprintf(stderr, "send_register_message: write request header failed\n");
        close(fd);
        return -1;
    }

    /* read reply header */
    ReplyHeader_t reply;
    if (compsys_helper_readn(fd, &reply, REPLY_HEADER_LEN) != REPLY_HEADER_LEN) {
        fprintf(stderr, "send_register_message: read reply header failed\n");
        close(fd);
        return -1;
    }

    uint32_t reply_length = ntohl(reply.length);
    uint32_t reply_status = ntohl(reply.status);

    if (reply_length > MAX_MSG_LEN) {
        fprintf(stderr, "send_register_message: reply length too large: %u\n", reply_length);
        close(fd);
        return -1;
    }

    if (reply_length > 0) {
        char *body = malloc(reply_length);
        if (!body) { close(fd); return -1; }
        if (compsys_helper_readn(fd, body, reply_length) != (ssize_t)reply_length) {
            fprintf(stderr, "send_register_message: read body failed\n");
            free(body); close(fd); return -1;
        }

        /* validate hash */
        hashdata_t computed;
        get_data_sha(body, computed, reply_length, SHA256_HASH_SIZE);
        if (memcmp(computed, reply.block_hash, SHA256_HASH_SIZE) != 0) {
            fprintf(stderr, "send_register_message: reply hash mismatch\n");
            free(body); close(fd); return -1;
        }

        if (reply_status != STATUS_OK) {
            fprintf(stderr, "send_register_message: reply status not OK: %u\n", reply_status);
            free(body); close(fd); return -1;
        }

        int res = parse_and_store_peer_list(body, reply_length);
        free(body); close(fd);
        return res;
    }

    close(fd);
    return (reply_status == STATUS_OK) ? 0 : -1;
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

    my_address = (NetworkAddress_t *)malloc(sizeof(NetworkAddress_t));
    memset(my_address->ip, '\0', IP_LEN);
    memcpy(my_address->ip, argv[1], strlen(argv[1]));
    my_address->port = atoi(argv[2]);

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

    /* Initialise identity: prompts once, generates salt, computes signature */
    initialize_my_address(argv[1], my_address->port);

    // Setup the client and server threads
    pthread_t client_thread_id;
    pthread_t server_thread_id;
    pthread_create(&client_thread_id, NULL, client_thread, NULL);
    pthread_create(&server_thread_id, NULL, server_thread, NULL);

    // Wait for them to complete.
    pthread_join(client_thread_id, NULL);
    pthread_join(server_thread_id, NULL);

    exit(EXIT_SUCCESS);
}