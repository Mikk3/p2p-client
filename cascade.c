#include <stdlib.h>
#include <stdio.h>
#include <netdb.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <string.h>

#ifdef __APPLE__
#include "./endian.h"
#else
#include <endian.h>
#endif

#include "./cascade.h"
#include "./sha256.h"

#include <err.h>

char tracker_ip[IP_LEN];
char tracker_port[PORT_LEN];
char my_ip[IP_LEN];
char my_port[PORT_LEN];

struct csc_file *casc_file;
csc_block_t** queue;
struct csc_peer *peers;

struct ActiveFiles* activeFiles;

pthread_mutex_t ConnLock = PTHREAD_MUTEX_INITIALIZER;



/*
 * Frees global resources that are malloc'ed during peer downloads.
 */
void free_resources()
{
    free(queue);
    free(peers);
}

/*
 * Gets a sha256 hash of specified data, sourcedata. The hash itself is
 * placed into the given variable 'hash'. Any size can be created, but a
 * a normal size for the hash would be given by the global variable
 * 'SHA256_HASH_SIZE', that has been defined in sha256.h
 */
void get_data_sha(const char* sourcedata, hashdata_t hash, uint32_t data_size, int hash_size)
{
  SHA256_CTX shactx;
  unsigned char shabuffer[hash_size];
  sha256_init(&shactx);
  sha256_update(&shactx, sourcedata, data_size);
  sha256_final(&shactx, shabuffer);

  for (int i=0; i<hash_size; i++)
    {
      hash[i] = shabuffer[i];
    }
}

/*
 * Gets a sha256 hash of a specified file, sourcefile. The hash itself is
 * placed into the given variable 'hash'. Any size can be created, but a
 * a normal size for the hash would be given by the global variable
 * 'SHA256_HASH_SIZE', that has been defined in sha256.h
 */
void get_file_sha(const char* sourcefile, hashdata_t hash, int size)
{
    int casc_file_size;

    FILE* fp = Fopen(sourcefile, "rb");
    if (fp == 0)
    {
        printf("Failed to open source: %s\n", sourcefile);
        return;
    }

    fseek(fp, 0L, SEEK_END);
    casc_file_size = ftell(fp);
    fseek(fp, 0L, SEEK_SET);

    char buffer[casc_file_size];
    Fread(buffer, casc_file_size, 1, fp);
    Fclose(fp);

    get_data_sha(buffer, hash, casc_file_size, size);
}


/*
 * Subscribe the given cascade hash to the network This is Identical to get_peers_list 
 * besides the command sent to tracker is 2 and not 1.
 */
int subscribe(hashdata_t hash)
{
    rio_t rio;
    char msg_buf[MAXLINE];

    int tracker_socket = Open_clientfd(tracker_ip, tracker_port);
    Rio_readinitb(&rio, tracker_socket);

    struct RequestHeader request_header;
    // memcpy as it does not end with terminating null byte.
    memcpy(request_header.protocol, "CASC", sizeof(request_header.protocol));

    request_header.version = htonl(1);
    request_header.command = htonl(2);
    request_header.length = htonl(BODY_SIZE);

    memcpy(msg_buf, &request_header, HEADER_SIZE);

    struct in_addr byte_my_ip;
    inet_aton(my_ip, &byte_my_ip);

    struct RequestBody request_body;
    memcpy(request_body.hash, hash, SHA256_HASH_SIZE);
    request_body.ip = byte_my_ip;
    request_body.port = htons(atoi(my_port));
    memcpy(msg_buf + HEADER_SIZE, &request_body, BODY_SIZE);

    Rio_writen(tracker_socket, msg_buf, MESSAGE_SIZE);

    Rio_readnb(&rio, msg_buf, MAXLINE);

    char reply_header[REPLY_HEADER_SIZE];
    memcpy(reply_header, msg_buf, REPLY_HEADER_SIZE);

    uint32_t msglen = ntohl(*(uint32_t*)&reply_header[1]);
    if (msglen == 0)
    {
        return 0;
    }

    if (reply_header[0] != 0)
    {
        char* error_buf = Malloc(msglen + 1);
        if (error_buf == NULL)
        {
            printf("Tracker error %d and out-of-memory reading error\n", reply_header[0]);
            Close(tracker_socket);
            return 0;
        }
        memset(error_buf, 0, msglen + 1);
        memcpy(reply_header, error_buf, msglen);
        printf("Tracker gave error: %d - %s\n", reply_header[0], error_buf);
        Free(error_buf);
        Close(tracker_socket);
        return 0;
    }

    if (msglen % 12 != 0)
    {
        printf("LIST response from tracker was length %ud but should be evenly divisible by 12\n", msglen);
        Close(tracker_socket);
        return 0;
    }
    
    Close(tracker_socket);
    return 1;
}

/*
 * Perform all client based interactions in the P2P network for a given cascade file.
 * E.g. parse a cascade file and get all the relevent data from somewhere else on the
 * network.
 */
void download_only_peer(char* cascade_file)
{
    printf("Managing download only for: %s\n", cascade_file);
    if (access(cascade_file, F_OK ) != 0 )
    {
        fprintf(stderr, ">> File %s does not exist\n", cascade_file);
        exit(EXIT_FAILURE);
    }

    char output_file[strlen(cascade_file)];
    memcpy(output_file, cascade_file, strlen(cascade_file));
    char* r = strstr(cascade_file, "cascade");
    int cutoff = r - cascade_file ;
    output_file[cutoff-1] = '\0';
    printf("Downloading to: %s\n", output_file);

    casc_file = csc_parse_file(cascade_file, output_file);

    // Calculate cascade file hash
    // Also used for get_peers_list
    hashdata_t hash_buf;
    get_file_sha(cascade_file, hash_buf, SHA256_HASH_SIZE);

    // Add to activeFiles, mutex ensures handle threads are not reading while we are updating.
    assert(pthread_mutex_lock(activeFiles->lock) == 0);
    memcpy(&activeFiles->csc_files[activeFiles->length].cascadeHash, &hash_buf, 32); // Cascade Hash
    activeFiles->csc_files[activeFiles->length].csc_file = casc_file; // Pointer to casc file data struture
    
    activeFiles->csc_files[activeFiles->length].output_file = malloc(cutoff * sizeof(char)); 
    memcpy(activeFiles->csc_files[activeFiles->length].output_file, output_file, cutoff); // The data file name
    activeFiles->length++;
    assert(pthread_mutex_unlock(activeFiles->lock) == 0);
    
    // Subscribe file to tracker
    // This is necessary as get_peers_list is not executed if its a complete file
    // and therefore not enrolling us in the network.
    subscribe(hash_buf);

    int uncomp_count = 0;
    queue = Malloc(casc_file->blockcount * sizeof(csc_block_t*));

    for (uint64_t i = 0; i < casc_file->blockcount; i++)
    {
        if (casc_file->blocks[i].completed == 0)
        {
            queue[uncomp_count] = &casc_file->blocks[i];
            uncomp_count++;
        }
    }

    printf("Missing blocks: %d/%lu\n", uncomp_count, casc_file->blockcount);
    if (uncomp_count == 0)
    {
        printf("All blocks are already present, skipping external connections.\n");
        free_resources();
        return;
    }
    queue = Realloc(queue, uncomp_count * sizeof(csc_block_t*));

    int peercount = 0;
    while (peercount == 0)
    {
        peercount = get_peers_list(hash_buf);
        if (peercount == 0)
        {
            printf("No peers were found. Will try again in %d seconds\n", PEER_REQUEST_DELAY);
            fflush(stdout);
            sleep(PEER_REQUEST_DELAY);
        }
        else
        {
            printf("Found %d peer(s)\n", peercount);
        }
    }

    csc_peer_t peer = peers[0];
    // Get a good peer if one is available
    for (int i = 0; i < peercount; i++)
    {
        if (peers[i].good)
        {
            peer = peers[i];
            break;
        }
    }

    printf("Downloading blocks\n");
    for (int i = 0; i < uncomp_count; i++)
    {
        get_block(queue[i], peer, hash_buf, output_file);
        queue[i]->completed = 1;
    }
    printf("File downloaded successfully\n");

    free_resources();
}

/*
 * Count how many times a character occurs in a string
 */
int count_occurences(char string[], char c)
{
    int count=0;
    for(size_t i = 0; i < strlen(string); i++)
    {
        if(string[i] == c)
        {
            count++;
        }
    }
    return count;
}


/*
 * Parses a cascade file, given the sourcepath input and destination, which may or may not exist.
 * Returns a pointer to a datastructure describing the file, or NULL if the file could not be parsed
 */
csc_file_t* csc_parse_file(const char* sourcefile, const char* destination)
{
    FILE* fp = Fopen(sourcefile, "rb");
    if (fp == 0)
    {
        printf("Failed to open source: %s\n", sourcefile);
        return NULL;
    }

    const int FILE_HEADER_SIZE = 8+8+8+8+32;

    char header[FILE_HEADER_SIZE];
    if (Fread(header, 1, FILE_HEADER_SIZE, fp) != (size_t)FILE_HEADER_SIZE)
    {
        printf("Failed to read magic 8 bytes header from file\n");
        Fclose(fp);
        return NULL;
    }

    if (memcmp(header, "CASCADE1", 8) != 0)
    {
        printf("File does not contain magic 8 bytes in header\n");
        Fclose(fp);
        return NULL;
    }

    csc_file_t* res = (csc_file_t*)Malloc(sizeof(csc_file_t));
    res->targetsize = be64toh(*((unsigned long long*)&header[16]));
    res->blocksize = be64toh(*((unsigned long long*)&header[24]));
    memcpy(&res->targethash, &header[32], 32);
    res->trailblocksize = res->targetsize % res->blocksize;
    if (res->trailblocksize == 0) // If the filesize is evenly divisible by the blocksize
        res->trailblocksize = res->blocksize;

    res->blockcount = (res->targetsize + res->blocksize - 1) / res->blocksize;

    res->blocks = (csc_block_t*)Malloc(sizeof(csc_block_t) * res->blockcount);
    if (res->blocks == NULL)
    {
        printf("Failed to allocate memory for %lud blocks\n", res->blockcount);
        Free(res);
        Fclose(fp);
        return NULL;
    }

    for(uint64_t i = 0; i < res->blockcount; i++)
    {
        csc_block_t* b = &res->blocks[i];
        b->index = i;
        b->length = i == res->blockcount - 1 ? res->trailblocksize : res->blocksize;
        b->offset = i * res->blocksize;
        b->completed = 0;
        if (Fread(&(b->hash), 1, sizeof(hashdata_t), fp) != sizeof(hashdata_t))
        {
            printf("Failed to read block %lud/%lud\n", i, res->blockcount);
            csc_free_file(res);
            Fclose(fp);
            return NULL;
        }
    }

    Fclose(fp);

    fp = Fopen(destination, "a+w");
    if (fp == NULL)
    {
        printf("Failed to open destination file %s\n", destination);
        csc_free_file(res);
        return NULL;
    }

    void* buffer = Malloc(res->blocksize);
    if (buffer == NULL)
    {
        printf("No block buffer asigned: %lud\n", res->blocksize);
        csc_free_file(res);
        Fclose(fp);
        return NULL;
    }

    SHA256_CTX shactx;
    for(uint64_t i = 0; i < res->blockcount; i++)
    {
        hashdata_t shabuffer;
        uint64_t size = res->blocks[i].length;
        if (fread(buffer, size, 1, fp) != 1)
        {
            break;
        }

        sha256_init(&shactx);
        sha256_update(&shactx, buffer, size);
        sha256_final(&shactx, shabuffer);

        if (memcmp(&res->blocks[i].hash, shabuffer, SHA256_HASH_SIZE) != 0)
        {
            break;
        }

        res->blocks[i].completed = 1;
    }
    Fclose(fp);
    Free(buffer);
    return res;
}

/*
 * Releases the memory allocated by a file datastructure
 */
void csc_free_file(csc_file_t* file)
{
    Free(file->blocks);
    file->blocks = NULL;
    Free(file);
}

/*
 * Get a specified block from a peer on the network. The block is retrieved and then inserted directly into
 * the appropriate data file at the appropriate location.
 */
void get_block(csc_block_t* block, csc_peer_t peer, hashdata_t hash, char* output_file)
{

    rio_t rio;
    char msg_buf[MAXLINE];

    int peer_socket = open_clientfd(peer.ip, peer.port);
    if(peer_socket != 0) {
        printf("Could not etablish connection to peer reported by tracker\n");
        return;
    }
    Rio_readinitb(&rio, peer_socket);

    struct ClientRequest client_request;
    // memcpy as we don't have space for terminating null.
    memcpy(client_request.protocol, "CASCADE1", sizeof(client_request.protocol));

    client_request.block_num = htobe64(block->index);
    memcpy(client_request.hash, hash, SHA256_HASH_SIZE);

    memcpy(msg_buf, &client_request, PEER_REQUEST_HEADER_SIZE);

    Rio_writen(peer_socket, msg_buf, PEER_REQUEST_HEADER_SIZE);

    Rio_readlineb(&rio, msg_buf, MAXLINE);

    char reply_header[PEER_RESPONSE_HEADER_SIZE];
    memcpy(reply_header, msg_buf, PEER_RESPONSE_HEADER_SIZE);

    if (reply_header[0] != 0)
    {
        if (reply_header[0] == 1)
        {
            printf("Peer reported: Invalid hash, File not present on peer\n");
        }
        else if (reply_header[0] == 2)
        {
            printf("Peer reported: Invalid hash, Block not present on peer\n");
        }
        else if (reply_header[0] == 3)
        {
            printf("Peer reported: Invalid block number\n");
        }
        else if (reply_header[0] == 4)
        {
            printf("Peer reported: Request could not be parsed\n");
        }
        else
        {
            printf("Invalid error code\n");
        }
        Close(peer_socket);
        return;
    }

    uint64_t msglen = be64toh(*(uint64_t*)&reply_header[1]);

    if (msglen != block->length)
    {
        printf("Invalid block length supplied\n");
        Close(peer_socket);
        return;
    }

    // msglen+1 to make room for terminating null byte.
    char *block_data = Calloc(msglen+1, sizeof(char));
    hashdata_t block_hash;

    strcpy(block_data, msg_buf + PEER_RESPONSE_HEADER_SIZE);

    uint64_t write_count = strlen(block_data);
    uint64_t to_read = msglen - write_count;
    uint64_t was_read = 0;

    while (write_count < msglen)
    {
        if (to_read > MAXLINE)
        {
            to_read = MAXLINE;
        }

        was_read = Rio_readnb(&rio, msg_buf, to_read);

        memcpy(block_data + write_count, msg_buf, was_read);

        write_count += was_read;
        to_read = msglen - write_count;
    }

    get_data_sha(block_data, block_hash, msglen, SHA256_HASH_SIZE);

    // Also make sure to check block hash is expected
    for (int i = 0; i < SHA256_HASH_SIZE; ++i) {
        if (block_hash[i] != block->hash[i])
        {
            printf("Invalid block hash\n");
            Free(block_data);
            Close(peer_socket);
            return;
        }
    }

    FILE* fp = Fopen(output_file, "rb+");
    if (fp == 0)
    {
        printf("Failed to open destination: %s\n", output_file);
        free(block_data);
        Close(peer_socket);
        return;
    }
    fseek(fp, block->offset, SEEK_SET);
    Fputs(block_data, fp);

    Free(block_data);
    Close(peer_socket);
    Fclose(fp);
}

/*
 * Get a list of peers on the network from a tracker. Note that this query is doing double duty according to
 * the protocol, and by asking for a list of peers we are also enrolling on the network ourselves.
 */
int get_peers_list(hashdata_t hash)
{
    rio_t rio;
    char msg_buf[MAXLINE];

    int tracker_socket = Open_clientfd(tracker_ip, tracker_port);
    Rio_readinitb(&rio, tracker_socket);

    struct RequestHeader request_header;
    // memcpy as it does not end with terminating null byte.
    memcpy(request_header.protocol, "CASC", sizeof(request_header.protocol));

    request_header.version = htonl(1);
    request_header.command = htonl(1);
    request_header.length = htonl(BODY_SIZE);
    memcpy(msg_buf, &request_header, HEADER_SIZE);

    struct in_addr byte_my_ip;
    inet_aton(my_ip, &byte_my_ip);

    struct RequestBody request_body;
    memcpy(request_body.hash, hash, SHA256_HASH_SIZE);
    request_body.ip = byte_my_ip;
    request_body.port = htons(atoi(my_port));
    memcpy(msg_buf + HEADER_SIZE, &request_body, BODY_SIZE);

    Rio_writen(tracker_socket, msg_buf, MESSAGE_SIZE);

    Rio_readnb(&rio, msg_buf, MAXLINE);

    char reply_header[REPLY_HEADER_SIZE];
    memcpy(reply_header, msg_buf, REPLY_HEADER_SIZE);

    uint32_t msglen = ntohl(*(uint32_t*)&reply_header[1]);
    if (msglen == 0)
    {
        return 0;
    }

    if (reply_header[0] != 0)
    {
        char* error_buf = Malloc(msglen + 1);
        if (error_buf == NULL)
        {
            printf("Tracker error %d and out-of-memory reading error\n", reply_header[0]);
            Close(tracker_socket);
            return 0;
        }
        memset(error_buf, 0, msglen + 1);
        memcpy(reply_header, error_buf, msglen);
        printf("Tracker gave error: %d - %s\n", reply_header[0], error_buf);
        Free(error_buf);
        Close(tracker_socket);
        return 0;
    }

    if (msglen % 12 != 0)
    {
        printf("LIST response from tracker was length %ud but should be evenly divisible by 12\n", msglen);
        Close(tracker_socket);
        return 0;
    }

    unsigned char body[msglen];
    memcpy(body, msg_buf+REPLY_HEADER_SIZE, msglen);

    int peercount = 0;
    peercount = (uint32_t)(msglen / 12);
    peers = Malloc(sizeof(csc_peer_t) * peercount);

    for(int i = 0; i < peercount; i++)
    {
        uint8_t peerdata[12];
        memcpy(peerdata, body+(12*i), 12);        
               
        uint32_t ip_buf;        
        memcpy(&ip_buf, peerdata, 4);

        char ip[IP_LEN];
        struct in_addr ip_addr;
        ip_addr.s_addr = ip_buf;
        memcpy(ip, inet_ntoa(ip_addr), IP_LEN);    
                
        char port_buf[PORT_LEN]; 
        sprintf(port_buf, "%1d", ntohs(*((uint16_t*)&peerdata[4])));       
       
        uint32_t lastseen = *((uint32_t*)&peerdata[6]);

        memcpy(&peers[i].ip, ip, IP_LEN);
        memcpy(&peers[i].port, port_buf, PORT_LEN);
        peers[i].lastseen = ntohl(lastseen);
        peers[i].good = peerdata[10];

        printf("Got peer with IP: %s, and Port: %s\n", ip, port_buf);
    }
    Close(tracker_socket);
    return peercount;
}


/*
 * Writes the status code and msg to the given file descriptor
 */
void reporterror(int connfd, char code, char* msg) {
    uint64_t msglen = strlen(msg);
    uint64_t msglenNetwork = htobe64(msglen);

    char buf[MAXLINE];

    memcpy(buf, &code, 1);
    memcpy(buf + 1, &msglenNetwork, 8);
    memcpy(buf + 9, msg, msglen);

    Rio_writen(connfd, buf, 9 + msglen);

    Close(connfd); 

}

/*
 * Read request from a peer and write back the requested block
 * or the appropriate error code and message
 */
void* handle(void *arg) {
    int connfd = *((int *) arg);
    assert(pthread_mutex_unlock(&ConnLock) == 0);

    rio_t rio;
    char msg_buf[MAXLINE];

    Rio_readinitb(&rio, connfd);

    // Read request
    Rio_readnb(&rio, msg_buf, PEER_REQUEST_HEADER_SIZE);

    uint64_t RequestedBlock;
    char RequestedCascadeHash[32];

    RequestedBlock = be64toh(*((unsigned long long*)&msg_buf[24]));
    memcpy(RequestedCascadeHash, &msg_buf[32], SHA256_HASH_SIZE);

    int fileFound = 0;
    csc_file_t* csc_file;
    char* output_file;
    
    // Search for file
    assert(pthread_mutex_lock(activeFiles->lock) == 0);
    for (int i = 0; i < activeFiles->length; i++) {
        if (memcmp(activeFiles->csc_files[i].cascadeHash, RequestedCascadeHash, SHA256_HASH_SIZE) == 0) {
            
            fileFound = 1;
            csc_file = activeFiles->csc_files[i].csc_file;
            output_file = activeFiles->csc_files[i].output_file;
        }
    }
    assert(pthread_mutex_unlock(activeFiles->lock) == 0);

    // Check if file is servered
    if (fileFound == 0) {
        reporterror(connfd, 1, "Requested hash is not servered");
        pthread_exit(NULL);
    }

    // Check if block number is too large
    if (RequestedBlock >= csc_file->blockcount) {
        reporterror(connfd, 3, "Requested block numbers was higher then file total block count");
        pthread_exit(NULL);
    }

    // check if requested block is present
    if(csc_file->blocks[RequestedBlock].completed != 1) {
        reporterror(connfd, 2, "Block number is not currently held by this peer");
        pthread_exit(NULL);
    }

    uint64_t body_length = csc_file->blocks[RequestedBlock].length;

    char *block_data = Calloc(body_length, sizeof(char));
    
    FILE* fp = Fopen(output_file, "rb+");
    if (fp == 0)
    {
        printf("Failed to open destination: %s\n", output_file);
        free(block_data);
        Close(connfd); 
        pthread_exit(NULL); 
    }
    fseek(fp, csc_file->blocks[RequestedBlock].offset, SEEK_SET);
    
    // 1 = status_code, 8 = msg length
    char* reply_buf = Calloc(1+8+body_length, sizeof(char));

    uint64_t msglenNetwork = htobe64(body_length);

    char status_code = 0;
    memcpy(reply_buf, &status_code, 1);
    memcpy(reply_buf + 1, &msglenNetwork, 8);
    // Read from file to reply buffer
    rio_readn(fileno(fp), reply_buf + 9, body_length);

    // Write to socket.
    rio_writen(connfd, reply_buf, 1+8+body_length);
    
    fclose(fp);
    Close(connfd); 
    
    pthread_exit(NULL);
}

/*
 * Accept incoming connections and create handle threads
 * to process these requests.
 */
void* server() {
    int listenfd;
    socklen_t clientlen;
    struct sockaddr clientaddr;

    listenfd = open_listenfd(my_port);

    pthread_t *threads = calloc(30000, sizeof(pthread_t));
    int indx = 0;

    while(1) {
        assert(pthread_mutex_lock(&ConnLock) == 0);
        clientlen = sizeof(clientaddr);
        int connfd = Accept(listenfd, (SA *) &clientaddr, &clientlen); // Waits for connection to happen

        if (connfd == -1) {
            assert(pthread_mutex_unlock(&ConnLock) == 0);
        } else {
            // Create thread to handle block request
            if (pthread_create(&threads[indx], NULL, &handle, &connfd) != 0) {
                err(1, "pthread_create() failed");
                assert(pthread_mutex_unlock(&ConnLock) == 0);
            }
            indx++;
        }
 
    }

    for (int i = 0; i < indx; i++) {
        if (pthread_join(threads[i], NULL) != 0) {
            err(1, "pthread_join() failed");
        }
    }

    pthread_exit(NULL);
}


/*
 * The entry point for the code. Parses command line arguments and starts up the appropriate peer code.
 */
int main(int argc, char **argv)
{
    if (argc != MAIN_ARGNUM + 1)
    {
        fprintf(stderr, "Usage: %s <cascade file(s)> <tracker server ip> <tracker server port> <peer ip> <peer port>.\n", argv[0]);
        exit(EXIT_FAILURE);
    }
    else if (!is_valid_ip(argv[2]))
    {
        fprintf(stderr, ">> Invalid tracker IP: %s\n", argv[2]);
        exit(EXIT_FAILURE);
    }
    else if (!is_valid_port(argv[3]))
    {
        fprintf(stderr, ">> Invalid tracker port: %s\n", argv[3]);
        exit(EXIT_FAILURE);
    }
    else if (!is_valid_ip(argv[4]))
    {
        fprintf(stderr, ">> Invalid peer IP: %s\n", argv[4]);
        exit(EXIT_FAILURE);
    }
    else if (!is_valid_port(argv[5]))
    {
        fprintf(stderr, ">> Invalid peer port: %s\n", argv[5]);
        exit(EXIT_FAILURE);
    }

    snprintf(tracker_ip,   IP_LEN, "%s",   argv[2]);
    snprintf(tracker_port, PORT_LEN, "%s", argv[3]);
    snprintf(my_ip,   IP_LEN, "%s",   argv[4]);
    snprintf(my_port, PORT_LEN, "%s", argv[5]);

    char cas_str[strlen(argv[1])];
    snprintf(cas_str, strlen(argv[1])+1, "%s", argv[1]);
    char delim[] = ":";

    int casc_count = count_occurences(argv[1], ':') + 1;
    char *cascade_files[casc_count];

    char *ptr = strtok(cas_str, delim);
    int i = 0;

    while (ptr != NULL)
    {
        if (strstr(ptr, ".cascade") != NULL)
        {
            cascade_files[i++] = ptr;
            ptr = strtok(NULL, delim);
        }
        else
        {
            printf("Abort on %s\n", ptr);
            fprintf(stderr, ">> Invalid cascade file: %s\n", ptr);
            exit(EXIT_FAILURE);
        }
    }

    activeFiles = malloc(sizeof(struct Activefiles*));
    activeFiles->lock = malloc(sizeof(pthread_mutex_t));
    pthread_mutex_init(activeFiles->lock, NULL);

    activeFiles->csc_files = calloc(casc_count, sizeof(struct ActiveFile*));

    // Create our server
    pthread_t server_thread;
    if (pthread_create(&server_thread, NULL, &server, NULL) != 0) {
      err(1, "pthread_create() failed");
    }

    // Download files
    for (int j=0; j<casc_count; j++)
    {
        printf("[ Getting file %i ]\n", j);
        download_only_peer(cascade_files[j]);
    }
    
    // Wait for server to stop
    if (pthread_join(server_thread, NULL) != 0) {
      err(1, "pthread_join() failed");
    }

    // Free activefiles
    for (int i = 0; i < casc_count; i++)
    {
        csc_free_file(activeFiles->csc_files[i].csc_file);
    }
    free(activeFiles->csc_files);
    activeFiles->csc_files = NULL;
    free(activeFiles->lock);
    activeFiles->lock = NULL;
    free(activeFiles); 

    exit(EXIT_SUCCESS);
}
