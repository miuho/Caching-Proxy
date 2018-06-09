/* 
 * proxy.c
 *
 * A multi-threading proxy with cache.
 * 
 * HingOn Miu
 * hmiu
 */

#include "csapp.h"

#define MAX_CACHE_SIZE 1049000
#define MAX_OBJECT_SIZE 102400
#define NUM_OF_SETS 40
#define NUM_OF_LINES 20
#define LARGE 1<<16
#define DEFAULT_PORT 80

/* Global variables */
int verbose = 0;            /* if true, print additional output */
int cache_verbose = 0;      /* if true, print additional output for caching */

static const char *user_agent_header =
"User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:10.0.3) Gecko/20120305 Firefox/10.0.3\r\n";
static const char *accept_header =
"Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n";
static const char *accept_encoding_header =
"Accept-Encoding: gzip, deflate\r\n";
static const char *connection_header = "Connection: close\r\n";
static const char *proxy_connection_header = "Proxy-Connection: close\r\n";
pthread_mutex_t open_clientfd_lock;
pthread_mutex_t used_count_lock1;
pthread_mutex_t used_count_lock2;
pthread_mutex_t used_count_lock3;

/* global for later storing the cache's pointer address */
struct cache* Cache = NULL;

/* Helper Functions */
void usage(void);
void doit(int connect_fd);
void *thread(void *vargp);

/* structure for a line in the sets of the cache, and I use path as the tag */
/* for referencing to a line in a set*/
struct cache_line{
    int valid;                  /* the valid bit*/
    char path[MAXLINE];         /* tag of line */
    int content_size;           /* size of data cached */
    int used_count;    /* keep counts for the LRU policy on replacing lines */
    char *content;                 /* data stored */
};

/* initialize the values in cache_line */
void *init_cache_line(void){
    struct cache_line *line = malloc(sizeof(struct cache_line));
    line->valid = 0;            /* originally not a valid line */
    line->path[0] = '\0';
    line->content_size = 0;
    line->used_count = 0;
    line->content = NULL;
    return line;
}

/* structure for a set in the cache, and I use hostname as the index for */
/* referencing to a set in the cache */
struct cache_set{
    char hostname[MAXLINE];     /* index to locate set */
    int used_count;    /* keep counts for the LRU policy on replacing sets */
    struct cache_line *lines[NUM_OF_LINES];
    /* a list of pointer to lines in this set structure */
};

/* initialize the values in cache_set */
void *init_cache_set(void){
    struct cache_set *set = malloc(sizeof(struct cache_set));
    set->hostname[0] = '\0';
    int i;
    for (i = 0; i < NUM_OF_LINES; i++){
        set->lines[i] = NULL;     /* all line pointers are originally NULL */
    }
    set->used_count = 0;
    return set;
}

/* structure for a cache */
struct cache{
    struct cache_set *sets[NUM_OF_SETS];
    /* a list of pointer to sets in this cache structure */
    int current_cache_size; /* keeps record of the total size of data cached */
};

/* initialize the values in cache */
void *init_cache(void){
    struct cache *cach = malloc(sizeof(struct cache));
    cach->current_cache_size = 0;
    int i;
    for (i = 0; i < NUM_OF_SETS; i++){
        cach->sets[i] = NULL;     /* all set pointers are originally NULL */
    }
    return cach;
}

/* search for a matched path line */
/* search for the cached data, returns a pointer to that data if it is cached */
/* with provided hostname (as index of cache) and path (as tag of cache) */
/* if not found, return NULL pointer */
char *cache_sets_search(struct cache_set *set,char *hostname_in,char *path_in){ 
    int i;
    /* look for a line that share same path */
    for (i = 0; i < NUM_OF_LINES; i++){
        /* to avoid deferencing NULL pointer, and ends the search if no */
        /* matching path */
        if (set->lines[i] == NULL) return NULL;
        
        if (cache_verbose)
            printf("search |%s %s|\n",set->lines[i]->path, path_in);
        
        /* if found matched path, returns that pointer, and increment the */
        /* used_count for both the set and the line for late implementing */
        /* LRU policy */
        if (!strcmp(set->lines[i]->path, path_in)) {
            pthread_mutex_lock(&used_count_lock1);
            set->used_count++;
            set->lines[i]->used_count++;
            pthread_mutex_unlock(&used_count_lock1);
            return set->lines[i]->content;
        }
    }
    /* no matching path */
    return NULL;
}

/* search for a matched hostname set */
/* search for the cached data, returns a pointer to that data if it is cached */
/* with provided hostname (as index of cache) and path (as tag of cache) */
/* if not found, return NULL pointer */
char *cache_search(char *hostname_in, char *path_in){
    int i;
    /* look for a set that share same hostname */
    for (i = 0; i < NUM_OF_SETS; i++){
        /* to avoid deferencing NULL pointer, and ends the search if no */
        /* matching hostname */
        if (Cache->sets[i] == NULL) return NULL;
        
        if (cache_verbose)
            printf("search |%s %s|\n",Cache->sets[i]->hostname, hostname_in);
        
        /* if found matched hostname, go into that set and search if the line */
        /* that shares the same path exist, if so, returns that pointer */
        if (!strcmp(Cache->sets[i]->hostname, hostname_in)) {
            return cache_sets_search(Cache->sets[i], hostname_in, path_in);
        }
    }
    /* no matching hostname */
    return NULL;
}

/* insert into the right line in set with provided path */
/* since I always call insert after search, so I can safely assume when I */
/* insert something in cache, it should not previously be cached */
void cache_sets_insert(struct cache_set *set, char *hostname_in,
                       char *path_in, char *content_in, int size_in){
    
    int i;
    /* look for a line that is uninitialized */
    for (i = 0; i < NUM_OF_LINES; i++){
        /* to avoid deferencing NULL pointer, and ends the search if no */
        /* matching path */
        if (set->lines[i] == NULL) break;
    }
    if (cache_verbose) printf("empty ith line: %i\n", i);
    /* create a new line if set not full */
    if (i != NUM_OF_LINES) {
        set->lines[i] = init_cache_line();
        if (cache_verbose)
            printf("cache line initialized\n");
        set->lines[i]->valid = 1;
        strcpy(set->lines[i]->path, path_in);
        if (cache_verbose)
            printf("cache set line copied: %s\n", set->lines[i]->path);
        set->lines[i]->content_size = size_in;
        set->lines[i]->used_count = 0;
        
        /* allocate the size for copying in the data */
        set->lines[i]->content = malloc(size_in);
        memcpy(set->lines[i]->content, content_in, size_in);
        
        /* keep up with the cache's current size */
        pthread_mutex_lock(&used_count_lock2);
        Cache->current_cache_size += size_in;
        pthread_mutex_unlock(&used_count_lock2);
        return;
    }
    else { /* all lines in set are taken, use LRU to replace a line */
        int j;
        int min = LARGE;
        int k;
        for (j = 0; j < NUM_OF_LINES; j++){
            if (set->lines[j] == NULL) return;
            
            if (min > set->lines[j]->used_count) {
                min = set->lines[j]->used_count;
                k = j; /* stored the min used line's index in list */
            }
        }
        if (cache_verbose)
            printf("min used ith line: %i\n", k);
        int replaced_size = set->lines[k]->content_size; 
        set->lines[k] = init_cache_line();
        if (cache_verbose)
            printf("cache line initialized\n");
        set->lines[k]->valid = 1;
        strcpy(set->lines[k]->path, path_in);
        if (cache_verbose)
            printf("cache set line copied: %s\n", set->lines[k]->path);
        set->lines[k]->content_size = size_in;
        set->lines[k]->used_count = 0;
        
        /* allocate the size for copying in the data */
        set->lines[k]->content = malloc(size_in);
        memcpy(set->lines[k]->content, content_in, size_in);
        
        /* keep up with the cache's current size */
        pthread_mutex_lock(&used_count_lock3);
        Cache->current_cache_size -= replaced_size;
        Cache->current_cache_size += size_in;
        pthread_mutex_lock(&used_count_lock3);
        return;
    }
}

/* insert into the right set in cache with provided hostname */
/* since I always call insert after search, so I can safely assume when I */
/* insert something in cache, it should not previously be cached */
void cache_insert(char *hostname_in,char *path_in,char *content_in,int size_in){
    int i;
    /* look for a set that share same hostname */
    for (i = 0; i < NUM_OF_SETS; i++){
        /* to avoid deferencing NULL pointer, and ends the search if no */
        /* matching hostname */
        if (Cache->sets[i] == NULL) break;
        
        if (cache_verbose)
            printf("insert |%s %s|\n",Cache->sets[i]->hostname, hostname_in);
        
        /* if found matched hostname, go into that set and create a new line */
        /* in that set */
        if (!strcmp(Cache->sets[i]->hostname, hostname_in)) {
            cache_sets_insert(Cache->sets[i], hostname_in,
                              path_in, content_in, size_in);
            return;
        }
    }
    if (cache_verbose) printf("empty ith set: %i\n", i);
    /* if not found, create a new set of new hostname if cache not full */
    if (i != NUM_OF_SETS) {
        int p;
        /* store the index of the available set pointer in list */
        for (p = 0; p < NUM_OF_SETS; p++){
            if (Cache->sets[p] == NULL) break;
        }
        Cache->sets[p] = init_cache_set();
        if (cache_verbose) printf("cache set initialized\n");
        strcpy(Cache->sets[p]->hostname, hostname_in);
        if (cache_verbose)
            printf("cache set hostname copied: %s\n", Cache->sets[p]->hostname);
        Cache->sets[p]->used_count = 0;
        if (cache_verbose)
            printf("cache set used_count zerod\n");
        
        /* create a new line in this new set */
        cache_sets_insert(Cache->sets[p], hostname_in,
                          path_in, content_in, size_in);
        return;
    }
    else { /* all set slots are taken, use LRU to replace a whole set */
        int j;
        int min = LARGE;
        int k;
        for (j = 0; j < NUM_OF_SETS; j++){
            if (Cache->sets[j] == NULL) return;
            
            if (min > Cache->sets[j]->used_count) {
                min = Cache->sets[j]->used_count;
                k = j;  /* stored the min used set's index in list */
            }
        }
        if (cache_verbose) printf("min used ith set: %i\n", k);
        Cache->sets[k] = init_cache_set();
        if (cache_verbose) printf("cache set initialized\n");
        strcpy(Cache->sets[k]->hostname, hostname_in);
        if (cache_verbose)
            printf("cache set hostname copied: %s\n", Cache->sets[k]->hostname);
        Cache->sets[k]->used_count = 0;
        if (cache_verbose)
            printf("cache set used_count zerod\n");
        
        /* create a new line in this new set */
        cache_sets_insert(Cache->sets[k], hostname_in,
                          path_in, content_in, size_in);
        return;
    }
}



int main(int argc, char **argv)
{
    char c;
    int listening_port;
    int listen_fd;
    int *connect_fdp;
    struct sockaddr_in client_address;
    pthread_t thread_id;
    
    /* parse the command line */
    while ((c = getopt(argc, argv, "hv")) != EOF) {
        switch (c) {
        case 'h':             /* print help message */
            usage();
            break;
        case 'v':             /* additional diagnostic info */
            verbose = 1;
            cache_verbose = 1;
            break;
        default:
            usage();
        }
    } 
    
    /* make sure there two arguments, and in the right format */
    if (argc == 2) {
        listening_port = atoi(argv[1]);
        /* port is defined to be a 16 bit integer */
        if (listening_port < 0 || listening_port > (1 << 16)) {
            printf("invalid listening port number\n");
            exit(0);
        } 
    }
    else {
        usage();
    }
    
    /* initialize the cache and store the pointe into a global */
    struct cache* temp = init_cache();
    Cache = temp;
    
    /* make sure listening port number can open a listen fd */
    if ((listen_fd = open_listenfd(listening_port)) == -1){
        printf("cannot open listen file descriptor\n");
        exit(0);
    }
    
    socklen_t client_address_length = sizeof(struct sockaddr_in);
    
    /* sychronization is done by mutex, proxy should abort without it */
    if (pthread_mutex_init(&open_clientfd_lock, NULL) != 0) {
        printf("mutex cannot be initialized\n");
        exit(0);
    }
    /* sychronization is done by mutex, proxy should abort without it */
    if (pthread_mutex_init(&used_count_lock1, NULL) != 0) {
        printf("mutex cannot be initialized\n");
        exit(0);
    }
    /* sychronization is done by mutex, proxy should abort without it */
    if (pthread_mutex_init(&used_count_lock2, NULL) != 0) {
        printf("mutex cannot be initialized\n");
        exit(0);
    }
    /* sychronization is done by mutex, proxy should abort without it */
    if (pthread_mutex_init(&used_count_lock3, NULL) != 0) {
        printf("mutex cannot be initialized\n");
        exit(0);
    }
    
    /* block SIGPIPE to not terminate the proxy */
    Signal(SIGPIPE, SIG_IGN); 
    
    while (1) {
        
        connect_fdp = malloc(sizeof(int));
        
        /* accept connection from client and open connect_fdp */
        if ((*(int *)connect_fdp = accept(listen_fd,(SA *)&client_address,
                                          &client_address_length)) == -1){
            printf("connection failue\n");
            /* request connection failure should not terminate the proxy */ 
            continue;
        }
        
        /* create a new thread to run a connection */
        if ((pthread_create(&thread_id, NULL, thread, connect_fdp)) != 0){
            printf("cannot create new thread\n");
            /* failure to create thread should not terminate the proxy */
            continue;
        }
    }
    
    /* sychronization is done by mutex, proxy should abort without it */
    if (pthread_mutex_destroy(&open_clientfd_lock) != 0) {
        printf("mutex cannot be destroyed\n");
        exit(0);
    }
    /* sychronization is done by mutex, proxy should abort without it */
    if (pthread_mutex_destroy(&used_count_lock1) != 0) {
        printf("mutex cannot be destroyed\n");
        exit(0);
    }
    /* sychronization is done by mutex, proxy should abort without it */
    if (pthread_mutex_destroy(&used_count_lock2) != 0) {
        printf("mutex cannot be destroyed\n");
        exit(0);
    }
    /* sychronization is done by mutex, proxy should abort without it */
    if (pthread_mutex_destroy(&used_count_lock3) != 0) {
        printf("mutex cannot be destroyed\n");
        exit(0);
    }
    return 0;
}

/*
 * the thread routine
 */
void *thread(void *vargp)  {
    int connect_fd;
    
    /* to avoid killing a thread would affect other running threads */
    if ((pthread_detach(pthread_self())) != 0){
        printf("cannot detach thread\n");
        /* cancel the current thread only if cannot detach thread */
        if ((pthread_cancel(pthread_self())) != 0){
            printf("cannot cancel thread\n");
            /* if both cannot detach and cancel the thread, something */
            /* must be badly wrong and should terminate the proxy */
            exit(0);
        }
    }
    
    connect_fd = *((int *)vargp);
    free(vargp);
    
    /* all the sending and reciving from client to server and from server to */
    /* client */
    doit(connect_fd);
    
    if (close(connect_fd) < 0) {
        printf("cannot close connecting file descriptor\n");
        /* failure to close connecting fd should not terminate the proxy */
    }
    
    return NULL;
}

int client_2_server(rio_t *client_riop, char *hostname, int request_port, char *method,
		     char *path, char *version){
    int client_fd;
    char buf[MAXLINE];
    /* gethostbyname is thread-unsafe, so mutex locking limit one thread only */
    pthread_mutex_lock(&open_clientfd_lock);
    
    /* open server connection */
    if ((client_fd = open_clientfd(hostname, request_port)) < 0) {
        printf("cannot connect to server\n");
        /* destroying locked mutex is undefined, all locks must be unlocked */
        pthread_mutex_unlock(&open_clientfd_lock);
        if (close(client_fd) < 0) {
            printf("cannot close client-server file descriptor\n");
            /* failure to close client-server fd should not abort the proxy */
        }
        /* proxy should not terminate due to connection failure */
        return -1;
    }
    
    pthread_mutex_unlock(&open_clientfd_lock);
    
    /* construct a HTTP request for server */
    sprintf(buf, "%s %s %s\r\n", method, path, version);
    if (rio_writen(client_fd, buf, strlen(buf)) != strlen(buf)) {
        printf("cannot write to server\n");
        /* proxy should not terminate due to writing error */
        if (close(client_fd) < 0) {
            printf("cannot close client-server file descriptor\n");
            /* failure to close client-server fd should not abort the proxy */
        }
        return -1;
    }
    /* send server the user_agent_header */
    if (rio_writen(client_fd, (void *)user_agent_header,
                    strlen(user_agent_header))
                    != strlen(user_agent_header)) {
        printf("cannot write to server\n");
        /* proxy should not terminate due to writing error */
        if (close(client_fd) < 0) {
            printf("cannot close client-server file descriptor\n");
            /* failure to close client-server fd should not abort the proxy */
        }
        return -1;
    }
    /* send server the accept_header */
    if (rio_writen(client_fd, (void *)accept_header,
                    strlen(accept_header))
                    != strlen(accept_header)) {
        printf("cannot write to server\n");
        /* proxy should not terminate due to writing error */
        if (close(client_fd) < 0) {
            printf("cannot close client-server file descriptor\n");
            /* failure to close client-server fd should not abort the proxy */
        }
        return -1;
    }
    /* send server the accept_encoding_header */
    if (rio_writen(client_fd, (void *)accept_encoding_header,
                    strlen(accept_encoding_header))
                    != strlen(accept_encoding_header)) {
        printf("cannot write to server\n");
        /* proxy should not terminate due to writing error */
        if (close(client_fd) < 0) {
            printf("cannot close client-server file descriptor\n");
            /* failure to close client-server fd should not abort the proxy */
        }
        return -1;
    }
    /* send server the connection_header */
    if (rio_writen(client_fd, (void *)connection_header,
                    strlen(connection_header))
                    != strlen(connection_header)) {
        printf("cannot write to server\n");
        /* proxy should not terminate due to writing error */
        if (close(client_fd) < 0) {
            printf("cannot close client-server file descriptor\n");
            /* failure to close client-server fd should not abort the proxy */
        }
        return -1;
    }
    /* send server the proxy_connection_header */
    if (rio_writen(client_fd, (void *)proxy_connection_header,
                    strlen(proxy_connection_header))
                    != strlen(proxy_connection_header)) {
        printf("cannot write to server\n");
        /* proxy should not terminate due to writing error */
        if (close(client_fd) < 0) {
            printf("cannot close client-server file descriptor\n");
            /* failure to close client-server fd should not abort the proxy */
        }
        return -1;
    }
    
    int data_read = 1;
    int host_len = strlen("Host:");
    int host_sent = 0;    /* record whether the client provide a host header */
    int user_len = strlen("User-Agent:");
    int accept_len = strlen("Accept:");
    int accept_encode_len = strlen("Accept-Encoding:");
    int connection_len = strlen("Connection:");
    int pconnection_len = strlen("Proxy-Connection:");
    /* reading the rest of HTTP request from client beside default headers */
    while(strcmp(buf,"\r\n")) {
        /* data_read == 0 when EOF */
        if ((data_read = rio_readlineb(client_riop, buf, MAXLINE)) < 0){
            printf("cannot read line from client request\n");
            /* proxy should not terminate due to rio read line error */
            if (close(client_fd) < 0) {
                printf("cannot close client-server file descriptor\n");
                /* fail to close client-server fd should not abort the proxy */
            }
            return -1;
        }
        
        if (verbose) printf("%i %s\n", data_read, buf);
        
        if (!strcmp(buf, "\r\n")) {
            /* since we need to use the client original host header if they */
            /* provide it, I need to check it is sent already. If not, I */
            /* then need to make one and send it before "\r\n" is sent */
            if (!host_sent) {
                sprintf(buf, "Host: %s\r\n", hostname);
                if (rio_writen(client_fd, buf, strlen(buf)) != strlen(buf)) {
                    printf("cannot write to server\n");
                    /* proxy should not terminate due to writing error */
                    if (close(client_fd) < 0) {
                        printf("cannot close client-server file descriptor\n");
                    }
                    return -1;
                }
            }
            /* send the end of the request headers */
            if (rio_writen(client_fd, "\r\n", strlen("\r\n"))!=strlen("\r\n")){
                printf("cannot write to server\n");
                /* proxy should not terminate due to writing error */
                if (close(client_fd) < 0) {
                    printf("cannot close client-server file descriptor\n");
                }
                return -1;
            }
            break;
        }
        
        if (!strncasecmp(buf, "Host:", host_len)) {
            host_sent = 1;
        }
        if (!strncasecmp(buf, "User-Agent:", user_len)) {
            continue;
        }
        if (!strncasecmp(buf, "Accept:", accept_len)) {
            continue;
        }
        if (!strncasecmp(buf, "Accept-Encoding:", accept_encode_len)) {
            continue;
        }
        if (!strncasecmp(buf, "Connection:", connection_len)) {
            continue;
        }
        if (!strncasecmp(buf, "Proxy-Connection:", pconnection_len)) {
            continue;
        }
        
        if (verbose) printf("%i %s\n", data_read, buf);
        
        if (rio_writen(client_fd, buf, data_read) != data_read) {
            printf("cannot write to server\n");
            /* proxy should not terminate due to writing error */
            if (close(client_fd) < 0) {
                printf("cannot close client-server file descriptor\n");
                /* fail to close client-server fd should not abort the proxy */
            }
            return -1;
        }
    }
    return client_fd;
}


char *content = NULL;

void server_2_client(rio_t *server_riop, int client_fd, int connect_fd, int head){
    int data_read = 1;
    char cont[MAX_OBJECT_SIZE];
    char buf[MAXLINE];
    content[0] = '\0';
    /* recieving response from server and forward to client */
    while(data_read != 0) {
        /* data_read == 0 when EOF */
        if ((data_read = rio_readlineb(server_riop, buf, MAXLINE)) < 0){
            printf("cannot read line from server response\n");
            /* proxy should not terminate due to rio read line error */
            if (close(client_fd) < 0) {
                printf("cannot close client-server file descriptor\n");
                /* fail to close client-server fd should not abort the proxy */
            }
            return;
        }
        /* concatenate the data for later caching */
        strcat(cont, buf);
        
        if (head && !strncasecmp(buf, "<", 1)) {
            /* if it was a HEAD request, it checks if it has the format of */
            /* a response body, and skip it if it is */
            continue;
        }
        if (verbose) printf("%s\n", buf);
        
        if (rio_writen(connect_fd, buf, data_read) != data_read) {
            printf("cannot write back to client\n");
            /* proxy should not terminate due to writing error */
            if (close(client_fd) < 0) {
                printf("cannot close client-server file descriptor\n");
                /* fail to close client-server fd should not abort the proxy */
            } 
            return;
        }
    }
    content = cont;
}

/*
 * doit - handle one HTTP request/response transaction
 */
void doit(int connect_fd) { 
    char buf[MAXLINE], method[MAXLINE], url[MAXLINE], version[MAXLINE];
    int request_port;
    int http_len = strlen("http://");
    rio_t client_rio;
    rio_t server_rio;
    
    /* Read request line and headers */
    Rio_readinitb(&client_rio, connect_fd);
    
    /* read the first line into buf */
    if ((rio_readlineb(&client_rio, buf, MAXLINE)) < 0){
        printf("cannot read line from client request\n");
        /* proxy should not terminate due to rio read line error */
        return;
    }
    
    /* store the method, url, and version of the request from client */
    sscanf(buf, "%s %s %s", method, url, version);
    
    if (verbose) printf("%s %s %s\n", method, url, version);
    
    int url_len = strlen(url);
    
    /* Parse the url request */
    char port[MAXLINE], hostname[MAXLINE], path[MAXLINE];
    int hostname_begin = http_len;
    int port_begin = http_len;
    int path_begin = http_len;
    
    int i;
    for (i = http_len; i < url_len; i++) {
        if (url[i] == ':') { /* record where port begins */
            port_begin = i+1;
            continue;
        }
        
        if (url[i] == '/') { /* record where path begins */
            path_begin = i+1;
            break;
        }
    }
    
    /* get the hostname */
    int hostname_end;
    /* check if port is given */
    if (port_begin == http_len) {
        /* check if path is given */
        if (path_begin == http_len) {
            /* if both port and path not given */
            hostname_end = url_len;
        }
        else {
            /* if port is not given but path is given */
            hostname_end = path_begin - 1;
        }
    }
    else {
        /* if both port and path are given */
        hostname_end = port_begin - 1;
    }
    int p = 0;
    int q;
    for (q = hostname_begin; q < hostname_end; q++){
        /* get the hostname from url */
        hostname[p] = url[q];
        p++;
    }
    hostname[p] = '\0';
    
    /* get the request port number */
    /* check if port is given */
    if (port_begin == http_len) {
        /* default port number is 80 */
        request_port = DEFAULT_PORT; /* if port is not given */
    }
    else {
        int port_end;
        /* check if path is given */
        if (path_begin == http_len) {
            /* if port is given but path is not given */
            port_end = url_len;
        }
        else {
            /* if both port and path are given */
            port_end = path_begin - 1;
        }
        
        int k = 0;
        int j;
        for (j = port_begin; j < port_end; j++){
            /* get the port from url */
            port[k] = url[j];
            k++;
        }
        port[k] = '\0';
        request_port = atoi(port);
    }
    
    /* get the path */
    int path_end;
    /* check if path is given */
    path[0] = '/';
    if (path_begin == http_len) {
        path[1] = '\0';      /* if path is not given */
    }
    else {
        /* if path is given */
        path_end = url_len;
        int m = 1;
        int n;
        for (n = path_begin; n < path_end; n++){
            /* get the path from url */
            path[m] = url[n];
            m++;
        }
        path[m] = '\0';
    }
    
    if (verbose) printf("%s %s %i\n", hostname, path, request_port);
    
    /* make sure the client request later got forward as HTTP/1.0 requests */
    version[strlen("HTTP/1.0") - 1] = '0';
    
    int head = 0; /* record if it is a head request */
    if (!strcmp(method, "HEAD")) { 
        /* HEAD is basically the same as GET, but server does not respond */
        /* a response body, so I will get rid of it when server responds */
        method[0] = 'G';
        method[1] = 'E';
        method[2] = 'T';
        method[3] = '\0';
        head = 1;
    }
    
    if (!strcmp(method, "CONNECT")) { 
        /* this proxy's connect should be left closed, so building up */
        /* a open connection with between the proxy and the server is */
        /* not nessary, so we can ignore CONNECT requests */
        return;
    }
    
    /* proxy should not terminate due to malformed requests */
    if (strcmp(method, "GET")) { 
        return;
    }
    
    if (verbose) printf("%s %s %s\n", method, url, version);
    
    if (cache_verbose) printf("before search\n");
    
    /* search whether if there is a line with matched path in a set with */
    /* matched set in the cache */
    char *cached_buf = cache_search(hostname, path);
    /* simply return that cached data to client without connecting to server */
    if (cached_buf != NULL) {
        int cached_buf_length = strlen(cached_buf);
        if (cache_verbose) printf("find cached content\n");
        if (rio_writen(connect_fd, cached_buf, cached_buf_length)
            != cached_buf_length) {
            printf("cannot write back to client\n");
            /* proxy should not terminate due to writing error */
            return;
        }
        return;
    }
    
    if (cache_verbose) printf("after search\n");
    
    int client_fd = client_2_server(&client_rio, hostname, request_port, method, path, version);
    
    Rio_readinitb(&server_rio, client_fd);
    
    server_2_client(&server_rio, client_fd, connect_fd, head);
    
    if (cache_verbose) printf("before insert\n");
    
    /* check if the data size exceeds MAX_OBJECT_SIZE and if cache exceeds */
    /* MAX_CACHE_SIZE before caching */
    int read_sum = strlen(content);
    if (read_sum <= MAX_OBJECT_SIZE &&
        Cache->current_cache_size <= MAX_CACHE_SIZE) {
        cache_insert(hostname, path, content, read_sum);
    }
    
    if (cache_verbose) printf("after insert\n");
    
    /* we are done with the client-server file descriptor */
    if (close(client_fd) < 0) {
        printf("cannot close client-server file descriptor\n");
        /* fail to close client-server fd should not abort the proxy */
        }
        return; 
    return; 
}

/*
 * usage - print a help message
 */
void usage(void) 
{
    printf("Usage: ./proxy [port] [-hv]\n");
    printf("   -h   print this message\n");
    printf("   -v   print additional diagnostic information\n");
    printf("  port  a listening port number on which the proxy listens \n");
    printf("        for incoming connection\n");
    exit(1);
}