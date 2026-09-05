#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <pthread.h>
#include <signal.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/evp.h>
// --- SECURITY SETTINGS ---
const unsigned char AES_KEY[] = "1234567890123456";

#define HTTP_PORT 8080
#define HTTPS_PORT 8443
#define UDP_PORT 8891
#define BUFFER_SIZE 4096
#define FRAME_BUFFER_SIZE 65535
#define TEMP_UDP_PORT 8892
#define PERSON_UDP_PORT 8890
int current_person_count = 0;
double current_host_cpu_temp = 0.0;

// --- GLOBAL VARIABLES ---
unsigned char latest_frame[FRAME_BUFFER_SIZE];
int latest_frame_size = 0;
pthread_mutex_t frame_mutex = PTHREAD_MUTEX_INITIALIZER;
long long prev_total_cpu = 0;
long long prev_idle_cpu = 0;

// --- UDP RECEIVER THREAD ---
// --- UDP RECEIVER THREAD (SECURE AES-GCM) ---
void *udp_video_receiver(void *arg) {
    int udp_socket = socket(AF_INET, SOCK_DGRAM, 0);
    int rcvbuf = 1024 * 1024;
    setsockopt(udp_socket, SOL_SOCKET, SO_RCVBUF, &rcvbuf, sizeof(rcvbuf));
    struct sockaddr_in server_addr, client_addr;
    socklen_t client_len = sizeof(client_addr);
    
    unsigned char buffer[FRAME_BUFFER_SIZE];
    unsigned char plaintext[FRAME_BUFFER_SIZE];

    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(UDP_PORT);
    
    bind(udp_socket, (struct sockaddr *)&server_addr, sizeof(server_addr));
    printf("[SERVER] Secure Video Receiver listening on Port %d\n", UDP_PORT);

    while(1) {
        int recv_len = recvfrom(udp_socket, buffer, FRAME_BUFFER_SIZE, 0, (struct sockaddr *)&client_addr, &client_len);
        
        // Minimum packet size: 12 (nonce) + 1 (data) + 16 (tag) = 29 bytes
        if (recv_len > 28) { 
            unsigned char nonce[12];
            unsigned char tag[16];
            
            // Extract Nonce and Tag
            memcpy(nonce, buffer, 12);
            memcpy(tag, buffer + recv_len - 16, 16);
            
            // Calculate ciphertext length and pointer
            int ciphertext_len = recv_len - 12 - 16;
            unsigned char *ciphertext = buffer + 12;

            // --- OpenSSL Decryption Engine ---
            EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
            int outlen, plaintext_len;

            EVP_DecryptInit_ex(ctx, EVP_aes_128_gcm(), NULL, NULL, NULL);
            EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, NULL);
            EVP_DecryptInit_ex(ctx, NULL, NULL, AES_KEY, nonce);

            EVP_DecryptUpdate(ctx, plaintext, &outlen, ciphertext, ciphertext_len);
            plaintext_len = outlen;

            EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, tag);
            
            int ret = EVP_DecryptFinal_ex(ctx, plaintext + outlen, &outlen);
            
            EVP_CIPHER_CTX_free(ctx);

            if (ret > 0) {
                // Decryption successful, frame is authentic!
                plaintext_len += outlen;
                
                pthread_mutex_lock(&frame_mutex);
                memcpy(latest_frame, plaintext, plaintext_len);
                latest_frame_size = plaintext_len;
                pthread_mutex_unlock(&frame_mutex);
            } else {
                printf("[SECURITY ALERT] Malicious or corrupted frame detected. Dropped!\n");
            }
        }
    }
    return NULL;
}
// --- TELEMETRY FUNCTIONS ---
double get_cpu_temp() {
    return current_host_cpu_temp;
}

long get_free_memory() {
    FILE *fp = fopen("/proc/meminfo", "r");
    if (!fp) return 0;
    char line[256];
    long free_mem_kb = 0;
    while (fgets(line, sizeof(line), fp)) {
        if (strncmp(line, "MemFree:", 8) == 0) {
            sscanf(line, "MemFree: %ld kB", &free_mem_kb);
            break;
        }
    }
    fclose(fp);
    return free_mem_kb / 1024;
}

double get_cpu_usage() {
    FILE *fp = fopen("/proc/stat", "r");
    if (!fp) return 0.0;
    long long user, nice, system, idle, iowait, irq, softirq, steal;
    fscanf(fp, "cpu %lld %lld %lld %lld %lld %lld %lld %lld", &user, &nice, &system, &idle, &iowait, &irq, &softirq, &steal);
    fclose(fp);
    long long current_total = user + nice + system + idle + iowait + irq + softirq + steal;
    long long current_idle = idle + iowait;
    double usage = 0.0;
    if (prev_total_cpu != 0 && (current_total - prev_total_cpu) != 0) {
        usage = (double)((current_total - prev_total_cpu) - (current_idle - prev_idle_cpu)) / (current_total - prev_total_cpu) * 100.0;
    }
    prev_total_cpu = current_total;
    prev_idle_cpu = current_idle;
    return usage;
}
// --- SECURE UDP PERSON RECEIVER ---
void *udp_person_receiver(void *arg) {
    int udp_socket = socket(AF_INET, SOCK_DGRAM, 0);
    struct sockaddr_in server_addr, client_addr;
    socklen_t client_len = sizeof(client_addr);
    char buffer[256];
    char plaintext[256];

    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(PERSON_UDP_PORT);
    bind(udp_socket, (struct sockaddr *)&server_addr, sizeof(server_addr));

    while(1) {
        int recv_len = recvfrom(udp_socket, buffer, sizeof(buffer)-1, 0, (struct sockaddr *)&client_addr, &client_len);
        
      
        if (recv_len > 28) {
            unsigned char nonce[12], tag[16];
            memcpy(nonce, buffer, 12);
            memcpy(tag, buffer + recv_len - 16, 16);
            
            int ciphertext_len = recv_len - 28;
            unsigned char *ciphertext = (unsigned char *)buffer + 12;

            EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
            int outlen, plaintext_len;

            EVP_DecryptInit_ex(ctx, EVP_aes_128_gcm(), NULL, NULL, NULL);
            EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, NULL);
            EVP_DecryptInit_ex(ctx, NULL, NULL, AES_KEY, nonce);
            EVP_DecryptUpdate(ctx, (unsigned char *)plaintext, &outlen, ciphertext, ciphertext_len);
            plaintext_len = outlen;
            EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, tag);
            int ret = EVP_DecryptFinal_ex(ctx, (unsigned char *)plaintext + outlen, &outlen);
            EVP_CIPHER_CTX_free(ctx);

            if (ret > 0) {
                plaintext_len += outlen;
                plaintext[plaintext_len] = '\0';
                current_person_count = atoi(plaintext); // آپدیت شدن تعداد افراد در وب!
            }
        }
    }
    return NULL;
}

int get_people_count() {
    return current_person_count;
}

// --- HTTP TO HTTPS REDIRECT THREAD ---
void *http_redirect_server(void *arg) {
    int server_fd, client_socket;
    struct sockaddr_in address;
    int opt = 1, addrlen = sizeof(address);
    char buffer[BUFFER_SIZE];

    server_fd = socket(AF_INET, SOCK_STREAM, 0);
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &opt, sizeof(opt));
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(HTTP_PORT);
    bind(server_fd, (struct sockaddr *)&address, sizeof(address));
    listen(server_fd, 5);
    
    printf("HTTP Redirector running on port %d...\n", HTTP_PORT);

    while(1) {
        client_socket = accept(server_fd, (struct sockaddr *)&address, (socklen_t*)&addrlen);
        if (client_socket < 0) continue;
        memset(buffer, 0, BUFFER_SIZE);
        read(client_socket, buffer, BUFFER_SIZE);

        // Extract the IP address the user typed so we redirect them correctly
        char host[256] = "192.168.118.130"; 
        char *host_start = strstr(buffer, "Host: ");
        if (host_start) {
            host_start += 6;
            char *colon = strchr(host_start, ':');
            if (colon && (colon - host_start) < 255) {
                strncpy(host, host_start, colon - host_start);
                host[colon - host_start] = '\0';
            }
        }

        char redirect_msg[512];
        sprintf(redirect_msg, "HTTP/1.1 301 Moved Permanently\r\nLocation: https://%s:%d/\r\nConnection: close\r\n\r\n", host, HTTPS_PORT);
        send(client_socket, redirect_msg, strlen(redirect_msg), 0);
        close(client_socket);
    }
    return NULL;
}

// --- OUTGOING SECURE VIDEO THREAD ---
void *handle_video_stream_thread(void *arg) {
    SSL *ssl = (SSL *)arg;
    

    char *header = "HTTP/1.1 200 OK\r\n"
                   "Connection: close\r\n"
                   "Cache-Control: no-store, no-cache, must-revalidate, pre-check=0, post-check=0, max-age=0\r\n"
                   "Pragma: no-cache\r\n"
                   "Content-Type: multipart/x-mixed-replace; boundary=frame\r\n\r\n";
                   
    SSL_write(ssl, header, strlen(header));

    while (1) {
        pthread_mutex_lock(&frame_mutex);
        if (latest_frame_size > 0) {
            char frame_header[256];
            sprintf(frame_header, "--frame\r\nContent-Type: image/jpeg\r\nContent-Length: %d\r\n\r\n", latest_frame_size);
            
            if (SSL_write(ssl, frame_header, strlen(frame_header)) <= 0) {
                pthread_mutex_unlock(&frame_mutex);
                break;
            }
            if (SSL_write(ssl, latest_frame, latest_frame_size) <= 0) {
                pthread_mutex_unlock(&frame_mutex);
                break;
            }
            SSL_write(ssl, "\r\n", 2); 
        }
        pthread_mutex_unlock(&frame_mutex);
        usleep(33000); 
    }
    
    int fd = SSL_get_fd(ssl);
    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(fd);
    return NULL;
}
void *udp_temp_receiver(void *arg) {
    int udp_socket = socket(AF_INET, SOCK_DGRAM, 0);
    struct sockaddr_in server_addr, client_addr;
    socklen_t client_len = sizeof(client_addr);
    char buffer[256];

    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(TEMP_UDP_PORT);
    bind(udp_socket, (struct sockaddr *)&server_addr, sizeof(server_addr));

    while(1) {
        int recv_len = recvfrom(udp_socket, buffer, sizeof(buffer)-1, 0, (struct sockaddr *)&client_addr, &client_len);
        if (recv_len > 0) {
            buffer[recv_len] = '\0'; // Ensure it's a valid string
            current_host_cpu_temp = atof(buffer); // Convert string to double
        }
    }
    return NULL;
}
// --- MAIN HTTPS SERVER ---
int main() {
    signal(SIGPIPE, SIG_IGN);

    // 1. Initialize OpenSSL
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();
    SSL_CTX *ctx = SSL_CTX_new(TLS_server_method());
    if (!ctx) { perror("Unable to create SSL context"); exit(EXIT_FAILURE); }
    if (SSL_CTX_use_certificate_file(ctx, "server.crt", SSL_FILETYPE_PEM) <= 0 || 
        SSL_CTX_use_PrivateKey_file(ctx, "server.key", SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr); exit(EXIT_FAILURE);
    }

    // 2. Launch background threads
    pthread_t udp_thread, http_thread, temp_thread , person_thread;
    pthread_create(&udp_thread, NULL, udp_video_receiver, NULL);
    pthread_create(&http_thread, NULL, http_redirect_server, NULL);
    pthread_create(&temp_thread, NULL, udp_temp_receiver, NULL);
    pthread_create(&person_thread, NULL, udp_person_receiver, NULL);

    // 3. Setup Secure Socket
    int server_fd, client_socket;
    struct sockaddr_in address;
    int opt = 1, addrlen = sizeof(address);
    char buffer[BUFFER_SIZE] = {0};

    server_fd = socket(AF_INET, SOCK_STREAM, 0);
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &opt, sizeof(opt));
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(HTTPS_PORT);
    bind(server_fd, (struct sockaddr *)&address, sizeof(address));
    listen(server_fd, 5);
    
    printf("HTTPS Secure Web Server running on port %d...\n", HTTPS_PORT);

    while(1) {
        client_socket = accept(server_fd, (struct sockaddr *)&address, (socklen_t*)&addrlen);
        if (client_socket < 0) continue;

        // Perform SSL Handshake
        SSL *ssl = SSL_new(ctx);
        SSL_set_fd(ssl, client_socket);
        if (SSL_accept(ssl) <= 0) {
            ERR_print_errors_fp(stderr);
            int fd = SSL_get_fd(ssl);
            SSL_free(ssl);
            close(fd);
            continue;
        }
        
        memset(buffer, 0, BUFFER_SIZE);
        SSL_read(ssl, buffer, BUFFER_SIZE);
        
        if (strncmp(buffer, "GET / ", 6) == 0 || strncmp(buffer, "GET /index", 10) == 0) {
            FILE *html_data = fopen("index.html", "r");
            if (html_data) {
                char response_data[BUFFER_SIZE];
                size_t bytes_read = fread(response_data, 1, sizeof(response_data) - 1, html_data);
                response_data[bytes_read] = '\0';
                fclose(html_data);

                char http_header[1024];
                sprintf(http_header, "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: %zu\r\nConnection: close\r\n\r\n", bytes_read);
                SSL_write(ssl, http_header, strlen(http_header));
                SSL_write(ssl, response_data, bytes_read);
            }
            int fd = SSL_get_fd(ssl); SSL_shutdown(ssl); SSL_free(ssl); close(fd);
        } 
        else if (strncmp(buffer, "GET /stream", 11) == 0) {
            printf("Secure Browser connected to live stream!\n");
            pthread_t vid_thread;
            pthread_create(&vid_thread, NULL, handle_video_stream_thread, (void*)ssl);
            pthread_detach(vid_thread); 
        }
        else if (strncmp(buffer, "GET /telemetry", 14) == 0) {
            char json[256];
            sprintf(json, "{\"cpu_usage\": %.1f, \"free_mem\": %ld, \"cpu_temp\": %.1f, \"people\": %d}", 
                    get_cpu_usage(), get_free_memory(), get_cpu_temp(), get_people_count());
            char http_header[1024];
            sprintf(http_header, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: %zu\r\nConnection: close\r\n\r\n%s", strlen(json), json);
            SSL_write(ssl, http_header, strlen(http_header));
            int fd = SSL_get_fd(ssl); SSL_shutdown(ssl); SSL_free(ssl); close(fd);
        }
        else {
            int fd = SSL_get_fd(ssl); SSL_shutdown(ssl); SSL_free(ssl); close(fd);
        }
    }
    return 0;
}
