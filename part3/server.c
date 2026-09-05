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
#include <time.h>
#include <curl/curl.h>
#include <mosquitto.h>
#include <openssl/evp.h>
const unsigned char AES_KEY[] = "1234567890123456";

#define HTTP_PORT 8080
#define HTTPS_PORT 8443
#define UDP_PORT 8891
#define TEMP_UDP_PORT 8892
#define BUFFER_SIZE 4096
#define FRAME_BUFFER_SIZE 65535
#define PERSON_UDP_PORT 8890
int current_person_count = 0; 
#define STUDENT_ID "401101749"

//  Watchdog Variables 
time_t last_video_receive_time = 0;
int is_video_stream_active = 0;
int has_sent_offline_email = 0; 


double current_host_cpu_temp = 0.0;
int history[5] = {0, 0, 0, 0, 0};
int history_count = 0;

void add_to_history(int new_count) {
    for(int i = 4; i > 0; i--) {
        history[i] = history[i-1];
    }
    history[0] = new_count;
    if(history_count < 5) history_count++;
}


unsigned char latest_frame[FRAME_BUFFER_SIZE];
int latest_frame_size = 0;
pthread_mutex_t frame_mutex = PTHREAD_MUTEX_INITIALIZER;
long long prev_total_cpu = 0;
long long prev_idle_cpu = 0;
time_t last_email_time = 0; 
void send_offline_email_alert(time_t timestamp);


void *udp_video_receiver(void *arg) {
    int udp_socket = socket(AF_INET, SOCK_DGRAM, 0);
    struct sockaddr_in server_addr, client_addr;
    socklen_t client_len = sizeof(client_addr);
    
    unsigned char buffer[FRAME_BUFFER_SIZE];
    unsigned char plaintext[FRAME_BUFFER_SIZE];

    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(UDP_PORT);
    
    if (bind(udp_socket, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("[FATAL] Video UDP Bind Failed (Port 8891)");
    } else {
        printf("[SERVER] Secure Video Receiver listening on Port %d\n", UDP_PORT);
    }

    while(1) {
        int recv_len = recvfrom(udp_socket, buffer, FRAME_BUFFER_SIZE, 0, (struct sockaddr *)&client_addr, &client_len);
        
        if (recv_len > 28) { 
            unsigned char nonce[12];
            unsigned char tag[16];
            memcpy(nonce, buffer, 12);
            memcpy(tag, buffer + recv_len - 16, 16);
            int ciphertext_len = recv_len - 12 - 16;
            unsigned char *ciphertext = buffer + 12;
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
                plaintext_len += outlen;
                pthread_mutex_lock(&frame_mutex);
                memcpy(latest_frame, plaintext, plaintext_len);
                latest_frame_size = plaintext_len;
                // watchdog implementation
                last_video_receive_time = time(NULL);
                is_video_stream_active = 1;
                has_sent_offline_email = 0; 
                
                pthread_mutex_unlock(&frame_mutex);
                
                // printf("[SECURITY] Authentic frame received! Size: %d\n", plaintext_len);
            } else {
                printf("[SECURITY ALERT] Malicious or corrupted frame detected. Dropped!\n");
            }
        }
    }
    return NULL;
}

double get_cpu_temp() { return current_host_cpu_temp; }

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

int get_people_count() {
    return current_person_count;
}

void *udp_person_receiver(void *arg) {
    int udp_socket = socket(AF_INET, SOCK_DGRAM, 0);
    struct sockaddr_in server_addr, client_addr;
    socklen_t client_len = sizeof(client_addr);
    
    unsigned char buffer[256];
    unsigned char plaintext[256];

    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(PERSON_UDP_PORT);
    
    if (bind(udp_socket, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("[FATAL] Person UDP Bind Failed (Port 8890)");
        return NULL;
    } else {
        printf("[SERVER] Secure Person Count Receiver listening on Port %d\n", PERSON_UDP_PORT);
    }

    while(1) {
        int recv_len = recvfrom(udp_socket, buffer, sizeof(buffer)-1, 0, (struct sockaddr *)&client_addr, &client_len);
        
      
        if (recv_len >= 29) { 
            unsigned char nonce[12];
            unsigned char tag[16];
            memcpy(nonce, buffer, 12);
            memcpy(tag, buffer + recv_len - 16, 16);
            
            int ciphertext_len = recv_len - 12 - 16;
            unsigned char *ciphertext = buffer + 12;
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
                plaintext_len += outlen;
                plaintext[plaintext_len] = '\0'; 
                
                current_person_count = atoi((char *)plaintext); 
                // printf("[SECURE UDP] Decrypted person count: %d\n", current_person_count); 
            } else {
                printf("[SECURITY ALERT] Malicious person count data detected. Dropped!\n");
            }
        }
    }
    return NULL;
}

void send_email_alert(int person_count, double temp, time_t timestamp) {
    CURL *curl;
    CURLcode res = CURLE_OK;

    char *email_pass = getenv("EMAIL_APP_PASS");
    if (email_pass == NULL) {
        fprintf(stderr, "[SECURITY ERROR] EMAIL_APP_PASS environment variable is missing! Email aborted.\n");
        return; 
    }
    struct tm *timeinfo;
    char time_string[80];
    timeinfo = localtime(&timestamp);
    strftime(time_string, sizeof(time_string), "%Y-%m-%d %H:%M:%S", timeinfo);

    curl = curl_easy_init();
    if(curl) {
        curl_easy_setopt(curl, CURLOPT_URL, "smtps://smtp.gmail.com:465");
        //curl_easy_setopt(curl, CURLOPT_USE_SSL, CURLUSESSL_ALL);
        curl_easy_setopt(curl, CURLOPT_USERNAME, "mahshidredaie@gmail.com"); 
        curl_easy_setopt(curl, CURLOPT_PASSWORD, email_pass); // Secure injection

        struct curl_slist *recipients = NULL;
        recipients = curl_slist_append(recipients, "mahshideredaie@gmail.com");
        curl_easy_setopt(curl, CURLOPT_MAIL_RCPT, recipients);
        
        curl_mime *mime = curl_mime_init(curl);
        curl_mimepart *part;

        // 1. The HTML Body
        part = curl_mime_addpart(mime);
        char html_body[2048];
    sprintf(html_body,
            "<html><body style='font-family: Arial, sans-serif; padding: 20px;'>"
            "<h2 style='color: #d9534f;'> Smart Guard Security Alert</h2>"
            "<p><strong>Student ID:</strong> %s</p>"
            "<p><strong>Detection Time:</strong> <span style='color: blue;'>%s</span></p>"
            "<p><strong>Intruders Detected:</strong> <span style='color: red; font-weight: bold;'>%d</span></p>"
            "<p><strong>System CPU Temp:</strong> %.1f &deg;C</p>"
            "</body></html>", STUDENT_ID, time_string, person_count, temp);
        
        curl_mime_data(part, html_body, CURL_ZERO_TERMINATED);
        curl_mime_type(part, "text/html");

    
        pthread_mutex_lock(&frame_mutex);
        int local_frame_size = latest_frame_size;
        unsigned char *local_frame_copy = NULL;
        if (local_frame_size > 0) {
            local_frame_copy = malloc(local_frame_size);
            memcpy(local_frame_copy, latest_frame, local_frame_size);
        }
        pthread_mutex_unlock(&frame_mutex);

        if (local_frame_copy != NULL) {
            part = curl_mime_addpart(mime);
            curl_mime_data(part, (const char*)local_frame_copy, local_frame_size);
            curl_mime_type(part, "image/jpeg");
            curl_mime_filename(part, "alert_capture.jpg");
            curl_mime_name(part, "attachment");
            curl_mime_encoder(part, "base64");
        }

        struct curl_slist *headers = NULL;
        headers = curl_slist_append(headers, "Subject:  CRITICAL: Human Detected!");
        headers = curl_slist_append(headers, "To: mahshideredaie@gmail.com");
        headers = curl_slist_append(headers, "From: Smart Guard System <mahshidredaie@gmail.com>");
        
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
        curl_easy_setopt(curl, CURLOPT_MIMEPOST, mime);

        printf("\n[EMAIL] Triggered! Transmitting security alert...\n");
        res = curl_easy_perform(curl);
        
        if(res != CURLE_OK) {
            fprintf(stderr, "[ERROR] Email failed: %s\n", curl_easy_strerror(res));
        } else {
            printf("[EMAIL] Alert successfully delivered!\n");
        }

        // Cleanup Memory
        if (local_frame_copy) free(local_frame_copy);
        curl_slist_free_all(recipients);
        curl_slist_free_all(headers);
        curl_mime_free(mime);
        curl_easy_cleanup(curl);
    }
}

void *mqtt_telemetry_thread(void *arg) {
    struct mosquitto *mosq = NULL;
    mosquitto_lib_init();
    mosq = mosquitto_new("smart_guard_c_client", true, NULL);
 
    char *mqtt_pass = getenv("MQTT_BROKER_PASS");
    if (mqtt_pass == NULL) {
        fprintf(stderr, "[SECURITY ERROR] MQTT_BROKER_PASS environment variable is missing! MQTT aborted.\n");
        return NULL;
    }
  
    mosquitto_username_pw_set(mosq, "guard_admin", mqtt_pass);

    char lwt_topic[128];
    sprintf(lwt_topic, "telemetry/%s/home", STUDENT_ID);
    char *lwt_payload = "{\"status\": \"offline\", \"message\": \"Unexpected server disconnection\"}";
    mosquitto_will_set(mosq, lwt_topic, strlen(lwt_payload), lwt_payload, 1, true);

  
    if (mosquitto_connect(mosq, "192.168.118.1", 1883, 60) != MOSQ_ERR_SUCCESS) {
        fprintf(stderr, "Failed to connect to Windows MQTT Broker\n");
        mosquitto_destroy(mosq);
        mosquitto_lib_cleanup();
        return NULL;
    }

    mosquitto_loop_start(mosq);

    while (1) {
        int count = get_people_count();
        double temp = get_cpu_temp();
        double usage = get_cpu_usage();
        long mem = get_free_memory();
        time_t now = time(NULL);
    
     
        if ((now - last_video_receive_time) > 5) {
            is_video_stream_active = 0; 
        }
        
       
        if (count > 0 && is_video_stream_active == 1) {
            if ((now - last_email_time) >= 30) {
                send_email_alert(count, temp, now);
                last_email_time = now; 
            }
        }
        
        if (is_video_stream_active == 0 && has_sent_offline_email == 0 && last_video_receive_time > 0) {
             printf("\n[WATCHDOG] Video stream lost! Sending offline alert...\n");
             send_offline_email_alert(now); 
             has_sent_offline_email = 1;    
        }

        char persons_topic[128], persons_json[256];
        sprintf(persons_topic, "persons/%s/home", STUDENT_ID);
        sprintf(persons_json, "{\"people\": %d, \"timestamp\": %ld}", count, now);
        mosquitto_publish(mosq, NULL, persons_topic, strlen(persons_json), persons_json, 1, false);

        char telemetry_topic[128], telemetry_json[256];
        sprintf(telemetry_topic, "telemetry/%s/home", STUDENT_ID);
        sprintf(telemetry_json, "{\"cpu_usage\": %.1f, \"free_mem\": %ld, \"cpu_temp\": %.1f, \"timestamp\": %ld}", usage, mem, temp, now);
        mosquitto_publish(mosq, NULL, telemetry_topic, strlen(telemetry_json), telemetry_json, 1, false);

        sleep(5); 
    }
    return NULL;
}

void send_offline_email_alert(time_t timestamp) {
    CURL *curl;
    CURLcode res = CURLE_OK;

    char *email_pass = getenv("EMAIL_APP_PASS");
    if (email_pass == NULL) return; 

    struct tm *timeinfo;
    char time_string[80];
    timeinfo = localtime(&timestamp);
    strftime(time_string, sizeof(time_string), "%Y-%m-%d %H:%M:%S", timeinfo);

    curl = curl_easy_init();
    if(curl) {
        curl_easy_setopt(curl, CURLOPT_URL, "smtps://smtp.gmail.com:465");
        curl_easy_setopt(curl, CURLOPT_USERNAME, "mahshidredaie@gmail.com"); 
        curl_easy_setopt(curl, CURLOPT_PASSWORD, email_pass);

        struct curl_slist *recipients = NULL;
        recipients = curl_slist_append(recipients, "mahshideredaie@gmail.com");
        curl_easy_setopt(curl, CURLOPT_MAIL_RCPT, recipients);
        
        curl_mime *mime = curl_mime_init(curl);
        curl_mimepart *part;
        part = curl_mime_addpart(mime);
        char html_body[2048];
        sprintf(html_body,
            "<html><body style='font-family: Arial, sans-serif; padding: 20px; border-left: 5px solid #FF9800; background-color: #FFF3E0;'>"
            "<h2 style='color: #E65100;'> System Alert: Video Stream Lost!</h2>"
            "<p><strong>Student ID:</strong> %s</p>"
            "<p><strong>Disconnection Time:</strong> %s</p>"
            "<p style='color: #333;'>The Smart Guard server has stopped receiving UDP video frames from the Python AI module. Please check the network connection or the Python script.</p>"
            "</body></html>", STUDENT_ID, time_string);
        
        curl_mime_data(part, html_body, CURL_ZERO_TERMINATED);
        curl_mime_type(part, "text/html");

        struct curl_slist *headers = NULL;
        headers = curl_slist_append(headers, "Subject: WARNING: Camera Connection Lost!");
        headers = curl_slist_append(headers, "To: mahshideredaie@gmail.com");
        headers = curl_slist_append(headers, "From: Smart Guard System <mahshidredaie@gmail.com>");
        
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
        curl_easy_setopt(curl, CURLOPT_MIMEPOST, mime);

        res = curl_easy_perform(curl);
        
        if(res != CURLE_OK) {
            fprintf(stderr, "[ERROR] Offline Email failed: %s\n", curl_easy_strerror(res));
        } else {
            printf("[EMAIL] Connection Lost Alert successfully delivered!\n");
        }

        curl_slist_free_all(recipients);
        curl_slist_free_all(headers);
        curl_mime_free(mime);
        curl_easy_cleanup(curl);
    }
}

// --- HTTP REDIRECT & VIDEO STREAM THREADS ---
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
    
    while(1) {
        client_socket = accept(server_fd, (struct sockaddr *)&address, (socklen_t*)&addrlen);
        if (client_socket < 0) continue;
        memset(buffer, 0, BUFFER_SIZE);
        read(client_socket, buffer, BUFFER_SIZE);

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

void *handle_video_stream_thread(void *arg) {
    SSL *ssl = (SSL *)arg;
    char *header = "HTTP/1.1 200 OK\r\nContent-Type: multipart/x-mixed-replace; boundary=frame\r\n\r\n";
    SSL_write(ssl, header, strlen(header));
    
    unsigned char local_frame[FRAME_BUFFER_SIZE];
    int local_size = 0;

    while (1) {
        pthread_mutex_lock(&frame_mutex);
        if (latest_frame_size > 0) {
            local_size = latest_frame_size;
            memcpy(local_frame, latest_frame, local_size);
        } else {
            local_size = 0;
        }
        pthread_mutex_unlock(&frame_mutex);

        if (local_size > 0) {
            char frame_header[256];
            sprintf(frame_header, "--frame\r\nContent-Type: image/jpeg\r\nContent-Length: %d\r\n\r\n", local_size);
            if (SSL_write(ssl, frame_header, strlen(frame_header)) <= 0) break;
            if (SSL_write(ssl, local_frame, local_size) <= 0) break;
            if (SSL_write(ssl, "\r\n", 2) <= 0) break;
        }
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
    
    // Hard check if the port binds successfully
    if (bind(udp_socket, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("[FATAL] Temp UDP Bind Failed (Port 8889)");
    } else {
        printf("[SERVER] Temp Receiver listening on Port %d\n", TEMP_UDP_PORT);
    }

    while(1) {
        int recv_len = recvfrom(udp_socket, buffer, sizeof(buffer)-1, 0, (struct sockaddr *)&client_addr, &client_len);
        if (recv_len > 0) {
            buffer[recv_len] = '\0';
            current_host_cpu_temp = atof(buffer);
            // Prove the temperature arrived!
            printf("[UDP RECEIVER] Caught CPU Temp: %.1f °C\n", current_host_cpu_temp);
        }
    }
    return NULL;
}

// --- MAIN HTTPS SERVER ---
int main() {
    signal(SIGPIPE, SIG_IGN);
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();
    SSL_CTX *ctx = SSL_CTX_new(TLS_server_method());
    if (!ctx) { perror("Unable to create SSL context"); exit(EXIT_FAILURE); }
    if (SSL_CTX_use_certificate_file(ctx, "server.crt", SSL_FILETYPE_PEM) <= 0 || 
        SSL_CTX_use_PrivateKey_file(ctx, "server.key", SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr); exit(EXIT_FAILURE);
    }

    pthread_t udp_thread, http_thread, temp_thread, mqtt_thread , person_thread;
    pthread_create(&udp_thread, NULL, udp_video_receiver, NULL);
    pthread_create(&http_thread, NULL, http_redirect_server, NULL);
    pthread_create(&temp_thread, NULL, udp_temp_receiver, NULL);
    pthread_create(&mqtt_thread, NULL, mqtt_telemetry_thread, NULL);
    pthread_create(&person_thread, NULL, udp_person_receiver, NULL);

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
    
    printf("Secure HTTPS Server running on port %d with Email & MQTT enabled...\n", HTTPS_PORT);

    while(1) {
        client_socket = accept(server_fd, (struct sockaddr *)&address, (socklen_t*)&addrlen);
        if (client_socket < 0) continue;

        SSL *ssl = SSL_new(ctx);
        SSL_set_fd(ssl, client_socket);
        if (SSL_accept(ssl) <= 0) {
            int fd = SSL_get_fd(ssl); SSL_free(ssl); close(fd);
            continue;
        }
        
        memset(buffer, 0, BUFFER_SIZE);
        SSL_read(ssl, buffer, BUFFER_SIZE);
        
        if (strncmp(buffer, "GET /API/V1/STREAM", 18) == 0) {
            pthread_t vid_thread;
            pthread_create(&vid_thread, NULL, handle_video_stream_thread, (void*)ssl);
            pthread_detach(vid_thread); 
        }
        else if (strncmp(buffer, "GET /API/V1/TELEMETRY", 21) == 0) {
            char json[256];
            sprintf(json, "{\"cpu_usage\": %.1f, \"free_mem\": %ld, \"cpu_temp\": %.1f}", get_cpu_usage(), get_free_memory(), get_cpu_temp());
            char http_header[1024];
            sprintf(http_header, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: %zu\r\nConnection: close\r\n\r\n%s", strlen(json), json);
            SSL_write(ssl, http_header, strlen(http_header));
            int fd = SSL_get_fd(ssl); SSL_shutdown(ssl); SSL_free(ssl); close(fd);
        }
        else if (strncmp(buffer, "GET /API/V1/PERSONS", 19) == 0) {
            int count = get_people_count();
            add_to_history(count);
            time_t timestamp = time(NULL);
            
            char json[256];
            sprintf(json, "{\"people\": %d, \"timestamp\": %ld}", count, timestamp);
            char http_header[1024];
            sprintf(http_header, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: %zu\r\nConnection: close\r\n\r\n%s", strlen(json), json);
            SSL_write(ssl, http_header, strlen(http_header));
            int fd = SSL_get_fd(ssl); SSL_shutdown(ssl); SSL_free(ssl); close(fd);
        }
        else if (strncmp(buffer, "GET /API/V1/HISTORY", 19) == 0) {
            char json[256];
            strcpy(json, "{\"history\": [");
            for(int i = 0; i < history_count; i++) {
                char temp[16];
                sprintf(temp, "%d%s", history[i], (i == history_count - 1) ? "" : ", ");
                strcat(json, temp);
            }
            strcat(json, "]}");

            char http_header[1024];
            sprintf(http_header, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: %zu\r\nConnection: close\r\n\r\n%s", strlen(json), json);
            SSL_write(ssl, http_header, strlen(http_header));
            int fd = SSL_get_fd(ssl); SSL_shutdown(ssl); SSL_free(ssl); close(fd);
        }
        else if (strncmp(buffer, "POST /API/V1/COMMAND", 20) == 0) {
            char *json = "{\"status\": \"Command received\"}";
            char http_header[1024];
            sprintf(http_header, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: %zu\r\nConnection: close\r\n\r\n%s", strlen(json), json);
            SSL_write(ssl, http_header, strlen(http_header));
            int fd = SSL_get_fd(ssl); SSL_shutdown(ssl); SSL_free(ssl); close(fd);

            if (strstr(buffer, "reboot") != NULL) system("/sbin/reboot");
        }
        else {
            int fd = SSL_get_fd(ssl); SSL_shutdown(ssl); SSL_free(ssl); close(fd);
        }
    }
    return 0;
}
