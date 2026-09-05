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
#include <sqlite3.h>

#define HTTP_PORT 8080
#define HTTPS_PORT 8443
#define UDP_PORT 8891
#define TEMP_UDP_PORT 8892
#define BUFFER_SIZE 4096
#define FRAME_BUFFER_SIZE 65535
#define PERSON_UDP_PORT 8890
#define STUDENT_ID "401101749"
#define CPU_TEMP_THRESHOLD 73.0  

#include <openssl/evp.h>

const unsigned char AES_KEY[] = "1234567890123456";

int current_person_count = 0; 
int guard_mode_active = 0;
double current_host_cpu_temp = 0.0;
int last_logged_count = 0;

time_t last_frame_time = 0;          
int thermal_throttle_active = 0;     
int thermal_email_sent = 0;
int intruder_email_sent = 0;
sqlite3 *db; 

typedef enum {
    ALERT_INTRUDER,
    ALERT_WATCHDOG,
    ALERT_THERMAL
} AlertType;

void send_email_alert(AlertType type, int person_count, double temp, time_t timestamp);

void init_blackbox_db() {
    int rc = sqlite3_open("blackbox.db", &db);
    if (rc) {
        fprintf(stderr, "[FATAL] Can't open database: %s\n", sqlite3_errmsg(db));
        return;
    }

    char *err_msg = 0;
    const char *sql_history = "CREATE TABLE IF NOT EXISTS history (id INTEGER PRIMARY KEY AUTOINCREMENT, count INTEGER, timestamp INTEGER);";
    sqlite3_exec(db, sql_history, 0, 0, &err_msg);
    
    const char *sql_trigger = "CREATE TRIGGER IF NOT EXISTS limit_size AFTER INSERT ON history "
                              "BEGIN DELETE FROM history WHERE id <= (SELECT MAX(id) FROM history) - 10; END;";
    sqlite3_exec(db, sql_trigger, 0, 0, &err_msg);

    const char *sql_stats = "CREATE TABLE IF NOT EXISTS stats (id INTEGER PRIMARY KEY, total_detections INTEGER);";
    sqlite3_exec(db, sql_stats, 0, 0, &err_msg);
    
    const char *sql_init_stats = "INSERT OR IGNORE INTO stats (id, total_detections) VALUES (1, 0);";
    sqlite3_exec(db, sql_init_stats, 0, 0, &err_msg);

    printf("[DATABASE] SQLite Black Box initialized successfully with Circular Buffer.\n");
}

void log_detection_to_db(int count) {
    if (db == NULL) return;
    
    char sql[512];
    time_t now = time(NULL);
    char *err_msg = 0;

    sprintf(sql, "INSERT INTO history (count, timestamp) VALUES (%d, %ld);", count, now);
    sqlite3_exec(db, sql, 0, 0, &err_msg);

    const char *sql_update_stats = "UPDATE stats SET total_detections = total_detections + 1 WHERE id = 1;";
    sqlite3_exec(db, sql_update_stats, 0, 0, &err_msg);
    
    printf("[DATABASE] Black Box updated! Logged %d person(s).\n", count);
}

unsigned char latest_frame[FRAME_BUFFER_SIZE];
int latest_frame_size = 0;
pthread_mutex_t frame_mutex = PTHREAD_MUTEX_INITIALIZER;
long long prev_total_cpu = 0;
long long prev_idle_cpu = 0;
time_t last_email_time = 0; 

double get_cpu_temp(void);
long get_free_memory(void);
double get_cpu_usage(void);
int get_people_count(void);

void *udp_video_receiver(void *arg) {
    int udp_socket = socket(AF_INET, SOCK_DGRAM, 0);
    int opt = 1;
    setsockopt(udp_socket, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    struct sockaddr_in server_addr, client_addr;
    
    unsigned char buffer[FRAME_BUFFER_SIZE];
    unsigned char plaintext[FRAME_BUFFER_SIZE]; 
    
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(UDP_PORT);
    
    if (bind(udp_socket, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("[FATAL] Video UDP Bind Failed");
    } else {
        printf("[SERVER] SECURE Video Receiver listening on Port %d\n", UDP_PORT);
    }

    while(1) {
        socklen_t client_len = sizeof(client_addr);
        int recv_len = recvfrom(udp_socket, buffer, FRAME_BUFFER_SIZE, 0, (struct sockaddr *)&client_addr, &client_len);
        
       
        if (recv_len > 28) {
            unsigned char nonce[12];
            unsigned char tag[16];
            memcpy(nonce, buffer, 12);
            memcpy(tag, buffer + recv_len - 16, 16);
            
            int ciphertext_len = recv_len - 28;
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
                last_frame_time = time(NULL); 
                pthread_mutex_unlock(&frame_mutex);
            }
        }
    }
    return NULL;
}

void *watchdog_thread(void *arg) {
    sleep(15); 
    while(1) {
        time_t now = time(NULL);
        // FIXED: Watchdog only triggers if at least one frame was received previously
        if (last_frame_time > 0 && (now - last_frame_time) >= 30) {
            printf("\n[WATCHDOG FATAL] No video frame for 30s! Camera tampering suspected.\n");
            send_email_alert(ALERT_WATCHDOG, current_person_count, get_cpu_temp(), now);
            printf("[WATCHDOG] Executing self-recovery service restart...\n");
            sleep(3); 
            
            // FIXED: Nuke all Ghost File Descriptors to prevent Socket Leaks
            for(int i = 3; i < 1024; i++) close(i);
            
            char *args[] = {"./webserver", NULL};
            execv(args[0], args);
            exit(1); 
        }
        sleep(5);
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

int get_people_count() { return current_person_count; }

void *udp_person_receiver(void *arg) {
    int udp_socket = socket(AF_INET, SOCK_DGRAM, 0);
    int opt = 1;
    setsockopt(udp_socket, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    struct sockaddr_in server_addr, client_addr;
    
    unsigned char buffer[256];
    unsigned char plaintext[256];

    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(PERSON_UDP_PORT);
    bind(udp_socket, (struct sockaddr *)&server_addr, sizeof(server_addr));

    while(1) {
        socklen_t client_len = sizeof(client_addr);
        int recv_len = recvfrom(udp_socket, buffer, sizeof(buffer)-1, 0, (struct sockaddr *)&client_addr, &client_len);
        
        if (recv_len >= 29) { 
            unsigned char nonce[12];
            unsigned char tag[16];
            memcpy(nonce, buffer, 12);
            memcpy(tag, buffer + recv_len - 16, 16);
            
            int ciphertext_len = recv_len - 28;
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
                
                if (current_person_count > 0 && current_person_count != last_logged_count) {
                    log_detection_to_db(current_person_count);
                    last_logged_count = current_person_count;
                } else if (current_person_count == 0) {
                    last_logged_count = 0;
                }

              
                if (guard_mode_active == 1 && current_person_count > 0) {
                    time_t now = time(NULL);
                    
               
                    if ((now - last_email_time) >= 30) { 
                        last_email_time = now; 
                        
                        printf("\n[SECURITY] INTRUDER DETECTED! GUARD MODE ACTIVE!\n");
                        
                        char *mqtt_pass = getenv("MQTT_BROKER_PASS");
                        char mqtt_cmd[512];
                        sprintf(mqtt_cmd, "mosquitto_pub -h 192.168.118.1 -u guard_admin -P %s -t 'alarm/%s/home' -m '{\"alert\": \"Intruder Detected!\", \"count\": %d}'", 
                                mqtt_pass ? mqtt_pass : "", STUDENT_ID, current_person_count);
                        system(mqtt_cmd);
                        
                        send_email_alert(ALERT_INTRUDER, current_person_count, get_cpu_temp(), now);
                    }
                }
            }
        }
    }
    return NULL;
}

void send_email_alert(AlertType type, int person_count, double temp, time_t timestamp) {
    CURL *curl;
    CURLcode res = CURLE_OK;

    char *email_pass = getenv("EMAIL_APP_PASS");
    if (email_pass == NULL) {
        fprintf(stderr, "[SECURITY ERROR] EMAIL_APP_PASS missing! Email aborted.\n");
        return; 
    }

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

char html_body[2048];
        char subject_line[256];
        struct tm *timeinfo;
        char time_string[80];
        timeinfo = localtime(&timestamp);
        strftime(time_string, sizeof(time_string), "%Y-%m-%d %H:%M:%S", timeinfo);
        if (type == ALERT_INTRUDER) {
            strcpy(subject_line, "Subject: CRITICAL: Human Detected!");
            sprintf(html_body, 
                "<html><body style='font-family: Arial; padding: 20px;'>"
                "<h2 style='color: #d9534f;'> Smart Guard Security Alert</h2>"
                "<p><strong>Intruders Detected:</strong> <span style='color: red; font-weight: bold;'>%d</span></p>"
                "<p><strong>Detection Time:</strong> <span style='color: blue;'>%s</span></p>"
                "<p><strong>System CPU Temp:</strong> %.1f &deg;C</p>"
                "</body></html>", person_count, time_string, temp);
        }
        else if (type == ALERT_WATCHDOG) {
            strcpy(subject_line, "Subject: WARNING: Camera Tampering Detected!");
            sprintf(html_body, 
                "<html><body style='font-family: Arial; padding: 20px;'>"
                "<h2 style='color: #f39c12;'> System Watchdog Triggered</h2>"
                "<p>No video frames received for over 30 seconds. Potential camera disconnect or tampering.</p>"
                "<p><em>System service is automatically restarting to attempt recovery...</em></p></body></html>");
        }
        else if (type == ALERT_THERMAL) {
            strcpy(subject_line, "Subject: ALERT: Thermal Management Activated");
            sprintf(html_body, 
                "<html><body style='font-family: Arial; padding: 20px;'>"
                "<h2 style='color: #e67e22;'> Thermal Threshold Exceeded</h2>"
                "<p><strong>System CPU Temp:</strong> %.1f &deg;C</p>"
                "<p><em>Action Taken: Automatically reducing video stream FPS to shed thermal load.</em></p></body></html>", temp);
        }

        part = curl_mime_addpart(mime);
        curl_mime_data(part, html_body, CURL_ZERO_TERMINATED);
        curl_mime_type(part, "text/html");

        pthread_mutex_lock(&frame_mutex);
        int local_frame_size = latest_frame_size;
        unsigned char *local_frame_copy = NULL;
        if (type == ALERT_INTRUDER && local_frame_size > 0) {
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
        headers = curl_slist_append(headers, subject_line);
        headers = curl_slist_append(headers, "To: mahshideredaie@gmail.com");
        headers = curl_slist_append(headers, "From: Smart Guard System <mahshidredaie@gmail.com>");
        
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
        curl_easy_setopt(curl, CURLOPT_MIMEPOST, mime);

        printf("\n[EMAIL] Transmitting automated event alert...\n");
        res = curl_easy_perform(curl);
        
        if(res != CURLE_OK) fprintf(stderr, "[ERROR] Email failed: %s\n", curl_easy_strerror(res));

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
    if (mqtt_pass == NULL) return NULL;
  
    mosquitto_username_pw_set(mosq, "guard_admin", mqtt_pass);

    char lwt_topic[128];
    sprintf(lwt_topic, "telemetry/%s/home", STUDENT_ID);
    char *lwt_payload = "{\"status\": \"offline\", \"message\": \"Unexpected server disconnection\"}";
    mosquitto_will_set(mosq, lwt_topic, strlen(lwt_payload), lwt_payload, 1, true);
  
    if (mosquitto_connect(mosq, "192.168.118.1", 1883, 60) != MOSQ_ERR_SUCCESS) {
        mosquitto_destroy(mosq);
        mosquitto_lib_cleanup();
        return NULL;
    }

    mosquitto_loop_start(mosq);

    while (1) {
        time_t now = time(NULL);
        char persons_topic[128], persons_json[256];
        sprintf(persons_topic, "persons/%s/home", STUDENT_ID);
        sprintf(persons_json, "{\"people\": %d, \"timestamp\": %ld}", get_people_count(), now);
        mosquitto_publish(mosq, NULL, persons_topic, strlen(persons_json), persons_json, 1, false);

        char telemetry_topic[128], telemetry_json[256];
        sprintf(telemetry_topic, "telemetry/%s/home", STUDENT_ID);
        sprintf(telemetry_json, "{\"cpu_usage\": %.1f, \"free_mem\": %ld, \"cpu_temp\": %.1f, \"timestamp\": %ld}", get_cpu_usage(), get_free_memory(), get_cpu_temp(), now);
        mosquitto_publish(mosq, NULL, telemetry_topic, strlen(telemetry_json), telemetry_json, 1, false);

        sleep(5); 
    }
    return NULL;
}

void *udp_temp_receiver(void *arg) {
    int udp_socket = socket(AF_INET, SOCK_DGRAM, 0);
    int opt = 1;
    setsockopt(udp_socket, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    struct sockaddr_in server_addr, client_addr;
    char buffer[256];
    
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(TEMP_UDP_PORT);
    bind(udp_socket, (struct sockaddr *)&server_addr, sizeof(server_addr));

    while(1) {
        socklen_t client_len = sizeof(client_addr);
        int recv_len = recvfrom(udp_socket, buffer, sizeof(buffer)-1, 0, (struct sockaddr *)&client_addr, &client_len);
        if (recv_len > 0) {
            buffer[recv_len] = '\0';
            double new_temp = atof(buffer);
            
            if (new_temp > 0.0) {
                current_host_cpu_temp = new_temp;

                if (current_host_cpu_temp >= CPU_TEMP_THRESHOLD && !thermal_throttle_active) {
                    thermal_throttle_active = 1;
                    printf("\n[THERMAL] CPU Temp (%.1f C) breached threshold! Activating thermal throttling.\n", current_host_cpu_temp);
                    
                    if (!thermal_email_sent) {
                        send_email_alert(ALERT_THERMAL, current_person_count, current_host_cpu_temp, time(NULL));
                        thermal_email_sent = 1;
                    }
                } 
                else if (current_host_cpu_temp <= (CPU_TEMP_THRESHOLD - 5.0) && thermal_throttle_active) {
                    thermal_throttle_active = 0;
                    thermal_email_sent = 0; 
                    printf("\n[THERMAL] CPU Temp normalized (%.1f C). Restoring max FPS.\n", current_host_cpu_temp);
                }
            }
        }
    }
    return NULL;
}

// --- FIXED: ASYNCHRONOUS MULTI-THREADED HTTP HANDLER ---
void *https_client_handler(void *arg) {
    SSL *ssl = (SSL *)arg;
    char buffer[BUFFER_SIZE] = {0};

    if (SSL_accept(ssl) <= 0) {
        int fd = SSL_get_fd(ssl); SSL_shutdown(ssl); SSL_free(ssl); close(fd);
        return NULL;
    }
    
    SSL_read(ssl, buffer, BUFFER_SIZE);
    
    if (strncmp(buffer, "GET / HTTP", 10) == 0) {
        FILE *fp = fopen("index.html", "r");
        if (fp) {
            fseek(fp, 0, SEEK_END);
            long fsize = ftell(fp);
            fseek(fp, 0, SEEK_SET);
            char *html = malloc(fsize + 1);
            fread(html, 1, fsize, fp);
            html[fsize] = 0;
            fclose(fp);

            char http_header[1024];
            sprintf(http_header, "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: %ld\r\nConnection: close\r\n\r\n", fsize);
            SSL_write(ssl, http_header, strlen(http_header));
            SSL_write(ssl, html, fsize);
            free(html);
        }
    }
    else if (strncmp(buffer, "GET /API/V1/STREAM", 18) == 0) {
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
            
            int stream_delay = thermal_throttle_active ? 200000 : 33000;
            usleep(stream_delay); 
        }
    }
    else if (strncmp(buffer, "GET /API/V1/TELEMETRY", 21) == 0) {
        char json[256];
        sprintf(json, "{\"cpu_usage\": %.1f, \"free_mem\": %ld, \"cpu_temp\": %.1f}", get_cpu_usage(), get_free_memory(), get_cpu_temp());
        char http_header[1024];
        sprintf(http_header, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: %zu\r\nConnection: close\r\n\r\n%s", strlen(json), json);
        SSL_write(ssl, http_header, strlen(http_header));
    }
    else if (strncmp(buffer, "GET /API/V1/PERSONS", 19) == 0) {
        time_t timestamp = time(NULL);
        char json[256];
        sprintf(json, "{\"people\": %d, \"timestamp\": %ld}", current_person_count, timestamp);
        char http_header[1024];
        sprintf(http_header, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: %zu\r\nConnection: close\r\n\r\n%s", strlen(json), json);
        SSL_write(ssl, http_header, strlen(http_header));
    }
    else if (strncmp(buffer, "GET /API/V1/HISTORY", 19) == 0) {
        char json_body[4096] = "{\"total_detections\": ";
        sqlite3_stmt *stmt;
        
        sqlite3_prepare_v2(db, "SELECT total_detections FROM stats WHERE id=1;", -1, &stmt, NULL);
        if (sqlite3_step(stmt) == SQLITE_ROW) {
            char total_str[32];
            sprintf(total_str, "%d", sqlite3_column_int(stmt, 0));
            strcat(json_body, total_str);
        } else {
            strcat(json_body, "0");
        }
        sqlite3_finalize(stmt);

        strcat(json_body, ", \"history\": [");
        
        sqlite3_prepare_v2(db, "SELECT count, timestamp FROM history ORDER BY id DESC;", -1, &stmt, NULL);
        int first = 1;
        while (sqlite3_step(stmt) == SQLITE_ROW) {
            if (!first) strcat(json_body, ", ");
            char temp[128];
            sprintf(temp, "{\"count\": %d, \"timestamp\": %d}", sqlite3_column_int(stmt, 0), sqlite3_column_int(stmt, 1));
            strcat(json_body, temp);
            first = 0;
        }
        sqlite3_finalize(stmt);
        strcat(json_body, "]}");

        char http_header[8192]; 
        sprintf(http_header, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: %zu\r\nConnection: close\r\n\r\n%s", strlen(json_body), json_body);
        SSL_write(ssl, http_header, strlen(http_header));
    }
    else if (strncmp(buffer, "GET /API/V1/GUARD", 17) == 0) {
        char json[256];
        sprintf(json, "{\"guard_mode\": %d}", guard_mode_active);
        char http_header[1024];
        sprintf(http_header, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: %zu\r\nConnection: close\r\n\r\n%s", strlen(json), json);
        SSL_write(ssl, http_header, strlen(http_header));
    }
else if (strncmp(buffer, "POST /API/V1/GUARD", 18) == 0) {
        guard_mode_active = !guard_mode_active; 
        printf("\n[API] Guard Mode toggled. Now: %d\n", guard_mode_active);
        
        if (guard_mode_active == 0) {
            last_email_time = 0; 
        }
        else if (guard_mode_active == 1 && current_person_count > 0) {
            time_t now = time(NULL);
            if ((now - last_email_time) >= 30) {
                last_email_time = now;
                printf("\n[SECURITY] SYSTEM ARMED WITH INTRUDER ALREADY PRESENT!\n");
                
                char *mqtt_pass = getenv("MQTT_BROKER_PASS");
                char mqtt_cmd[512];
                sprintf(mqtt_cmd, "mosquitto_pub -h 192.168.118.1 -u guard_admin -P %s -t 'alarm/%s/home' -m '{\"alert\": \"Intruder Detected!\", \"count\": %d}'", 
                        mqtt_pass ? mqtt_pass : "", STUDENT_ID, current_person_count);
                system(mqtt_cmd);
                
                send_email_alert(ALERT_INTRUDER, current_person_count, get_cpu_temp(), now);
            }
        }
        char json[256];
        sprintf(json, "{\"guard_mode\": %d}", guard_mode_active);
        char http_header[1024];
        sprintf(http_header, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: %zu\r\nConnection: close\r\n\r\n%s", strlen(json), json);
        SSL_write(ssl, http_header, strlen(http_header));
    }
    else if (strncmp(buffer, "POST /API/V1/COMMAND", 20) == 0) {
        char *json = "{\"status\": \"Command received\"}";
        char http_header[1024];
        sprintf(http_header, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: %zu\r\nConnection: close\r\n\r\n%s", strlen(json), json);
        SSL_write(ssl, http_header, strlen(http_header));

        if (strstr(buffer, "reboot") != NULL) system("/sbin/reboot");
    }
    
    int fd = SSL_get_fd(ssl); 
    SSL_shutdown(ssl); 
    SSL_free(ssl); 
    close(fd);
    return NULL;
}

int main() {
    signal(SIGPIPE, SIG_IGN);
    // FIXED: Removed the premature timer initialization so Watchdog doesn't trigger before Python starts!
    
    init_blackbox_db();

    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();
    SSL_CTX *ctx = SSL_CTX_new(TLS_server_method());
    if (SSL_CTX_use_certificate_file(ctx, "server.crt", SSL_FILETYPE_PEM) <= 0 || 
        SSL_CTX_use_PrivateKey_file(ctx, "server.key", SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr); exit(EXIT_FAILURE);
    }

    pthread_t udp_thread, temp_thread, mqtt_thread, person_thread, watchdog_th;
    pthread_create(&udp_thread, NULL, udp_video_receiver, NULL);
    pthread_create(&temp_thread, NULL, udp_temp_receiver, NULL);
    pthread_create(&mqtt_thread, NULL, mqtt_telemetry_thread, NULL);
    pthread_create(&person_thread, NULL, udp_person_receiver, NULL);
    pthread_create(&watchdog_th, NULL, watchdog_thread, NULL); 

    int server_fd, client_socket;
    struct sockaddr_in address;
    int opt = 1, addrlen = sizeof(address);

    server_fd = socket(AF_INET, SOCK_STREAM, 0);
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &opt, sizeof(opt));
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(HTTPS_PORT);
    bind(server_fd, (struct sockaddr *)&address, sizeof(address));
    listen(server_fd, 5);
    
    printf("Secure HTTPS Server running on port %d with Active Watchdog, Thermal Management & SQLite Black Box...\n", HTTPS_PORT);

    while(1) {
        client_socket = accept(server_fd, (struct sockaddr *)&address, (socklen_t*)&addrlen);
        if (client_socket < 0) continue;

        SSL *ssl = SSL_new(ctx);
        SSL_set_fd(ssl, client_socket);
        
        // FIXED: Each client request now runs in its own background thread! No more blocking.
        pthread_t client_th;
        pthread_create(&client_th, NULL, https_client_handler, (void*)ssl);
        pthread_detach(client_th);
    }
    return 0;
}
