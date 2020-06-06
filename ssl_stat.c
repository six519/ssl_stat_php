#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <curl/curl.h>
#include <string.h>
#include "php.h"

#define PHP_SSL_STAT_VERSION "1.0.0"
#define PHP_SSL_STAT_EXTNAME "ssl_stat"

char *get_second_part(char *str) {
    char * token = strtok(str, ":");
    token = strtok(NULL, ":");
    return token;
}

char *get_datetime(char *str) {
    char * retstr = (char *) malloc(30);
    char * token = strtok(str, ":");
    strcpy(retstr, "");
    int ignore_first = 1;
    while( token != NULL ) {
        if (ignore_first) {
            ignore_first = 0;
            token = strtok(NULL, " ");
            continue;
        }
        strcat(retstr, token);
        strcat(retstr, " ");
        token = strtok(NULL, " ");
    }
    return retstr;
}

static size_t wrfu(void *ptr,  size_t  size,  size_t  nmemb,  void *stream) {
    (void)stream;
    (void)ptr;
    return size * nmemb;
}

PHP_FUNCTION(ssl_stat_check);

extern zend_module_entry ssl_stat_module_entry;
#define phpext_my_extension_ptr &ssl_stat_module_entry

static zend_function_entry ssl_stat_functions[] = {
    PHP_FE(ssl_stat_check, NULL)
    {NULL, NULL, NULL}
};

zend_module_entry ssl_stat_module_entry = {
    #if ZEND_MODULE_API_NO >= 20170718
    STANDARD_MODULE_HEADER,
    #endif
    PHP_SSL_STAT_EXTNAME,
    ssl_stat_functions,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    #if ZEND_MODULE_API_NO >= 20170718
    PHP_SSL_STAT_VERSION,
    #endif
    STANDARD_MODULE_PROPERTIES
};

ZEND_GET_MODULE(ssl_stat)

PHP_FUNCTION(ssl_stat_check) {

    char *url_to_check;
    size_t url_to_check_len;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s", &url_to_check, &url_to_check_len) == FAILURE) { 
        return;
    }

    array_init(return_value);

    CURL *curl;
    CURLcode res;

    curl_global_init(CURL_GLOBAL_DEFAULT);

    curl = curl_easy_init();
    if(curl) {
        curl_easy_setopt(curl, CURLOPT_URL, url_to_check);
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, wrfu);
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
        curl_easy_setopt(curl, CURLOPT_VERBOSE, 0L);
        curl_easy_setopt(curl, CURLOPT_CERTINFO, 1L);

        res = curl_easy_perform(curl);

        if(!res) {
            struct curl_certinfo *certinfo;
            int need_break = 0;
            char *serial_number, *expire_date, *start_date;

            res = curl_easy_getinfo(curl, CURLINFO_CERTINFO, &certinfo);

            if(!res && certinfo) {
                int i;

                for(i = 0; i < certinfo->num_of_certs; i++) {
                    struct curl_slist *slist;

                    for(slist = certinfo->certinfo[i]; slist; slist = slist->next) {
                        if (strstr(slist->data, "Serial Number:") != NULL) {
                            serial_number = get_second_part(slist->data);
                        }

                        if(strstr(slist->data, "Start date:") != NULL) {
                            start_date = get_datetime(slist->data);
                        } 

                        if(strstr(slist->data, "Expire date:") != NULL) {
                            expire_date = get_datetime(slist->data);
                        } 
                        if(strstr(slist->data, "Subject Alternative Name") != NULL) {
                            need_break = 1;
                        }
                    }

                    if (need_break) {
                        add_assoc_string(return_value, "serial_number", serial_number);
                        add_assoc_string(return_value, "start_date", start_date);
                        add_assoc_string(return_value, "expire_date", expire_date);
                        break;
                    }

                }
            }

        }

        curl_easy_cleanup(curl);
    }

    curl_global_cleanup();
}