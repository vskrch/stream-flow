#ifndef STREAM_FLOW_H
#define STREAM_FLOW_H

#ifdef __cplusplus
extern "C" {
#endif

#define STREAM_FLOW_OK 0
#define STREAM_FLOW_PANIC -1
#define STREAM_FLOW_INVALID_ARGUMENT -2
#define STREAM_FLOW_ERROR -3

int stream_flow_ffi_version(void);
char *stream_flow_version_string(void);
void stream_flow_string_free(char *ptr);
int stream_flow_validate_config_json(const char *json);
int stream_flow_generate_proxy_url_json(
    const char *config_json,
    const char *request_json,
    char **out_json);
int stream_flow_store_normalize_json(const char *store, char **out_json);
int stream_flow_store_catalog_json(char **out_json);

#ifdef __cplusplus
}
#endif

#endif
