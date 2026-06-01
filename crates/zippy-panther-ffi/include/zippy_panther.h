#ifndef ZIPPY_PANTHER_H
#define ZIPPY_PANTHER_H

#ifdef __cplusplus
extern "C" {
#endif

#define ZIPPY_PANTHER_OK 0
#define ZIPPY_PANTHER_PANIC -1
#define ZIPPY_PANTHER_INVALID_ARGUMENT -2
#define ZIPPY_PANTHER_ERROR -3

int zippy_panther_ffi_version(void);
char *zippy_panther_version_string(void);
void zippy_panther_string_free(char *ptr);
int zippy_panther_validate_config_json(const char *json);
int zippy_panther_generate_proxy_url_json(
    const char *config_json,
    const char *request_json,
    char **out_json);
int zippy_panther_store_normalize_json(const char *store, char **out_json);
int zippy_panther_store_catalog_json(char **out_json);

#ifdef __cplusplus
}
#endif

#endif
