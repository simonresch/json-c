#include <assert.h>
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <string.h>
#include <cifuzz/cifuzz.h>
#include <fuzzer/FuzzedDataProvider.h>
#include "config.h"
#include "json.h"
#include "snprintf_compat.h"
#include "json_patch.h"

extern "C" {
  #include "strerror_override.h"
}

void test_json_patch_op(struct json_object *jo) {
    const char *comment = json_object_get_string(json_object_object_get(jo, "comment"));
    struct json_object *doc = json_object_object_get(jo, "doc");
    struct json_object *patch = json_object_object_get(jo, "patch");
    struct json_object *expected = NULL;
    json_bool have_expected = json_object_object_get_ex(jo, "expected", &expected);
    struct json_object *error = json_object_object_get(jo, "error");
    const char *error_s = json_object_get_string(error);
    struct json_object *res = NULL;
    int ret;

    struct json_patch_error jperr;
    if (error) {
        if (json_patch_apply(doc, patch, &res, &jperr) != -1) {
            json_object_put(res);
            return;
        }
        if (jperr.errno_code == 0) {
            json_object_put(res);
            return;
        }
        json_object_put(res);
    } else {
        ret = json_patch_apply(doc, patch, &res, &jperr);
        if (ret) {
            json_object_put(res);
            return;
        }
        if (jperr.errno_code != 0) {
            json_object_put(res);
            return;
        }
        ret = json_object_equal(expected, res);
        if (ret == 0) {
            json_object_put(res);
            return;
        }
        json_object_put(res);
        res = NULL;
    }
}

FUZZ_TEST(const uint8_t *data, size_t size) {
    FuzzedDataProvider fdp(data, size);

    // Create a JSON object from fuzzed data
    std::string json_data = fdp.ConsumeRandomLengthString(size);
    struct json_object *jo = json_tokener_parse(json_data.c_str());

    if (jo != NULL) {
        test_json_patch_op(jo);
        json_object_put(jo);
    }
}
