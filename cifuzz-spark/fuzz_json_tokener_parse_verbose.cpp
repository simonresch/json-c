#include <assert.h>
#include <cifuzz/cifuzz.h>
#include <errno.h>
#include <limits.h>
#include <math.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <locale.h>
#include <strings.h>
#include <fuzzer/FuzzedDataProvider.h>

extern "C" {
  #include "debug.h"
  #include "json_object.h"
  #include "json_object_private.h"
  #include "json_tokener.h"
  #include "json_util.h"
  #include "printbuf.h"
}

FUZZ_TEST_SETUP() {
  // One-time initialization tasks, if any.
}

FUZZ_TEST(const uint8_t *data, size_t size) {
  FuzzedDataProvider fdp(data, size);

  // Fuzzing json_tokener_parse
  std::string json_string = fdp.ConsumeRandomLengthString(512);
  struct json_object *parsed_obj = json_tokener_parse(json_string.c_str());
  if (parsed_obj != NULL) {
    json_object_put(parsed_obj);
  }

  // Fuzzing json_object_array_add and related functions
  json_object *my_array = json_object_new_array();
  json_object *jo1 = json_object_new_int(fdp.ConsumeIntegral<int32_t>());
  json_object_array_add(my_array, jo1);
  json_object_array_add(my_array, json_object_new_int(fdp.ConsumeIntegral<int32_t>()));
  json_object_array_add(my_array, json_object_new_int(fdp.ConsumeIntegral<int32_t>()));

  // Insert at random index
  json_object_array_insert_idx(my_array, fdp.ConsumeIntegral<size_t>(), json_object_new_int(fdp.ConsumeIntegral<int32_t>()));
  struct json_object *jo2 = json_tokener_parse("[1, 2, 4, 5]");
  if (jo2 != NULL) {
    json_object_equal(my_array, jo2);
    json_object_put(jo2);
  }

  // Fuzzing json_object_to_json_string
  const char *json_str = json_object_to_json_string(my_array);
  if (json_str != NULL) {
    struct json_object *parsed_str_obj = json_tokener_parse(json_str);
    if (parsed_str_obj != NULL) {
      json_object_put(parsed_str_obj);
    }
  }

  json_object_put(my_array);

  // Fuzzing json_object_new_string_len and json_tokener_parse
  std::string input = fdp.ConsumeRandomLengthString(256);
  struct json_object *string = json_object_new_string_len(input.c_str(), input.size());
  if (string != NULL) {
    const char *json = json_object_to_json_string(string);
    if (json != NULL) {
      struct json_object *parsed_str = json_tokener_parse(json);
      if (parsed_str != NULL) {
        json_object_put(parsed_str);
      }
    }
    json_object_put(string);
  }

  // Fuzzing json_object_deep_copy
  struct json_object *src = json_tokener_parse(json_string.c_str());
  if (src != NULL) {
    struct json_object *dst = NULL;
    json_object_deep_copy(src, &dst, NULL);
    if (dst != NULL) {
      json_object_put(dst);
    }
    json_object_put(src);
  }

  // Fuzzing json_object_set_string
  struct json_object *tmp = json_object_new_string("initial");
  if (tmp != NULL) {
    std::string new_string = fdp.ConsumeRandomLengthString(128);
    json_object_set_string(tmp, new_string.c_str());
    json_object_put(tmp);
  }
}
