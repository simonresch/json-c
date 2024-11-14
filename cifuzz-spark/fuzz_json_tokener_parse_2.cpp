// Necessary standard library imports
#include <assert.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Include the necessary headers from the json-c library
#include "json.h"
extern "C" {
  #include "json_tokener.h"
  #include "json_util.h"
  #include "json_object_iterator.h"
  #include "json_visit.h"
  #include "printbuf.h"
  #include "snprintf_compat.h"
  #include "strerror_override.h"
}

// Include the necessary headers for the fuzzing engine
#include <fuzzer/FuzzedDataProvider.h>
#include <cifuzz/cifuzz.h>

// One-time setup tasks
FUZZ_TEST_SETUP() {
  // One-time initialization tasks, if any
}

// Implementing necessary functions for json_c_visit
static int emit_object(json_object *jso, int flags, json_object *parent_jso, const char *jso_key,
                       size_t *jso_index, void *userarg) {
  return JSON_C_VISIT_RETURN_CONTINUE;
}

static int skip_arrays(json_object *jso, int flags, json_object *parent_jso, const char *jso_key,
                       size_t *jso_index, void *userarg) {
  if (json_object_get_type(jso) == json_type_array)
    return JSON_C_VISIT_RETURN_SKIP;
  return JSON_C_VISIT_RETURN_CONTINUE;
}

static int pop_and_stop(json_object *jso, int flags, json_object *parent_jso, const char *jso_key,
                        size_t *jso_index, void *userarg) {
  if (jso_key != NULL && strcmp(jso_key, "subobj1") == 0)
    return JSON_C_VISIT_RETURN_POP;
  if (jso_key != NULL && strcmp(jso_key, "obj3") == 0)
    return JSON_C_VISIT_RETURN_STOP;
  return JSON_C_VISIT_RETURN_CONTINUE;
}

static int err_on_subobj2(json_object *jso, int flags, json_object *parent_jso, const char *jso_key,
                          size_t *jso_index, void *userarg) {
  if (jso_key != NULL && strcmp(jso_key, "subobj2") == 0)
    return JSON_C_VISIT_RETURN_ERROR;
  return JSON_C_VISIT_RETURN_CONTINUE;
}

static int pop_array(json_object *jso, int flags, json_object *parent_jso, const char *jso_key,
                     size_t *jso_index, void *userarg) {
  if (jso_index != NULL && (*jso_index == 0))
    return JSON_C_VISIT_RETURN_POP;
  return JSON_C_VISIT_RETURN_CONTINUE;
}

static int stop_array(json_object *jso, int flags, json_object *parent_jso, const char *jso_key,
                      size_t *jso_index, void *userarg) {
  if (jso_index != NULL && (*jso_index == 0))
    return JSON_C_VISIT_RETURN_STOP;
  return JSON_C_VISIT_RETURN_CONTINUE;
}

static int err_return(json_object *jso, int flags, json_object *parent_jso, const char *jso_key,
                      size_t *jso_index, void *userarg) {
  return 100;
}

// The entry point for the fuzz test
FUZZ_TEST(const uint8_t *data, size_t size) {
  // Initialize a FuzzedDataProvider to construct values from the fuzzer-generated input
  FuzzedDataProvider fdp(data, size);

  // Fuzzing json_tokener_parse and json_object_to_json_string functions
  {
    std::string json_str = fdp.ConsumeRandomLengthString(1024);
    json_object *parsed_obj = json_tokener_parse(json_str.c_str());
    if (parsed_obj) {
      json_object_to_json_string(parsed_obj);
      json_object_put(parsed_obj);
    }
  }

  // Fuzzing json_object_array_add and json_object_array_insert_idx functions
  {
    json_object *my_array = json_object_new_array();
    int32_t val1 = fdp.ConsumeIntegral<int32_t>();
    int32_t val2 = fdp.ConsumeIntegral<int32_t>();
    int32_t val3 = fdp.ConsumeIntegral<int32_t>();
    int32_t val4 = fdp.ConsumeIntegral<int32_t>();
    int32_t val5 = fdp.ConsumeIntegral<int32_t>();

    json_object_array_add(my_array, json_object_new_int(val1));
    json_object_array_add(my_array, json_object_new_int(val2));
    json_object_array_add(my_array, json_object_new_int(val3));
    json_object_array_insert_idx(my_array, 2, json_object_new_int(val4));
    json_object_array_insert_idx(my_array, 5, json_object_new_int(val5));

    json_object_put(my_array);
  }

  // Fuzzing json_object_to_file and json_object_to_file_ext functions
  {
    json_object *jso = json_tokener_parse(fdp.ConsumeRandomLengthString(1024).c_str());
    if (jso) {
      const char *outfile = "/tmp/json.out";
      json_object_to_file(outfile, jso);
      json_object_to_file_ext(outfile, jso, JSON_C_TO_STRING_PRETTY);
      json_object_put(jso);
    }
  }

  // Fuzzing json_object_iter functions
  {
    std::string json_str = fdp.ConsumeRandomLengthString(1024);
    json_object *new_obj = json_tokener_parse(json_str.c_str());
    if (new_obj) {
      struct json_object_iterator it;
      struct json_object_iterator itEnd;

      it = json_object_iter_init_default();
      it = json_object_iter_begin(new_obj);
      itEnd = json_object_iter_end(new_obj);

      while (!json_object_iter_equal(&it, &itEnd)) {
        json_object_iter_peek_name(&it);
        json_object_to_json_string(json_object_iter_peek_value(&it));
        json_object_iter_next(&it);
      }

      json_object_put(new_obj);
    }
  }

  // Fuzzing json_c_visit functions
  {
    std::string json_str = fdp.ConsumeRandomLengthString(1024);
    json_object *jso = json_tokener_parse(json_str.c_str());
    if (jso) {
      json_c_visit(jso, 0, emit_object, nullptr);
      json_c_visit(jso, 0, skip_arrays, nullptr);
      json_c_visit(jso, 0, pop_and_stop, nullptr);
      json_c_visit(jso, 0, err_on_subobj2, nullptr);
      json_c_visit(jso, 0, pop_array, nullptr);
      json_c_visit(jso, 0, stop_array, nullptr);
      json_c_visit(jso, 0, err_return, nullptr);
      json_object_put(jso);
    }
  }
}
