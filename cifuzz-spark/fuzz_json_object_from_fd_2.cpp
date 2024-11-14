#include <assert.h>
#include <cifuzz/cifuzz.h>
#include <fcntl.h>
#include <limits.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <fuzzer/FuzzedDataProvider.h>

extern "C" {
  #include "strerror_override.h"
  #include "json_util.h"
  #include "json_object.h"
  #include "json_tokener.h"
  #include "printbuf.h"
}

FUZZ_TEST_SETUP() {
  // One time initialization tasks, e.g., memory allocation, file opening.
}

FUZZ_TEST(const uint8_t *data, size_t size) {
  // Use FuzzedDataProvider to handle the fuzzing data
  FuzzedDataProvider fdp(data, size);

  // Create a temporary file to use with json_object_from_file
  char tmp_filename[] = "/tmp/fuzz_jsonXXXXXX";
  int fd = mkstemp(tmp_filename);
  if (fd == -1) {
    return;
  }

  // Write fuzz data to the temporary file
  std::vector<uint8_t> file_content = fdp.ConsumeBytes<uint8_t>(size);
  write(fd, file_content.data(), file_content.size());
  close(fd);

  // Fuzz json_object_from_file
  struct json_object *obj = json_object_from_file(tmp_filename);
  if (obj) {
    json_object_put(obj);
  }

  // Fuzz json_object_from_fd
  fd = open(tmp_filename, O_RDONLY);
  if (fd != -1) {
    obj = json_object_from_fd(fd);
    if (obj) {
      json_object_put(obj);
    }
    close(fd);
  }

  // Fuzz json_object_to_file and json_object_to_file_ext
  if (obj) {
    json_object_to_file(tmp_filename, obj);
    json_object_to_file_ext(tmp_filename, obj, JSON_C_TO_STRING_PRETTY);
  }

  // Fuzz json_object_array_length and json_object_array_get_idx
  if (obj && json_object_is_type(obj, json_type_array)) {
    size_t array_length = json_object_array_length(obj);
    for (size_t i = 0; i < array_length; ++i) {
      struct json_object *elem = json_object_array_get_idx(obj, i);
      if (elem) {
        json_object_put(elem);
      }
    }
  }

  // Remove the temporary file
  unlink(tmp_filename);
}
