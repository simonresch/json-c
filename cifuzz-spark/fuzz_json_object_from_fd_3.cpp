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
  #include "debug.h"
  #include "json_object.h"
  #include "json_tokener.h"
  #include "json_util.h"
  #include "printbuf.h"
}

// FUZZ_TEST_SETUP is used for one-time initialization tasks
FUZZ_TEST_SETUP() {
  // No one-time setup is needed for this harness
}

// FUZZ_TEST is the entry point for the fuzzing harness
FUZZ_TEST(const uint8_t *data, size_t size) {
  // Initialize FuzzedDataProvider with the input data
  FuzzedDataProvider fdp(data, size);

  // Create a temporary file to use with json_object_from_file
  char filename[] = "/tmp/fuzz_json.XXXXXX";
  int fd = mkstemp(filename);
  if (fd == -1) {
    return;
  }

  // Write fuzzer data to the temporary file
  std::vector<uint8_t> file_content = fdp.ConsumeBytes<uint8_t>(fdp.remaining_bytes());
  write(fd, file_content.data(), file_content.size());
  close(fd);

  // Call json_object_from_file with the temporary file
  struct json_object *jo = json_object_from_file(filename);
  if (jo != NULL) {
    json_object_put(jo);
  }

  // Remove the temporary file
  unlink(filename);

  // Test json_object_from_fd using a valid file descriptor
  fd = open("/dev/null", O_RDONLY);
  if (fd != -1) {
    jo = json_object_from_fd(fd);
    if (jo != NULL) {
      json_object_put(jo);
    }
    close(fd);
  }

  // Test json_object_from_fd using an invalid file descriptor
  jo = json_object_from_fd(-1);
  if (jo != NULL) {
    json_object_put(jo);
  }

  // Test json_object_to_file_ext
  struct json_object *test_obj = json_object_new_object();
  json_object_object_add(test_obj, "key", json_object_new_string("value"));
  json_object_to_file_ext(filename, test_obj, JSON_C_TO_STRING_PRETTY);
  json_object_put(test_obj);

  // Test json_object_from_file with the file written above
  jo = json_object_from_file(filename);
  if (jo != NULL) {
    json_object_put(jo);
  }

  // Remove the temporary file
  unlink(filename);
}
