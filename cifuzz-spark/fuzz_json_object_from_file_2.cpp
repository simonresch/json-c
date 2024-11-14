#include <assert.h>
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <cifuzz/cifuzz.h>
#include <fuzzer/FuzzedDataProvider.h>
#include "json.h"
#include "json_util.h"

extern "C" {
  #include "strerror_override.h"
}

FUZZ_TEST_SETUP() {
  // One time initialization tasks, e.g., memory allocation, file opening.
}

FUZZ_TEST(const uint8_t *data, size_t size) {
  // Initialize FuzzedDataProvider
  FuzzedDataProvider fdp(data, size);

  // Create a temporary file in the system's temp directory
  char temp_filename[] = "/tmp/json_fuzzXXXXXX";
  int fd = mkstemp(temp_filename);
  if (fd == -1) {
    return;
  }

  // Write fuzzed data into the temporary file
  write(fd, data, size);
  close(fd);

  // Test json_object_from_file
  json_object *jo = json_object_from_file(temp_filename);
  if (jo != NULL) {
    json_object_put(jo);
  }

  // Test json_object_from_fd
  fd = open(temp_filename, O_RDONLY);
  if (fd != -1) {
    json_object *jo_fd = json_object_from_fd(fd);
    if (jo_fd != NULL) {
      json_object_put(jo_fd);
    }
    close(fd);
  }

  // Remove the temporary file
  unlink(temp_filename);
}
