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
  // Initialize FuzzedDataProvider
  FuzzedDataProvider fdp(data, size);

  // Create a temporary file to use with file descriptor functions
  char temp_filename[] = "/tmp/json_fuzz_XXXXXX";
  int fd = mkstemp(temp_filename);
  if (fd == -1) {
    return;
  }

  // Write fuzzer data to the temporary file
  size_t data_size = fdp.ConsumeIntegralInRange<size_t>(0, size);
  write(fd, data, data_size);
  lseek(fd, 0, SEEK_SET);

  // Fuzz json_object_from_fd_ex
  int depth = fdp.ConsumeIntegralInRange<int>(0, JSON_TOKENER_DEFAULT_DEPTH);
  if (depth > 0) {
    struct json_object *jso = json_object_from_fd_ex(fd, depth);
    if (jso != NULL) {
      json_object_put(jso);
    }
  }

  // Close and remove the temporary file
  close(fd);
  unlink(temp_filename);
}
