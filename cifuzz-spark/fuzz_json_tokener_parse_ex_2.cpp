#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <cifuzz/cifuzz.h>
#include <fuzzer/FuzzedDataProvider.h>
extern "C" {
  #include "json_object.h"
  #include "json_tokener.h"
  #include "json_util.h"
}

// Function to simulate a callback, used in parseit function
static int dummy_callback(struct json_object *new_obj) {
  return 0; // Always return success
}

// Function to simulate the parseit function from the provided code examples
static int parseit(int fd, int (*callback)(struct json_object *)) {
  struct json_object *obj;
  char buf[32768];
  ssize_t ret;
  int depth = JSON_TOKENER_DEFAULT_DEPTH;
  json_tokener *tok;

  tok = json_tokener_new_ex(depth);
  if (!tok) {
    return 1;
  }

  size_t total_read = 0;
  while ((ret = read(fd, buf, sizeof(buf))) > 0) {
    size_t retu = (size_t)ret;
    total_read += retu;
    size_t start_pos = 0;
    while (start_pos != retu) {
      obj = json_tokener_parse_ex(tok, &buf[start_pos], retu - start_pos);
      enum json_tokener_error jerr = json_tokener_get_error(tok);
      size_t parse_end = json_tokener_get_parse_end(tok);
      if (obj == NULL && jerr != json_tokener_continue) {
        json_tokener_free(tok);
        return 1;
      }
      if (obj != NULL) {
        int cb_ret = callback(obj);
        json_object_put(obj);
        if (cb_ret != 0) {
          json_tokener_free(tok);
          return 1;
        }
      }
      start_pos += json_tokener_get_parse_end(tok);
      assert(start_pos <= retu);
    }
  }

  json_tokener_free(tok);
  return 0;
}

// Fuzzing entry point
FUZZ_TEST(const uint8_t *data, size_t size) {
  // Initialize the FuzzedDataProvider
  FuzzedDataProvider fdp(data, size);

  // Fuzzing json_tokener_parse_ex function
  // {
  //   std::string input_str = fdp.ConsumeRandomLengthString(1024);
  //   int depth = fdp.ConsumeIntegralInRange<int>(1, 32);
  //   json_tokener *tok = json_tokener_new_ex(depth);
  //   if (tok) {
  //     json_object *obj = json_tokener_parse_ex(tok, input_str.c_str(), input_str.length());
  //     if (obj != NULL) {
  //       json_object_put(obj);
  //     }
  //     json_tokener_free(tok);
  //   }
  // }

  // Fuzzing json_object_from_fd_ex function
  {
    std::string temp_file_content = fdp.ConsumeRandomLengthString(1024);
    char temp_file_path[] = "/tmp/fuzz_temp_file_XXXXXX";
    int fd = mkstemp(temp_file_path);
    if (fd != -1) {
      write(fd, temp_file_content.c_str(), temp_file_content.length());
      lseek(fd, 0, SEEK_SET);
      int depth = fdp.ConsumeIntegralInRange<int>(-1, 32);
      //int depth = 0;
      if (depth == 0) {
        depth = -1;
      }
      json_object *obj = json_object_from_fd_ex(fd, depth);
      if (obj != NULL) {
        json_object_put(obj);
      }
      close(fd);
      unlink(temp_file_path);
    }
  }

  // // Fuzzing parseit function
  // {
  //   std::string temp_file_content = fdp.ConsumeRandomLengthString(1024);
  //   char temp_file_path[] = "/tmp/fuzz_temp_file_XXXXXX";
  //   int fd = mkstemp(temp_file_path);
  //   if (fd != -1) {
  //     write(fd, temp_file_content.c_str(), temp_file_content.length());
  //     lseek(fd, 0, SEEK_SET);
  //     parseit(fd, dummy_callback);
  //     close(fd);
  //     unlink(temp_file_path);
  //   }
  // }
}
