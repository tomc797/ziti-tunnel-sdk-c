/*
 Copyright 2019-2021 NetFoundry Inc.

 Licensed under the Apache License, Version 2.0 (the "License");
 you may not use this file except in compliance with the License.
 You may obtain a copy of the License at

 https://www.apache.org/licenses/LICENSE-2.0

 Unless required by applicable law or agreed to in writing, software
 distributed under the License is distributed on an "AS IS" BASIS,
 WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 See the License for the specific language governing permissions and
 limitations under the License.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#if __linux__
#include <pwd.h>
#include <grp.h>
#include <unistd.h>
#endif

#include <ziti/ziti_log.h>

const char* app_data = "APPDATA";
static char* identifier_path = NULL;

static int makedirs(char *path);

char* get_system_config_path() {
    char* config_path = malloc(FILENAME_MAX * sizeof(char));

    if (!config_path)
      abort();

#if _WIN32
    sprintf(config_path, "%s/NetFoundry", getenv(app_data));
#elif __linux__
    const char *netns = getenv("ZITI_NETNS");
    if (netns) {
      sprintf(config_path, "/var/lib/ziti/netns/%s", netns);
    } else {
      sprintf(config_path, "/var/lib/ziti");
    }
    (void) makedirs(config_path);
#else
    sprintf(config_path, "/tmp");
#endif
    return config_path;
}

char* get_identifier_path() {
    return identifier_path;
}

void set_identifier_path(char* id_path) {
    if (id_path != NULL) {
        identifier_path = strdup(id_path);
    }
}

char* get_config_file_name(char* config_path) {
    if (config_path != NULL) {
        char* config_file_name = calloc(FILENAME_MAX, sizeof(char));
        snprintf(config_file_name, FILENAME_MAX, "%s/config.json", config_path);
        return config_file_name;
    } else {
        return "config.json";
    }

}

char* get_backup_config_file_name(char* config_path) {
    if (config_path != NULL) {
        char* bkp_config_file_name = calloc(FILENAME_MAX, sizeof(char));
        snprintf(bkp_config_file_name, FILENAME_MAX, "%s/config.json.backup", config_path);
        return bkp_config_file_name;
    } else {
        return "config.json.backup";
    }
}

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#include <errno.h>

static int ziti_user(uid_t *uid, gid_t *gid)
{
  static uid_t saved_uid;
  static gid_t saved_gid;
  static int initialized = 0;
  struct passwd *pw;

  if (!initialized) {
    if ((pw = getpwnam("ziti")) == NULL) {
      ZITI_LOG(ERROR, "getpwnam: [Errno %d] %s", errno, strerror(errno));
      return -1;
    }
    saved_uid = pw->pw_uid;
    saved_gid = pw->pw_gid;
  }
  *uid = saved_uid;
  *gid = saved_gid;
  return 0;
}

static int makedirs(char *path)
{
  struct stat sb;
  char *slash = path;
  mode_t old_mask;
  uid_t uid;
  gid_t gid;
  int exists = 0;
  int rv = 0;

  old_mask = umask(0027);
  ziti_user(&uid, &gid);

  for (;;) {
    slash += strspn(slash, "/");
    slash += strcspn(slash, "/");

    int done = *slash == '\0';

    *slash = '\0';

    exists = stat(path, &sb) == 0;

    if (mkdir(path, 0777) != 0) {
      int mkdir_errno = errno;

      if (stat(path, &sb) == -1) {
        errno = mkdir_errno;
        rv = -1;
        goto out;
      }

      if (!S_ISDIR(sb.st_mode)) {
        errno = ENOTDIR;
        rv = -1;
        goto out;
      }
    }

    if (!exists) {
      (void) chown(path, uid, gid);
    }

    if (done) break;

    *slash = '/';
  }

out:
  umask(old_mask);
  return rv;
}

char *join_path(const char *components[static 1])
{
  size_t n = 0;
  char *path;

  for (const char *comp, **comps = components; (comp = *comps); comps++) {
    n += strlen(comp) + 1;
  }

  path = malloc(n);
  if (!path)
    abort();

  n = 0;
  for (const char *comp, **comps = components; (comp = *comps); comps++) {
    size_t complen;

    if (n > 0) path[n++] = '/';
    complen = strlen(comp);
    memcpy(path+n, comp, complen+1);
    n += complen;
  }

  return path;
}

char *get_socket_path(const char *sockname)
{
  char *system_config_path = get_system_config_path();
  char *dirpath, *filepath;

  dirpath = join_path((const char*[]){system_config_path, "sock", NULL});
  (void) makedirs(dirpath);
  filepath = join_path((const char*[]){dirpath, sockname, NULL});
  free(system_config_path);
  free(dirpath);
  return filepath;
}

char *make_identifier_dirpath(const char *config_dir)
{
  const char *netns = getenv("ZITI_NETNS");
  char *dirpath;

  if (netns) {
      dirpath = join_path((const char*[]){config_dir, "netns", netns, NULL});
  } else {
      dirpath = join_path((const char*[]){config_dir});
  }
  (void) makedirs(dirpath);
  return dirpath;
}
