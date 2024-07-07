/*
 Copyright 2021 NetFoundry Inc.

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

#ifndef ZITI_TUNNELER_SDK_TUN_H
#define ZITI_TUNNELER_SDK_TUN_H

//#include <linux/if.h>
#include <net/if.h>
#include "ziti/netif_driver.h"

struct netif_options {
    bool use_rt_main;
};

struct netif_handle_s {
    int  fd;
    char name[IFNAMSIZ];

    int route_table;

    model_map *route_updates;
};

extern netif_driver tun_open(struct uv_loop_s *loop, uint32_t tun_ip, uint32_t dns_ip, const char *cidr, char *error, size_t error_len, const struct netif_options *opts);

#endif //ZITI_TUNNELER_SDK_TUN_H
