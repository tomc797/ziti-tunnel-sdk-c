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

#define _GNU_SOURCE
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/wait.h>
//#include <linux/if.h>
#include <linux/if_tun.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <fcntl.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdarg.h>

#include <ziti/ziti_log.h>
#include <ziti/ziti_dns.h>

#include "resolvers.h"
#include "tun.h"
#include "utils.h"

#include <linux/capability.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <grp.h>
#include <pwd.h>
#include <sched.h>

#ifndef DEVTUN
#define DEVTUN "/dev/net/tun"
#endif

#define ZITI_USER     "ziti"
#define MAX_NLMSG_LEN 1024

/*
 * ip link set tun0 up
 * ip addr add 169.254.1.1 remote 169.254.0.0/16 dev tun0
 */

#if 0
#define IP_ADDR_ARGS "addr add %d.%d.%d.%d/24 dev %s"
#define IP_UP_ARGS "link set %s up"
#define IP_BIN "/sbin/ip "
#endif

#define CHECK_UV(op) \
    __extension__({ int rc = (op); if (rc < 0) ZITI_LOG(ERROR, "uv_err: %d/%s", rc, uv_strerror(rc)); rc >= 0; })

enum route_command { ROUTE_NOOP = 0, ROUTE_ADD = 1, ROUTE_DEL };

struct zt__netlink_socket {
    uv_udp_t h;
    uint32_t seq;
};

extern void dns_set_miss_status(int code);

static void dns_update_resolvectl(const char* tun, unsigned int ifindex, const char* addr);
static void dns_update_systemd_resolve(const char* tun, unsigned int ifindex, const char* addr);

static void (*dns_updater)(const char* tun, unsigned int ifindex, const char* addr);
static uv_once_t dns_updater_init;

static zt__netlink_socket_t *netlink_socket(uv_loop_t *loop, int protocol, unsigned int subscriptions);
static int netlink_sendmsg(zt__netlink_socket_t *sock, struct nlmsghdr *nlm);
static void netlink_close_cb(uv_handle_t *handle);
static int netlink_addattrl(struct nlmsghdr *nlm, int maxlen, int type, const void *data, int dlen);
static int netlink_addattr32(struct nlmsghdr *nlm, int maxlen, int type, uint32_t data);

static int get_netns_fd(const char *name);
static int join_netns(const char *netns);
static int restore_netns(int old_netns);

struct dnsmasq_process_s {
  uv_process_t base;
};

typedef struct dnsmasq_process_s dnsmasq_process_t;

static dnsmasq_process_t *dnsmasq_spawn(uv_loop_t *, const char *netns);
static void dnsmasq_terminate(dnsmasq_process_t *proc);

static struct {
    char tun_name[IFNAMSIZ];
    uint32_t dns_ip;

    uv_udp_t nl_udp;
    uv_timer_t update_timer;
} dns_maintainer;

#define NLMSG_TAIL(nmsg) \
   ((struct rtattr *) (((char *) (nmsg)) + NLMSG_ALIGN((nmsg)->nlmsg_len)))

int get_netns_fd(const char *name)
{
    const char *p;

    p = strchr(name, '/');
    if (p) {
        return open(name, O_RDONLY|O_CLOEXEC, 0);
    }

    for (const char *stem, **stems = (const char*[]) { "/run/netns", "/var/run/netns", NULL };
        (stem = *stems);
        stems++) {
        char *pathbuf = NULL;
        int fd;

        if (asprintf(&pathbuf, "%s/%s", stem, name) < 0)
            return -1;

        fd = open(pathbuf, O_RDONLY|O_CLOEXEC, 0);
        free(pathbuf);
        if (fd < 0 && errno == ENOENT)
            continue;

        return fd;
    }

    errno = ENOENT;
    return -1;
}

static int join_netns(const char *name)
{
    int old_netns = -1, netns;
    int ret, saved_errno;

    old_netns = open("/proc/self/ns/net", O_RDONLY|O_CLOEXEC, 0);
    if (old_netns < 0)
        abort();

    netns = get_netns_fd(name);
    /**
     * If the netns doesn't exist, try creating it.
     */
    if (netns < 0 && errno == ENOENT) {
        if (run_command("ip netns add %s", name) == 0)
            run_command("ip link set lo up");
        netns = get_netns_fd(name);
    }

    if (netns < 0)
      abort();

    ret = setns(netns, CLONE_NEWNET);
    saved_errno = errno;
    (void) close(netns);
    errno = saved_errno;

    if (!ret) {
        abort();
    }

    return old_netns;
}

static
int
restore_netns(int old_netns)
{
  int rv;

  rv = setns(old_netns, CLONE_NEWNET);
  if (rv < 0)
    abort();
  close(old_netns);
  return 0;
}

static zt__netlink_socket_t *netlink_socket(uv_loop_t *loop, int protocol, unsigned int subscriptions)
{
    int sd = socket(AF_NETLINK, SOCK_RAW|SOCK_CLOEXEC, protocol);
    if (sd < 0) {
        ZITI_LOG(ERROR, "RTNETLINK: cannot open netlink socket: %d/%s",
            errno, strerror(errno));
        return NULL;
    }

    int sndbuf = 32*1024;
    if (setsockopt(sd, SOL_SOCKET, SO_SNDBUF, &sndbuf, sizeof sndbuf) < 0) {
        ZITI_LOG(ERROR, "RTNETLINK: SNDBUF: %d/%s",
            errno, strerror(errno));
        goto err;
    }

    int rcvbuf = 1024*1024;
    if (setsockopt(sd, SOL_SOCKET, SO_RCVBUF, &rcvbuf, sizeof rcvbuf) < 0) {
        ZITI_LOG(ERROR, "RTNETLINK: SNDBUF: %d/%s",
            errno, strerror(errno));
        goto err;
    }

    struct sockaddr_nl name = { .nl_family = AF_NETLINK, .nl_groups = subscriptions };
    if (bind(sd, (struct sockaddr *)&name, sizeof name) < 0) {
        ZITI_LOG(ERROR, "RTNETLINK: cannot bind name to socket: %d/%s",
            errno, strerror(errno));
        goto err;
    }

    zt__netlink_socket_t *sock = calloc(sizeof *sock, 1);
    if (!sock) {
        ZITI_LOG(ERROR, "RTNETLINK: out of memory");
        goto err;
    }

    int rc = uv_udp_init(loop, &sock->h);
    if (!CHECK_UV(rc)) {
        goto err;
    }

    rc = uv_udp_open(&sock->h, sd);
    if (!CHECK_UV(rc)) {
        uv_close((uv_handle_t *)&sock->h, netlink_close_cb);
        return NULL;
    }

    struct timeval tv;
    (void) gettimeofday(&tv, NULL);
    sock->seq = tv.tv_usec;

    return sock;

err:
    (void) close(sd);
    return NULL;
}

static int netlink_sendmsg(zt__netlink_socket_t *sock, struct nlmsghdr *nlm)
{
    /**
     * Update sequence number. Ignore zero as special
     */
    nlm->nlmsg_seq = sock->seq++;
    if (!nlm->nlmsg_seq) nlm->nlmsg_seq = sock->seq++;

    uv_udp_send_t send_req;
    uv_buf_t send_buf = uv_buf_init((char *)nlm, nlm->nlmsg_len);
    int status = uv_udp_send(&send_req, &sock->h, &send_buf, 1, NULL, NULL);
    if (status < 0) {
        ZITI_LOG(WARN, "RTNETLINK: failed sending message: %d/%s", status, uv_strerror(status));
        return -1;
    }

    return 0;
}

static void netlink_close_cb(uv_handle_t *handle)
{
    zt__netlink_socket_t *sock = (zt__netlink_socket_t *)((char *)handle - offsetof(struct zt__netlink_socket, h));
    free(sock);
}

static int netlink_addattrl(struct nlmsghdr *nlm, int maxlen, int type, const void *data, int dlen)
{
    int alen = RTA_LENGTH(dlen);
    int newlen = NLMSG_ALIGN(nlm->nlmsg_len) + RTA_ALIGN(alen);

    if (newlen > maxlen) {
        ZITI_LOG(WARN, "RTNETLINK: message exceeds length limit of %d", maxlen);
        return -1;
    }

    struct rtattr *rta = NLMSG_TAIL(nlm);
    rta->rta_type = type;
    rta->rta_len = alen;
    memcpy(RTA_DATA(rta), data, dlen);

    nlm->nlmsg_len = newlen;

    return 0;
}

static int netlink_addattr32(struct nlmsghdr *nlm, int maxlen, int type, uint32_t data)
{
  return netlink_addattrl(nlm, maxlen, type, &data, sizeof data);
}

static int tun_close(struct netif_handle_s *tun) {
    int r = 0;

    if (tun == NULL) {
        return 0;
    }

    dnsmasq_terminate(tun->dnsmasq_proc);

    if (tun->route_sock) {
        uv_udp_recv_stop(&tun->route_sock->h);
        uv_close((uv_handle_t *)&tun->route_sock->h, netlink_close_cb);
    }

    if (tun->fd > -1) {
        r = close(tun->fd);
    }

    free(tun);
    return r;
}

ssize_t tun_read(netif_handle tun, void *buf, size_t len) {
    return read(tun->fd, buf, len);
}

ssize_t tun_write(netif_handle tun, const void *buf, size_t len) {
    return write(tun->fd, buf, len);
}

int tun_uv_poll_init(netif_handle tun, uv_loop_t *loop, uv_poll_t *tun_poll_req) {
    return uv_poll_init(loop, tun_poll_req, tun->fd);
}

int tun_add_route(netif_handle tun, const char *dest) {
    if (tun->route_updates == NULL) {
        tun->route_updates = calloc(1, sizeof(*tun->route_updates));
    }
    model_map_set(tun->route_updates, dest, (void*)(uintptr_t)ROUTE_ADD);
    return 0;
}

int tun_delete_route(netif_handle tun, const char *dest) {
    if (tun->route_updates == NULL) {
        tun->route_updates = calloc(1, sizeof(*tun->route_updates));
    }
    model_map_set(tun->route_updates, dest, (void*)(uintptr_t)ROUTE_DEL);
    return 0;
}

struct rt_process_cmd {
    model_map *updates;
    netif_handle tun;
};

static void route_updates_done(uv_work_t *wr, int status) {
    struct rt_process_cmd *cmd = wr->data;
    ZITI_LOG(INFO, "route updates[%zd]: %d/%s", model_map_size(cmd->updates), status, status ? uv_strerror(status) : "OK");

    model_map_iter it = model_map_iterator(cmd->updates);
    while(it) {
        it = model_map_it_remove(it);
    }
    free(cmd->updates);
    free(cmd);
    free(wr);
}

static int route_cmd(netif_handle tun, enum route_command cmd, const ziti_address *dest)
{
    union request {
        struct {
            struct nlmsghdr nlm;
            struct rtmsg rtm;
        };
        char data[MAX_NLMSG_LEN];
    } request = {
        .nlm.nlmsg_len = NLMSG_LENGTH(sizeof(struct rtmsg)),
        .nlm.nlmsg_flags = NLM_F_REQUEST,
        .rtm.rtm_table = RT_TABLE_MAIN,
        .rtm.rtm_scope = RT_SCOPE_LINK,
        .rtm.rtm_protocol = RTPROT_STATIC,
        .rtm.rtm_type = RTN_UNICAST,
    };

    switch (cmd) {
      case ROUTE_ADD:
          request.nlm.nlmsg_type = RTM_NEWROUTE;
          request.nlm.nlmsg_flags |= NLM_F_CREATE|NLM_F_EXCL;
          break;
      case ROUTE_DEL:
          request.nlm.nlmsg_type = RTM_DELROUTE;
          break;
      default:
          return -1;
    }

    if (dest->type != ziti_address_cidr)
        return -1;

    size_t iplen;
    switch (dest->addr.cidr.af) {
      case AF_INET:
          iplen = sizeof(struct in_addr);
          break;
      case AF_INET6:
          iplen = sizeof(struct in6_addr);
          break;
      default:
          return -1;
    }

    request.rtm.rtm_family = dest->addr.cidr.af;
    request.rtm.rtm_dst_len = dest->addr.cidr.bits;
    if (netlink_addattrl(&request.nlm, sizeof request, RTA_DST, &dest->addr.cidr.ip, iplen) < 0)
        return -1;
    if (netlink_addattr32(&request.nlm, sizeof request, RTA_OIF, tun->ifindex) < 0)
        return -1;

    return netlink_sendmsg(tun->route_sock, &request.nlm);
}

static void process_routes_updates(uv_work_t *wr) {
    struct rt_process_cmd *cmd = wr->data;

    // delete before add
    for (enum route_command action, *actions = (enum route_command[]) { ROUTE_DEL, ROUTE_ADD, ROUTE_NOOP }; (action = *actions) != ROUTE_NOOP; actions++) {
        const char *prefix;
        const void *value;

        MODEL_MAP_FOREACH(prefix, value, cmd->updates) {
            if (action == (uintptr_t) value) {
                ziti_address address;

                if (parse_ziti_address_str(&address, prefix) < 0 || address.type != ziti_address_cidr) {
                    ZITI_LOG(ERROR, "failed to parse address '%s'", prefix);
                    continue;
                }

                route_cmd(cmd->tun, action, &address);
            }
        }
    }
}

int tun_commit_routes(netif_handle tun, uv_loop_t *l) {
    uv_work_t *wr = calloc(1, sizeof(uv_work_t));
    struct rt_process_cmd *cmd = calloc(1, sizeof(struct rt_process_cmd));
    if (tun->route_updates && model_map_size(tun->route_updates) > 0) {
        ZITI_LOG(INFO, "starting %zd route updates", model_map_size(tun->route_updates));
        cmd->tun = tun;
        cmd->updates = tun->route_updates;
        wr->data = cmd;
        tun->route_updates = NULL;
        uv_queue_work(l, wr, process_routes_updates, route_updates_done);
    }
    return 0;
}

static void dns_update_resolvectl(const char* tun, unsigned int ifindex, const char* addr) {

    run_command(RESOLVECTL " dns %s %s", tun, addr);
    int s = run_command_ex(false, RESOLVECTL " domain | grep -F -v '%s' | grep -F -q '~.'",
                           dns_maintainer.tun_name);
    // set wildcard domain if any other resolvers set it.
    if (s == 0) {
        run_command(RESOLVECTL " domain %s '~.'", dns_maintainer.tun_name);
    } else {
        // Use busctl due to systemd version differences fixed in systemd>=240
        run_command(BUSCTL " call %s %s %s SetLinkDomains 'ia(sb)' %u 0",
                RESOLVED_DBUS_NAME,
                RESOLVED_DBUS_PATH,
                RESOLVED_DBUS_MANAGER_INTERFACE,
                ifindex);
    }
    run_command(RESOLVECTL " dnssec %s no", dns_maintainer.tun_name);
    run_command(RESOLVECTL " reset-server-features");
    run_command(RESOLVECTL " flush-caches");
}

static void dns_update_systemd_resolve(const char* tun, unsigned int ifindex, const char* addr) {
    run_command(SYSTEMD_RESOLVE " -i %s --set-dns=%s", tun, addr);
    int s = run_command_ex(false, SYSTEMD_RESOLVE " --status | grep -F 'DNS Domain' | grep -F -q '~.'");
    // set wildcard domain if any other resolvers set it.
    if (s == 0) {
        run_command(SYSTEMD_RESOLVE " -i %s --set-domain='~.'", dns_maintainer.tun_name);
    } else {
        // Use busctl due to systemd version differences fixed in systemd>=240
        run_command(BUSCTL " call %s %s %s SetLinkDomains 'ia(sb)' %u 0",
                RESOLVED_DBUS_NAME,
                RESOLVED_DBUS_PATH,
                RESOLVED_DBUS_MANAGER_INTERFACE,
                ifindex);
    }
    run_command(SYSTEMD_RESOLVE " --set-dnssec=no --interface=%s", dns_maintainer.tun_name);
    run_command(SYSTEMD_RESOLVE " --reset-server-features");
    run_command(SYSTEMD_RESOLVE " --flush-caches");
}

static void find_dns_updater() {
#ifndef EXCLUDE_LIBSYSTEMD_RESOLVER
    if(try_libsystemd_resolver()) {
        dns_updater = dns_update_systemd_resolved;
        return;
    }
#endif
    if (is_executable(BUSCTL)) {
        if (run_command_ex(false, BUSCTL " status %s > /dev/null 2>&1", RESOLVED_DBUS_NAME) == 0) {
            if (is_executable(RESOLVECTL)) {
                dns_updater = dns_update_resolvectl;
                return;
            } else if (is_executable(SYSTEMD_RESOLVE)) {
                dns_updater = dns_update_systemd_resolve;
                return;
            } else {
                ZITI_LOG(WARN, "systemd-resolved DBus name found, but could not find a way to configure systemd-resolved");
            }
        } else {
            ZITI_LOG(TRACE, "systemd-resolved DBus name is NOT acquired");
        }
    }

    if (!(is_systemd_resolved_primary_resolver())) {
        // On newer systems, RESOLVCONF is a symlink to RESOLVECTL
        // By now, we know systemd-resolved is not available
        if (is_executable(RESOLVCONF) && !(is_resolvconf_systemd_resolved())) {
            dns_updater = dns_update_resolvconf;
            return;
        }

        ZITI_LOG(WARN, "Adding ziti resolver to /etc/resolv.conf. Ziti DNS functionality may be impaired");
        dns_updater = dns_update_etc_resolv;
        dns_set_miss_status(DNS_REFUSE);
    } else {
        ZITI_LOG(ERROR, "Refusing to alter DNS configuration. /etc/resolv.conf is a symlink to systemd-resolved, but no systemd resolver succeeded");
        exit(1);
    }
}

static void set_dns(uv_work_t *wr) {
    uv_once(&dns_updater_init, find_dns_updater);
    dns_updater(
            dns_maintainer.tun_name,
            if_nametoindex(dns_maintainer.tun_name),
            inet_ntoa(*(struct in_addr*)&dns_maintainer.dns_ip)
    );
}

static void after_set_dns(uv_work_t *wr, int status) {
    ZITI_LOG(DEBUG, "DNS update: %d", status);
    free(wr);
}

static void on_dns_update_time(uv_timer_t *t) {
    ZITI_LOG(DEBUG, "queuing DNS update");
    uv_work_t *wr = calloc(1, sizeof(uv_work_t));
    uv_queue_work(t->loop, wr, set_dns, after_set_dns);

}
static void do_dns_update(uv_loop_t *loop, int delay) {
    uv_timer_start(&dns_maintainer.update_timer, on_dns_update_time, delay, 0);
}

void nl_alloc(uv_handle_t *h, size_t req, uv_buf_t *b) {
    req = req < MAX_NLMSG_LEN ? MAX_NLMSG_LEN : req;
    b->base = malloc(req);
    b->len = b->base ? req : 0;
}

void on_nl_message(uv_udp_t *nl, ssize_t len, const uv_buf_t *buf, const struct sockaddr * addr, unsigned int i) {
    // delay to make sure systemd-resolved finished its own updates
    do_dns_update(nl->loop, 3000);
    if (buf->base) free(buf->base);
}

static void init_dns_maintainer(uv_loop_t *loop, const char *tun_name, uint32_t dns_ip) {
    strncpy(dns_maintainer.tun_name, tun_name, sizeof(dns_maintainer.tun_name));
    dns_maintainer.dns_ip = dns_ip;

    ZITI_LOG(DEBUG, "setting up NETLINK listener");
    struct sockaddr_nl local = {0};
    local.nl_family = AF_NETLINK;
    local.nl_groups = RTMGRP_LINK;// | RTMGRP_IPV4_ROUTE;

    int s = socket(AF_NETLINK, SOCK_DGRAM|SOCK_CLOEXEC, NETLINK_ROUTE);
    if ( s < 0) {
        ZITI_LOG(ERROR, "failed to open netlink socket: %d/%s", errno, strerror(errno));
    }
    if (bind(s, (struct sockaddr *)&local, sizeof(local)) < 0) {
        ZITI_LOG(ERROR, "failed to bind %d/%s", errno, strerror(errno));
    }

    CHECK_UV(uv_udp_init(loop, &dns_maintainer.nl_udp));
    uv_unref((uv_handle_t *) &dns_maintainer.nl_udp);
    CHECK_UV(uv_udp_open(&dns_maintainer.nl_udp, s));

    struct sockaddr_nl kern = {0};
    kern.nl_family = AF_NETLINK;
    kern.nl_groups = 0;

    CHECK_UV(uv_udp_recv_start(&dns_maintainer.nl_udp, nl_alloc, on_nl_message));

    uv_timer_init(loop, &dns_maintainer.update_timer);
    uv_unref((uv_handle_t *) &dns_maintainer.update_timer);
    do_dns_update(loop, 0);
}

static int tun_exclude_rt(netif_handle dev, uv_loop_t *l, const char *addr) {
    char cmd[1024];
    char route[128];
    FILE *cmdpipe = NULL;
    int n;

    n = snprintf(cmd, sizeof cmd,
        "ip -o route show match %s table all | "
        "awk '/dev %s/ { next; } { if (match($0, / metric ([^ ]+)/)) { metric = substr($0, RSTART, RLENGTH); } printf \"%%s %%s%%s\\n\", $2, $3, metric; }'",
        addr, dev->name);
    if (n > 0 && (size_t) n < sizeof cmd) {
        ZITI_LOG(DEBUG, "popen(%s)", cmd);
        cmdpipe = popen(cmd, "r");
    } else {
        errno = ENOMEM;
    }

    if (cmdpipe == NULL) {
        ZITI_LOG(WARN, "ip route cmd popen(%s) failed [%d:%s]", cmd, errno, strerror(errno));
        return -1;
    }

    errno = 0;
    size_t size = fread(route, 1, sizeof route, cmdpipe);
    int saved_errno = errno;
    int ferr = ferror(cmdpipe);
    (void) pclose(cmdpipe);
    if (ferr) {
        errno = saved_errno ? saved_errno : EIO;
        ZITI_LOG(WARN, "ip route cmd I/O failed [%d:%s]", errno, strerror(errno));
        return -1;
    }

    // only look at first line
    char *p = memchr(route, '\n', size);
    // was a full line read?
    if (p == NULL || p == route) {
        ZITI_LOG(WARN, "failed to retrieve destination route");
        return -1;
    }
    *p = 0;

    ZITI_LOG(DEBUG, "route is %s %s", addr, route);

    return run_command("ip route replace %s %s", addr, route);
}

static int tun_noop_exclude_rt(netif_handle dev, uv_loop_t *l, const char *addr)
{
    /* UNUSED */
    (void) dev;
    (void) l;
    (void) addr;
    return 0;
}

static void netlink_on_response(uv_udp_t *route_sock, ssize_t nread, const uv_buf_t *resp, const struct sockaddr *addr, unsigned flags)
{
    /* UNUSED */
    (void) route_sock;
    (void) addr;
    (void) flags;

    if (nread < 0) {
        ZITI_LOG(WARN, "RTNETLINK: %zd/%s", nread, uv_strerror(nread));
        goto done;
    }

    for (struct nlmsghdr *h = (struct nlmsghdr *)resp->base; NLMSG_OK(h, nread); h = NLMSG_NEXT(h, nread)) {
        if (h->nlmsg_type == NLMSG_ERROR) {
            struct nlmsgerr *err = (struct nlmsgerr *)NLMSG_DATA(h);

            if (h->nlmsg_len < NLMSG_LENGTH(sizeof(struct nlmsgerr))) {
                ZITI_LOG(WARN, "RTNETLINK: error truncated");
                goto done;
            }

            if (err->error)
                ZITI_LOG(WARN, "RTNETLINK: %d/%s", -err->error, strerror(-err->error));
        }
    }

done:
    free(resp->base);
}

static int become_unprivileged(void)
{
    int saved_errno;
    if (geteuid() == 0) {
        struct passwd *pw;
        if ((pw = getpwnam(ZITI_USER)) == NULL) {
            saved_errno = errno;
            ZITI_LOG(ERROR, "getpwname: %d/%s", saved_errno, strerror(saved_errno));
            errno = saved_errno;
            return -1;
        }

        if (setresgid(pw->pw_gid, pw->pw_gid, pw->pw_gid) < 0) {
            saved_errno = errno;
            ZITI_LOG(ERROR, "getgid: %d/%s", errno, strerror(errno));
            errno = saved_errno;
            return -1;
        }

        if (initgroups(ZITI_USER, pw->pw_gid) < 0) {
            saved_errno = errno;
            ZITI_LOG(ERROR, "setgroups: %d/%s", errno, strerror(errno));
            errno = saved_errno;
            return -1;
        }

        if (prctl(PR_SET_KEEPCAPS, 1, 0, 0, 0) < 0) {
            saved_errno = errno;
            ZITI_LOG(ERROR, "keepcaps: %d/%s", errno, strerror(errno));
            errno = saved_errno;
            return -1;
        }

        if (setresuid(pw->pw_uid, pw->pw_uid, pw->pw_uid) < 0) {
            saved_errno = errno;
            ZITI_LOG(ERROR, "setuid: %d/%s", errno, strerror(errno));
            errno = saved_errno;
            return -1;
        }

        struct __user_cap_header_struct hdr = { .version = _LINUX_CAPABILITY_VERSION_3 };
        struct __user_cap_data_struct datap[_LINUX_CAPABILITY_U32S_3] = {{0}};
        unsigned int w = CAP_NET_ADMIN / 32, b = CAP_NET_ADMIN % 32;
        if (w >= sizeof datap/sizeof datap[0]) {
            saved_errno = errno = EINVAL;
            ZITI_LOG(ERROR, "capset: %d/%s", errno, strerror(errno));
            errno = saved_errno;
            return -1;
        }

        datap[w].permitted = datap[w].effective = 1UL << b;
        if (syscall(SYS_capset, &hdr, datap) < 0) {
            ZITI_LOG(ERROR, "capset: %d/%s", errno, strerror(errno));
            errno = saved_errno;
            return -1;
        }
    }

    return 0;
}

netif_driver tun_open1(uv_loop_t *loop, uint32_t tun_ip, uint32_t dns_ip, const char *dns_block, char *error, size_t error_len, const char *netns) {

    if (error != NULL) {
        memset(error, 0, error_len * sizeof(char));
    }

    struct netif_handle_s *tun = calloc(1, sizeof(struct netif_handle_s));
    if (tun == NULL) {
        if (error != NULL) {
            snprintf(error, error_len, "failed to allocate tun");
        }
        return NULL;
    }

    if ((tun->fd = open(DEVTUN, O_RDWR|O_CLOEXEC)) < 0) {
        if (error != NULL) {
            snprintf(error, error_len,"open %s failed", DEVTUN);
        }
        free(tun);
        return NULL;
    }

    struct ifreq ifr = { .ifr_name = "ziti%d",
                         .ifr_flags = IFF_TUN | IFF_NO_PI };

    if (ioctl(tun->fd, TUNSETIFF, &ifr) < 0) {
        if (error != NULL) {
            snprintf(error, error_len, "failed to open tun device:%s", strerror(errno));
        }
        tun_close(tun);
        return NULL;
    }

    strncpy(tun->name, ifr.ifr_name, sizeof(tun->name));

    if ((tun->ifindex = if_nametoindex(tun->name)) == 0) {
        if (error != NULL) {
            snprintf(error, error_len, "failed to get tun's ifindex: %s", strerror(errno));
        }
        tun_close(tun);
        return NULL;
    }

    zt__netlink_socket_t *route_sock;
    if ((route_sock = netlink_socket(loop, NETLINK_ROUTE, 0)) == NULL) {
        if (error != NULL) {
            snprintf(error, error_len, "failed to get tun's index: %s", strerror(errno));
        }
        tun_close(tun);
        return NULL;
    }

    int rc = uv_udp_recv_start(&route_sock->h, nl_alloc, netlink_on_response);
    if (rc < 0) {
        if (error != NULL) {
            snprintf(error, error_len, "uv_udp_recv_start: %s", uv_strerror(rc));
        }
        uv_close((uv_handle_t *)&route_sock->h, netlink_close_cb);
        tun_close(tun);
        return NULL;
    }

    tun->route_sock = route_sock;

    struct netif_driver_s *driver = calloc(1, sizeof(struct netif_driver_s));
    if (driver == NULL) {
        if (error != NULL) {
            snprintf(error, error_len, "failed to allocate netif_device_s");
        }
        tun_close(tun);
        return NULL;
    }

    driver->handle       = tun;
    driver->read         = tun_read;
    driver->write        = tun_write;
    driver->uv_poll_init = tun_uv_poll_init;
    driver->add_route    = tun_add_route;
    driver->delete_route = tun_delete_route;
    driver->close        = tun_close;
    driver->exclude_rt   = netns ? tun_noop_exclude_rt : tun_exclude_rt;
    driver->commit_routes = tun_commit_routes;

    run_command("ip link set %s up", tun->name);
    run_command("ip addr add %s dev %s", inet_ntoa(*(struct in_addr*)&tun_ip), tun->name);

    run_command("ip link set lo up");

    if (dns_ip) {
        init_dns_maintainer(loop, tun->name, dns_ip);
    }

    if (dns_block) {
        run_command("ip route add %s dev %s", dns_block, tun->name);
    }

    return driver;
}

static
void *
Xcalloc(size_t count, size_t size)
{
  void *p;

  if (!count || !size)
    abort();

  p = calloc(count, size);
  if (!p)
    abort();

  return p;
}

static
void *
Xmalloc(size_t n)
{
  return Xcalloc(1, n);
}

static
char *
Xstrdup(const char *s)
{
  size_t n = strlen(s)+1;
  return memcpy(Xmalloc(n), s, n);
}

static
int
Xasprintf(char **strp, const char *fmt, ...)
{
  va_list args;
  int ret, saved_errno;

  va_start(args, fmt);
  ret = vasprintf(strp, fmt, args);
  saved_errno = errno;
  va_end(args);
  errno = saved_errno;
  if (ret  < 0)
    abort();
  return ret;
}

static
void
dnsmasq_exit_cb(uv_process_t *handle, long int exit_status, int term_status)
{
    dnsmasq_process_t *proc = (dnsmasq_process_t *)((char *)handle - offsetof(dnsmasq_process_t, base));

    if (exit_status) {
      ZITI_LOG(ERROR, "dnsmasq exited with code %ld\n", exit_status);
    } else {
      ZITI_LOG(ERROR, "dnsmasq exited on signal %d\n", term_status);
    }
    proc->base.pid = (pid_t)-1;
}

static
dnsmasq_process_t *
dnsmasq_spawn(uv_loop_t *loop, const char *netns_name)
{
    uv_process_options_t opts = {0};
    dnsmasq_process_t *proc = NULL;
    const char *argz[8] = {0};
    const char *envz[3] = {0};
    char *etc_path = NULL;
    char *dnsmasq_confdir_path = NULL;
    char *server_conf = NULL;
    char *dnsmasq_confdir_conf = NULL;
    char *pathbuf = NULL;
    const char *path = NULL;
    size_t len;
    int rc;

    // namespace aware
    if (netns_name) {
      Xasprintf(&etc_path, "/etc/netns/%s", netns_name);
    } else {
      Xasprintf(&etc_path, "/etc");
    }
    Xasprintf(&dnsmasq_confdir_path, "%s/dnsmasq.d", etc_path);

    Xasprintf(&server_conf, "--server=%s", "100.64.0.2");
    if (access(dnsmasq_confdir_path, R_OK|X_OK)) {
        Xasprintf(&dnsmasq_confdir_conf, "--conf-dir=%s,*.conf", dnsmasq_confdir_path);
    }

    if ((len = confstr(_CS_PATH, NULL, 0)) > 0
        && confstr(_CS_PATH, pathbuf = Xmalloc(len), len) > 0) {
      path = pathbuf;
    } else {
      path = "/usr/sbin:/sbin:/usr/bin:/bin";
    }

    argz[0] = "/usr/sbin/dnsmasq";
    argz[1] = "--keep-in-foreground";
    argz[2] = "--conf-file=/dev/null";
    argz[3] = "--no-resolv";
    argz[4] = "--no-hosts";
    argz[5] = server_conf;
    argz[6] = dnsmasq_confdir_conf;
    argz[7] = NULL;

    envz[0] = path;
    envz[1] = "LANG=C";
    envz[2] = NULL;

    opts.file = (char *) argz[0];
    opts.args = (char **) argz;
    opts.env = (char **) envz;
    opts.cwd = "/";
    opts.exit_cb = dnsmasq_exit_cb;

    proc = (dnsmasq_process_t *)Xcalloc(1, sizeof *proc);

    if ((rc = uv_spawn(loop, &proc->base, &opts)) < 0) {
      ZITI_LOG(ERROR, "failed to spawn dnsmasq: %d/%s", rc, uv_strerror(rc));
      abort();
    }

    uv_unref((uv_handle_t *)&proc->base);

    free(etc_path);
    free(dnsmasq_confdir_path);
    free(server_conf);
    free(dnsmasq_confdir_conf);
    free(pathbuf);

    return proc;
}

void
dnsmasq_terminate(dnsmasq_process_t *proc)
{
    if (proc) {
      if (proc->base.pid != (pid_t)-1) {
        uv_process_kill(&proc->base, SIGTERM);
      }
      uv_close((uv_handle_t*)&proc->base, NULL);
      free(proc);
    }
}

netif_driver tun_open(uv_loop_t *loop, uint32_t tun_ip, uint32_t dns_ip, const char *dns_block, char *error, size_t error_len) {
  netif_driver driver;
  char *netns;
  int save_netns = -1;

  netns = getenv("ZITI_NETNS");
  if (netns)
      save_netns = join_netns(netns);

  driver = tun_open1(loop, tun_ip, dns_ip, dns_block, error, error_len, netns);

  if (save_netns > -1) {
      struct netif_handle_s *tun = driver->handle;

      tun->dnsmasq_proc = dnsmasq_spawn(loop, netns);
      restore_netns(save_netns);
  }

  return driver;
}
