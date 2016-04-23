#include "poller.h"
using namespace geco::net;

#ifdef SCTP_OVER_UDP
int dummy_sctp_udp;
int dummy_sctpv6_udp;
static uint inet_checksum(const void* ptr, size_t count)
{
    ushort* addr = (ushort*) ptr;
    uint sum = 0;

    while (count > 1)
    {
        sum += *(ushort*) addr++;
        count -= 2;
    }

    if (count > 0)
        sum += *(uchar*) addr;

    while (sum >> 16)
        sum = (sum & 0xffff) + (sum >> 16);

    return (~sum);
}
#endif

int str_to_sockaddr(const char * str, sockaddrunion *su, bool ip4)
{
    int ret;
    memset((void*)su, 0, sizeof(union sockaddrunion));

    if (ip4)
    {
#ifndef WIN32
        ret = inet_aton(str, &su->sin.sin_addr);
#else
        (su->sin.sin_addr.s_addr = inet_addr(str)) == INADDR_NONE ? ret = 0 : ret = 1;
#endif

        if (ret > 0)  /* Valid IPv4 address format. */
        {
            su->sin.sin_family = AF_INET;
#ifdef HAVE_SIN_LEN
            su->sin.sin_len = sizeof(struct sockaddr_in);
#endif                          
            return 0;
        }
    }
    else
    {
        ret = inet_pton(AF_INET6, (const char *)str, &su->sin6.sin6_addr);
        if (ret > 0)     /* Valid IPv6 address format. */
        {
            su->sin6.sin6_family = AF_INET6;
#ifdef SIN6_LEN
            su->sin6.sin6_len = sizeof(struct sockaddr_in6);
#endif      
            su->sin6.sin6_scope_id = 0;
            return 0;
        }
    }
    return -1;
}
int sockaddr_to_str(sockaddrunion *su, uchar * buf, size_t len)
{
    char        ifnamebuffer[IFNAMSIZ];
    const char* ifname = 0;

    if (su->sa.sa_family == AF_INET)
    {
        if (len > 16) len = 16;
        strncpy((char *)buf, inet_ntoa(su->sin.sin_addr), len);
        return (1);
    }
    else if (su->sa.sa_family == AF_INET6)
    {
        if (inet_ntop(AF_INET6, &su->sin6.sin6_addr, (char *)buf, len) == NULL) return 0;
        if (IN6_IS_ADDR_LINKLOCAL(&su->sin6.sin6_addr))
        {
            // ifname = if_indextoname(su->sin6.sin6_scope_id, (char*)&ifnamebuffer);
            if (ifname == NULL)
            {
                return(0);   /* Bad scope ID! */
            }
            if (strlen((const char*)buf) + strlen(ifname) + 2 >= len)
            {
                return(0);   /* Not enough space! */
            }
            strcat((char*)buf, "%");
            strcat((char*)buf, ifname);
        }
        return (1);
    }
    return 0;
}
bool is_same_saddr(sockaddrunion *a, sockaddrunion *b)
{
    switch (saddr_family(a))
    {
        case AF_INET:
            return (saddr_family(b) == AF_INET &&
                s4addr(&a->sin) == s4addr(&b->sin));
            break;
        case AF_INET6:
            return (saddr_family(b) == AF_INET6 &&
                memcmp(s6addr(&a->sin6), s6addr(&b->sin6),
                sizeof(s6addr(&a->sin6)) == 0));
            break;
        default:
            error_logi(loglvl_major_error_abort,
                "Address family %d not supported",
                saddr_family(a));
            return false;
            break;
    }
}

int poller_t::poll_socket_despts(socket_despt_t* despts,
    int* count,
    int timeout,
    void(*lock)(void* data),
    void(*unlock)(void* data),
    void* data)
{
    struct timeval tv;
    struct timeval* to;

    fd_set            rd_fdset;;
    fd_set            wt_fdset;
    fd_set            except_fdset;
    int               fdcount;
    int               n;
    int               ret;
    int i;

    // fill timeval 
    if (timeout < 0)
    {
        to = nullptr;
    }
    else
    {
        to = &tv;
        fills_timeval(to, timeout);
    }

    // Initialize structures for select() 
    fdcount = 0;
    n = 0;
    FD_ZERO(&rd_fdset);
    FD_ZERO(&wt_fdset);
    FD_ZERO(&except_fdset);

    for (i = 0; i < (*count); i++)
    {
        // only filter out the illegal fd less than zero, 
        // if it is a no-evevent-specified-fd,
        // we  treats it as correct fd as select() will detect what event happened on it.
        if (despts[i].fd < 0) continue;
        n = MAX(n, despts[i].fd);
        if (despts[i].events & (POLLIN | POLLPRI))
        {
            FD_SET(despts[i].fd, &rd_fdset);
        }
        if (despts[i].events & POLLOUT) {
            FD_SET(despts[i].fd, &wt_fdset);
        }
        if (despts[i].events & (POLLIN | POLLOUT)) {
            FD_SET(despts[i].fd, &except_fdset);
        }
        fdcount++;
    }

    if (fdcount == 0)
    {
        ret = 0; // fds are all illegal we return zero, means no events triggered
    }
    else
    {
        //Set the revision number of all entries to the current revision.
        for (i = 0; i < *count; i++)
        {
            despts[i].revision = this->revision;
        }

        /*
        * Increment the revision number by one -> New entries made by
        * another thread during select() call will get this new revision number.
        */
        ++this->revision;

        if (unlock)
        {
            unlock(data);
        }

        ret = select(n + 1, &rd_fdset, &wt_fdset, &except_fdset, to);

        if (lock)
        {
            lock(data);
        }

        for (i = 0; i < *count; i++)
        {
            despts[i].revents = 0;
            /*If despts's revision is equal or greater than the current revision, then the despts entry
             * has been added by another thread during the poll() call.
             * If this is the case, clr all fdsets to skip the event results
             * (they will be reported again when select() is called the next timeout).*/
            if (despts[i].revision >= this->revision)
            {
                FD_CLR(despts[i].fd, &rd_fdset);
                FD_CLR(despts[i].fd, &wt_fdset);
                FD_CLR(despts[i].fd, &except_fdset);
            }
        }

        // ret >0 means some events occured, we need handle them
        if (ret > 0)
        {
            for (i = 0; i < *count; i++)
            {
                despts[i].revents = 0;
                if (despts[i].revision < revision)
                {
                    if ((despts[i].events & POLLIN) && FD_ISSET(despts[i].fd, &rd_fdset))
                    {
                        despts[i].revents |= POLLIN;
                    }
                    if ((despts[i].events & POLLOUT) && FD_ISSET(despts[i].fd, &wt_fdset))
                    {
                        despts[i].revents |= POLLOUT;
                    }
                    if ((despts[i].events & (POLLIN | POLLOUT)) && FD_ISSET(despts[i].fd, &except_fdset))
                    {
                        despts[i].revents |= POLLERR;
                    }
                }
            }
        }
    }

    return ret;
}