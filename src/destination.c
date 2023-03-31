/*
 * Project: udptunnel
 * File: destination.c
 *
 * Copyright (C) 2009 Andreas Rottmann
 * Contact: a.rottmann@gmx.at
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <stdlib.h>
#include <string.h>

#include "destination.h"

destination_t *destination_create(const char *address)
{
    destination_t *dst;
    char *cp;

    dst = calloc(sizeof(destination_t), 1);
    if (!dst)
        goto fail;

    dst->data = strdup(address);
    if (!dst->data)
        goto fail;

    /* Break address into both host and port, both optional */
    cp = strchr(dst->data, ':');
    if (!cp)
    {
        dst->host = dst->data;
        dst->port = NULL;
    }
    else if (cp == dst->data)
    {
        dst->host = NULL;
        dst->port = cp + 1;
    }
    else
    {
        *cp = '\0';
        dst->host = dst->data;
        dst->port = cp + 1;
    }

    return dst;

fail:
    if (dst)
        destination_free(dst);
    return NULL;
}

destination_t *destination_copy(destination_t *dst, destination_t *src, size_t len)
{
    size_t host_len, port_len;

    host_len = src->host ? strlen(src->host) : 0;
    port_len = src->port ? strlen(src->port) : 0;

    dst->data = calloc(host_len + port_len + 2, 1);
    if (!dst->data)
        return NULL;

    if (host_len > 0)
    {
        dst->host = dst->data;
        memcpy((char *)dst->host, src->host, host_len + 1);
    }
    else
    {
        dst->host = NULL;
    }

    if (port_len > 0)
    {
        dst->port = dst->data + host_len + 1;
        memcpy((char *)dst->port, src->port, port_len + 1);
    }
    else
    {
        dst->port = NULL;
    }
    
    return dst;
}

static int strcmp_null(const char *s1, const char *s2)
{
    if (!s1)
    {
        if (s2) return -1;
        else   return 0;
    }
    else if (!s2)
    {
        if (s1) return 1;
        else   return 0;
    }
    else
        return strcmp(s1, s2);
}

int destination_cmp(destination_t *d1, destination_t *d2, size_t len)
{
    int cmp;

    cmp = strcmp_null(d1->host, d2->host);
    if (cmp)
        return cmp;
    return strcmp_null(d1->port, d2->port);
}

void destination_free(destination_t *dst)
{
    if (dst->data)
        free(dst->data);
    free(dst);
}
