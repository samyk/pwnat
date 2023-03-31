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

#ifndef DESTINATION_H
#define DESTINATION_H

#include <stddef.h>

typedef struct destination {
        const char *host;
        const char *port;
        char *data;
} destination_t;

#define p_destination_copy ((void* (*)(void *, const void *, size_t))&destination_copy)
#define p_destination_cmp ((int (*)(const void *, const void *, size_t))&destination_cmp)
#define p_destination_free ((void (*)(void *))&destination_free)

destination_t *destination_create(const char *address);
destination_t *destination_copy(destination_t *dst, destination_t *src, size_t len);
int destination_cmp(destination_t *c1, destination_t *c2, size_t len);
void destination_free(destination_t *c);

#endif
