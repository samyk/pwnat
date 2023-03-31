/*
 * Project: udptunnel
 * File: list.c
 *
 * Copyright (C) 2009 Daniel Meekins
 * Contact: dmeekins - gmail
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
#include "list.h"

/*
 * Allocates and initializes a new list type to hold objects of obj_sz bytes,
 * and uses the cmp, copy, and free functions. If any of the function pointers
 * are NULL, they will be set to memcmp, memcpy, or free.
 */
list_t *list_create(int obj_sz,
                    int (*obj_cmp)(const void *, const void *, size_t),
                    void* (*obj_copy)(void *, const void *, size_t),
                    void (*obj_free)(void *))
{
    list_t *new;

    new = malloc(sizeof(*new));
    if(!new)
        return NULL;

    new->obj_arr = malloc(LIST_INIT_SIZE * sizeof(void *));
    if(!new->obj_arr)
    {
        free(new);
        return NULL;
    }

    new->obj_sz = obj_sz;
    new->num_objs = 0;
    new->length = LIST_INIT_SIZE;
    new->obj_cmp = obj_cmp ? obj_cmp : &memcmp;
    new->obj_copy = obj_copy ? obj_copy : &memcpy;
    new->obj_free = obj_free ? obj_free : &free;

    return new;
}

/*
 * Inserts a new object into the list in sorted order. It makes a deep copy
 * of the object and returns a pointer to that new object if obj wasn't
 * already in the list, or a pointer to the object already in the list.
 */
void *list_add(list_t *list, void *obj)
{
    void *o;
    void **new_arr;
    void *temp;
    int i;

    /* Check if obj is already in the list, and return it if so */
    o = list_get(list, obj);
    if(o)
        return o;

    o = malloc(list->obj_sz);
    if(!o)
        return NULL;

    list->obj_copy(o, obj, list->obj_sz);

    /* Resize the object array if needed, doubling the size */
    if(list->num_objs == list->length)
    {
        new_arr = realloc(list->obj_arr, list->length * 2 * sizeof(void *));
        if(!new_arr)
        {
            list->obj_free(o);
            return NULL;
        }

        list->obj_arr = new_arr;
        list->length *= 2;
    }

    /* Insert new object at end of array */
    list->obj_arr[list->num_objs++] = o;

    /* Move object up in array until list is sorted again */
    for(i = list->num_objs-1; i > 0; i--)
    {
        if(list->obj_cmp(list->obj_arr[i-1], list->obj_arr[i],
                         list->obj_sz) > 0)
        {
            temp = list->obj_arr[i-1];
            list->obj_arr[i-1] = list->obj_arr[i];
            list->obj_arr[i] = temp;
        }
        else
            break; /* since list was sorted before, just need to go this far */
    }
    
    return o;
}

/*
 * Returns a pointer to the object that matches the one passed, or NULL if
 * one wasn't found. Does a simple linear search for now.
 */
void *list_get(list_t *list, void *obj)
{
    int i;

    i = list_get_index(list, obj);
    if(i == -1)
        return NULL;

    return list->obj_arr[i];
}

/*
 * Returns a pointer to the object at position i in the list or NULL if i is
 * out of bounds.
 */
void *list_get_at(list_t *list, int i)
{
    if(i >= list->num_objs || i < 0)
        return NULL;

    return list->obj_arr[i];
}

/*
 * Gets the index of object that's equal to the passed object.
 */
int list_get_index(list_t *list, void *obj)
{
    int i;

    for(i = 0; i < list->num_objs; i++)
    {
        if(list->obj_cmp(list->obj_arr[i], obj, list->obj_sz) == 0)
            return i;
    }

    return -1;
}

/*
 * Does a deep copy of src into a newly created list, and returns a pointer to
 * the new list.
 */
list_t *list_copy(list_t *src)
{
    list_t *dst;
    int i;
    
    dst = malloc(sizeof(*dst));
    if(!dst)
        return NULL;

    memcpy(dst, src, sizeof(*src));

    /* Create the pointer array */
    dst->obj_arr = malloc(sizeof(void *) * src->length);
    if(!dst->obj_arr)
    {
        free(dst);
        return NULL;
    }

    /* Make copies of all the objects in the src array */
    for(i = 0; i < src->num_objs; i++)
    {
        dst->obj_arr[i] = malloc(dst->obj_sz);
        if(!dst->obj_arr[i])
        {
            dst->num_objs = i; /* so only will free objs up to this point */
            list_free(dst);
            return NULL;
        }

        dst->obj_copy(dst->obj_arr[i], src->obj_arr[i], dst->obj_sz);
    }

    return dst;
}

/*
 * Calls a function 'action', passing each object in the list to it, one at
 * a time.
 */
void list_action(list_t *list, void (*action)(void *))
{
    int i;

    for(i = 0; i < list->num_objs; i++)
        action(list->obj_arr[i]);
}

/*
 * Removes the object from the list that compares equally to obj.
 */
void list_delete(list_t *list, void *obj)
{
    list_delete_at(list, list_get_index(list, obj));
}

/*
 * Removes and frees an object from the list at the specified index
 */
void list_delete_at(list_t *list, int i)
{
    if(i >= list->num_objs || i < 0)
        return;

    list->obj_free(list->obj_arr[i]);

    /* Shift the rest of the object pointers one to the left */
    for(; i < list->num_objs - 1; i++)
        list->obj_arr[i] = list->obj_arr[i+1];

    list->obj_arr[i] = NULL;
    list->num_objs--;
}

/*
 * Frees each element in the list and then the list and then the list struct
 * itself.
 */
void list_free(list_t *list)
{
    int i;

    for(i = 0; i < list->num_objs; i++)
        list->obj_free(list->obj_arr[i]);

    free(list->obj_arr);
    free(list);
}
