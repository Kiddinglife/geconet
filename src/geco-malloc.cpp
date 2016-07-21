/*
 * Geco Gaming Company
 * All Rights Reserved.
 * Copyright (c)  2016 GECOEngine.
 *
 * GECOEngine is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * GECOEngine is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.

 * You should have received a copy of the GNU Lesser General Public License
 * along with KBEngine.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

// created on 02-June-2016 by Jackie Zhang
#include "geco-malloc.h"
static void* _DefaultMalloc(size_t size)
{
    return malloc(size);
}
static void* _DefaultRealloc(void *p, size_t size)
{
    return realloc(p, size);
}
static void _DefaultFree(void *p, size_t size)
{
    free(p);
}
// These pointers are statically and globally defined in RakMemoryOverride.cpp
// Change them to point to your own allocators if you want.
// Use the functions for a DLL, or just reassign the variable if using source
GecoMalloc geco_malloc = _DefaultMalloc;
GecoRealloc geco_realloc = _DefaultRealloc;
GecoFree geco_free = _DefaultFree;

static void* _DefaultMalloc_Ex(size_t size, const char *file, unsigned int line)
{
    return malloc(size);
}
static void* _DefaultRealloc_Ex(void *p, size_t size, const char *file,
        unsigned int line)
{
    return realloc(p, size);
}
static void _DefaultFree_Ex(void *p, size_t size, const char *file,
        unsigned int line)
{
    free(p);
}
/*function with ext for debug*/
GecoMallocExt geco_malloc_ext = _DefaultMalloc_Ex;
GecoReallocExt geco_realloc_ext = _DefaultRealloc_Ex;
GecoFreeExt geco_free_ext = _DefaultFree_Ex;
