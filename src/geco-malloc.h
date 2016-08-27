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

// created on 04-June-2016 by Jackie Zhang
#ifndef __INCLUDE_GECO_MALLOC_H
#define __INCLUDE_GECO_MALLOC_H

#if defined(__FreeBSD__)
#include <stdlib.h>
#elif defined ( __APPLE__ ) || defined ( __APPLE_CC__ )
#include <malloc/malloc.h>
#include <alloca.h>
#elif defined(_WIN32)
#include <malloc.h>
#else
#include <malloc.h>
#include <alloca.h> // Alloca needed on Ubuntu apparently
#endif
#include <new>

// These pointers are statically and globally defined in RakMemoryOverride.cpp
// Change them to point to your own allocators if you want.
// Use the functions for a DLL, or just reassign the variable if using source
typedef void*(*GecoMalloc)(size_t size);
typedef void*(*GecoRealloc)(void *p, size_t size);
typedef void (*GecoFree)(void *p, size_t size);
extern GecoMalloc geco_malloc;
extern GecoRealloc geco_realloc;
extern GecoFree geco_free;

typedef void * (*GecoMallocExt)(size_t size, const char *file,
		unsigned int line);
typedef void * (*GecoReallocExt)(void *p, size_t size, const char *file,
		unsigned int line);
typedef void (*GecoFreeExt)(void *p, const char *file, unsigned int line);
extern GecoMallocExt geco_malloc_ext;
extern GecoReallocExt geco_realloc_ext;
extern GecoFreeExt geco_free_ext;

/// new functions with different number of ctor params, up to 4
template<class Type>
Type* geco_new(const char *file, unsigned int line)
{
	char *buffer = (char *) (geco_malloc_ext)(sizeof(Type), file, line);
	Type *t = new (buffer) Type;
	return t;
}
template<class Type, class P1>
Type* geco_new(const char *file, unsigned int line, const P1 &p1)
{
	char *buffer = (char *) (geco_malloc_ext)(sizeof(Type), file, line);
	Type *t = new (buffer) Type(p1);
	return t;
}
template<class Type, class P1, class P2>
Type* geco_new(const char *file, unsigned int line, const P1 &p1, const P2 &p2)
{
	char *buffer = (char *) (geco_malloc_ext)(sizeof(Type), file, line);
	Type *t = new (buffer) Type(p1, p2);
	return t;
}
template<class Type, class P1, class P2, class P3>
Type* geco_new(const char *file, unsigned int line, const P1 &p1, const P2 &p2,
		const P3 &p3)
{
	char *buffer = (char *) (geco_malloc_ext)(sizeof(Type), file, line);
	Type *t = new (buffer) Type(p1, p2, p3);
	return t;
}
template<class Type, class P1, class P2, class P3, class P4>
Type* geco_new(const char *file, unsigned int line, const P1 &p1, const P2 &p2,
		const P3 &p3, const P4 &p4)
{
	char *buffer = (char *) (geco_malloc_ext)(sizeof(Type), file, line);
	Type *t = new (buffer) Type(p1, p2, p3, p4);
	return t;
}

template<class Type>
Type* geco_new_array(const int count, const char *file, unsigned int line)
{
	if (count == 0)
		return 0;

	//		Type *t;
	char *buffer = (char *) (geco_malloc_ext)(
			sizeof(int) + sizeof(Type) * count, file, line);
	((int*) buffer)[0] = count;
	for (int i = 0; i < count; i++)
	{
		new (buffer + sizeof(int) + i * sizeof(Type)) Type;
	}
	return (Type *) (buffer + sizeof(int));
}

template<class Type>
void geco_delete(Type *buff, const char *file, unsigned int line)
{
	if (buff == 0)
		return;
	buff->~Type();
	geco_free_ext(buff, file, line);
}

template<class Type>
void geco_delete_array(Type *buff, const char *file, unsigned int line)
{
	if (buff == 0)
		return;
	char* ptr = (char*) buff - sizeof(int);
	int count = *(int*) ptr;
	Type* tmp = (Type*) (ptr + sizeof(int));
	for (int i = 0; i < count; i++)
	{
		(tmp + i)->~Type();
	}
	(geco_free_ext)(ptr, file, line);
}

#endif
