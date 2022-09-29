/* Copyright (C) 2008, 2009 Free Software Foundation, Inc.



  This file is part of GCC.



  GCC is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3, or (at your option)
   any later version.



  GCC is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.



  Under Section 7 of GPL version 3, you are granted additional
   permissions described in the GCC Runtime Library Exception, version
   3.1, as published by the Free Software Foundation.



  You should have received a copy of the GNU General Public License and
   a copy of the GCC Runtime Library Exception along with this program;
   see the files COPYING3 and COPYING.RUNTIME respectively.  If not, see
   <http://www.gnu.org/licenses/>.  */



#ifndef _X86INTRIN_H_INCLUDED
#define _X86INTRIN_H_INCLUDED



#ifdef _MMX_
#include <mmintrin.h>
#endif



#ifdef _SSE_
#include <xmmintrin.h>
#endif



#ifdef _SSE2_
#include <emmintrin.h>
#endif



#ifdef _SSE3_
#include <pmmintrin.h>
#endif



#ifdef _SSSE3_
#include <tmmintrin.h>
#endif



#ifdef _SSE4a_
#include <ammintrin.h>
#endif



#if defined (_SSE4_2) || defined (SSE4_1_)
#include <smmintrin.h>
#endif



#ifdef _SSE5_
#include <bmmintrin.h>
#endif



#if defined (_AES) || defined (PCLMUL_)
#include <wmmintrin.h>
#endif



   /* For including AVX instructions */
#include <immintrin.h>



#ifdef _3dNOW_
#include <mm3dnow.h>
#endif



#endif /* _X86INTRIN_H_INCLUDED */#pragma once
