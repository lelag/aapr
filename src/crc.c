/**********************************************************************
 *
 * Filename:    crc.c
 * 
 * Description: An implementation for the CRC calculation used in RAR files.
 *
 * Notes:       
 *
 * 
 *   This functions come from UniquE RAR File Library.
 *   Copyright (C) 2000-2002 by Christian Scheurer (www.ChristianScheurer.ch)
 *   UNIX port copyright (c) 2000-2002 by Johannes Winkelmann (jw@tks6.net)
 *
 *   This program is free software: you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation, either version 3 of the License, or
 *   (at your option) any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program.  If not, see <http://www.gnu.org/licenses/>.
 **********************************************************************/
 
#ifndef _crc_h
#define _crc_h
extern unsigned int CRCTab[256];

void InitCRC();
unsigned long CalcCRC32(unsigned long StartCRC,unsigned char *Addr,unsigned long Size);

#endif /* _crc_h */

#include "crc.h"

unsigned int CRCTab[256];

void InitCRC(void)
{
  int I, J;
  unsigned long C;
  for (I=0;I<256;I++)
  {
    for (C=I,J=0;J<8;J++)
      C=(C & 1) ? (C>>1)^0xEDB88320L : (C>>1);
    CRCTab[I]=C;
  }
}


unsigned long CalcCRC32(unsigned long StartCRC,unsigned char *Addr,unsigned long Size)
{
  unsigned int I;
  for (I=0; I<Size; I++)
    StartCRC = CRCTab[(unsigned char)StartCRC ^ Addr[I]] ^ (StartCRC >> 8);
  return(StartCRC);
}
