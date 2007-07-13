/**********************************************************************
 *
 * Filename:    crc.h
 * 
 * Description: A header file for the CRC calculation used in RAR files.
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