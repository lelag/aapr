/* aapr.h
 *   AAPR - AES Archive Password Recovery tool.
 *   Copyright (C) 2007 Guillaume Michalag.
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
 *
 *
 *	 Check the aapr.c file to find detailed comments.
 */
 
#ifndef AAPR_H
#define AAPR_H
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
#include <time.h>
#include <math.h>

#ifdef __WIN32__
#define __LITTLE_ENDIAN__
#endif

#include "aes.h"
#include "sha1.h"


void display_usage();

void get_crk_file(char * crk_file, const char * archive_file);

int bruteforce(char * password, int max_pass, FILE* dic_file,
				FILE* to_crack_file, uint64_t low_index, uint64_t high_index, 
				int benchmark);

int dictionary(char * password, FILE* dic_file,
				FILE* to_crack_file, uint64_t low_index, uint64_t high_index, 
				int benchmark);

int rar_bruteforce(char * password,int max_pass, FILE * dic_file, FILE * to_crack_file, 
					uint64_t low_index, uint64_t high_index, int benchmark);

int rar_dictionary(char * password, FILE * dic_file, FILE * to_crack_file, 
					uint64_t low_index, uint64_t high_index, int benchmark);

int parse_rar(FILE * to_crack_file, char *salt, char *encrypted_block);

int read_rar_block_header(FILE * to_crack_file, uint16_t * head_crc, char * head_type, uint16_t * head_flags, uint16_t * head_size, uint32_t *add_size);

int read_rar_marker_block(FILE * to_crack_file);

uint16_t read_rar_head_crc(char * block);

uint16_t read_rar_head_flags(char * block);

uint16_t read_rar_head_size(char * block);

void ccombination(char charset[], int charset_size, char password[], uint64_t index, int password_length);

void scombination(char *charset[], int charset_size, char password[], uint64_t index, int password_length);

void get_char_password(char charset[], int charset_size, char password[], uint64_t index);

void get_string_password(char **charset, int charset_size, char password[], uint64_t index);

uint64_t get_combi_number(int charset_size, int max_password_size);

int rar_test_password(char * encrypted_block,char * password,char * salt, AVAES *aescon);

void utf2wide(const unsigned char *src,wchar_t *dst,int size);

unsigned char * wide2raw(const wchar_t *src, unsigned char *dst,int size);

int strlenw(const wchar_t *string);

void prepare_key(unsigned char* password, unsigned char* salt, unsigned char *aeskey, unsigned char *aesinit);

void save_progress(char method, uint64_t low_index, uint64_t high_index, int max_pass, int benchmark);

void save_result(char * password);

void utility_test();

#endif AAPR_H