/* aapr.c
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
 */

#include "aapr.h"

/* 
 * Display an help screen to stdout when no arguments are given.
 * 
 * Arguments : none.
 *
 * Return Value : none.
 */
void display_usage()
{
	fprintf(stdout, "AES Archive Password Recovery Tool\n");
	fprintf(stdout, "Version 0.01 Copyright (c) 2007 Guillaume Michalag");
	fprintf(stdout, "\n\n Only RARv3+ with encrypted file names are supported.");
	fprintf(stdout, "\n\n Usage : aapr <options> <file_to_crack>\n\nOptions:\n");
	fprintf(stdout, "-m[b,d] [file]: choose the attack method\n\t[b] = bruteforce\n\t[d] = dictionary\n");
	fprintf(stdout, "\n\t[file] is the file containing the dictionary for a dictionary attack");
	fprintf(stdout, "\n\t[file] is the file containing the character set for a bruteforce attack");
	fprintf(stdout, "\n\n-p [#] : max length of passwords.");
	fprintf(stdout, "\n\t Only used with bruteforce. Note that bruteforce can perform hybrid dictionary attack");
	fprintf(stdout, "\n\t by having each dictionary entry in the character set file.");
	fprintf(stdout, "\n\n-i [# #] : starting and ending index - useful to split a job between several computers");
	fprintf(stdout, "\n\n-b [#] : benchmark.. [#] is the number of passwords to test.");
	fprintf(stdout, "\n\n-c : continue a previously started job after the program was stopped.");
	fprintf(stdout, "\n\n-t [#]: Number of tries between progress saving. Default is 1500.");
	fprintf(stdout, "\n\nExample :");
	fprintf(stdout, "\n\t aapr -mb dic.txt -p 2 -i 50000 100000 archive.part01.rar\n");
	fprintf(stdout, "\n\t aapr -c archive.rar\n");
}

/*
 * Strips the extensions of a filename and add the extension '.crk'
 * 
 * Arguments :
 *		crk_file : will contains the result.
 *		archive_file : the name of the archive with the extension.
 *
 * Return Value : none.
 */
void get_crk_file(char * crk_file,const char * archive_file)
{
	int i = 0;
	int last_dot;

	while(archive_file[i] != '\0') {
		if(archive_file[i] == '.')
			last_dot = i;
		i++;
	}

	for(i=0; i < last_dot; i++)
			crk_file[i] = archive_file[i];
	crk_file[i++]='.';
	crk_file[i++]='c';
	crk_file[i++]='r';
	crk_file[i++]='k';
	crk_file[i]='\0';
}

/*
 * The function checks if the file is recognized and then launch a bruteforce attack.
 *
 * Arguments : 
 *		char * password : will contains the password when it is found.
 *		int max_pass : the maximum size of password to try.
 *		FILE * dic_file : a stream to the file containing the character set.
 *		FILE * to_crack_file : a stream to the archive file we want to decrypt.
 *		low_index : the starting point.
 *		high_index : the end point.
 *		benchmark : if > 0 then only benchmark tests will be effectued.
 *
 * Return Value :
 *		0 : password not found.
 *		1 : password found. Result in char * password.
 */
int bruteforce(	char * password, int max_pass, FILE * dic_file,
				FILE * to_crack_file, uint64_t low_index, uint64_t high_index, 
				int benchmark)
{
	/*Read the 2 first byte of the file to crack to identify it.*/
	char magic[3]="  ";
	char rar_marker_block[7]={0x52, 0x61,0x72, 0x21, 0x1a, 0x07, 0x00};
	char * rar_marker_ptr = rar_marker_block;
	int result;
	magic[0] = fgetc(to_crack_file);
	magic[1] = fgetc(to_crack_file);
	if((magic[0]==(*rar_marker_ptr))&&(magic[1]==(*++rar_marker_ptr))) {	/*Probably a RAR File*/
	
		/*Let's read the rest to check it's really a RAR file Marker Block*/
		while((*++rar_marker_ptr) != 0x00) {
			if(*rar_marker_ptr != fgetc(to_crack_file)) {					/*Actually not a RAR*/
				fprintf(stderr,"Unknown file format.\n");
				return 2;
			}
		}
		
		/*Launch the bruteforce function for RAR files*/
		rewind(to_crack_file);
		result = rar_bruteforce(password, max_pass, dic_file, to_crack_file, low_index, high_index, benchmark);
	} else {
		if((magic[0]=='P')&&(magic[1]=='K')) {								/*Probably a Zip file*/
			fprintf(stderr,"Zip file cracking is not yet implemented.\n");
			return 2;	
		} else {
			fprintf(stderr,"Unknown file format.\n");
			return 2;
		}
	}
	return result;
}
/*
 * The function performs a bruteforce attack an a RAR file.
 *
 * Arguments : 
 *		char * password : will contains the password when it is found.
 *		int max_pass : the maximum size of password to try.
 *		FILE * dic_file : a stream to the file containing the character set.
 *		FILE * to_crack_file : a stream to the archive file we want to decrypt.
 *		low_index : the starting point.
 *		high_index : the end point.
 *		benchmark : if > 0 then only benchmark tests will be effectued.
 *
 * Return Value :
 *		0 : password not found.
 *		1 : password found. Result in char * password.
 */
int rar_bruteforce(	char * password,int max_pass, FILE * dic_file, FILE * to_crack_file, 
					uint64_t low_index, uint64_t high_index, int benchmark)
{
	extern int saving_interval;
	int number_of_line_in_dic=0;
	char charset_c[256] = {'\0'};
	char salt[9];
	char encrypted_block[1025];
	char **charset_s;
	int result;
	int bench_high_index;

	/*Initialize the CRC Tab for faster lookup*/
	InitCRC();
						
	/*First Let's get all the character set in memory. If the character set file has only one line, each characters in this 
	line will represent one character of the set. However, if there is more than one line, each line represent a unit of the
	character set. A character in this case can be a uint64_t string. It is useful if you know that a password is a combination
	of known elements but don't know the order. */
	int c,i;
	time_t start_time, end_time;
	uint64_t num_combination;
	
	i=-1;
	while ((c = fgetc(dic_file)) != EOF) {
		if(c == '\r')							/*ignore CR on win32*/
			continue;
		if(c=='\n'&&c!=i)
			number_of_line_in_dic++;
		i=c;
	}
	if(i != '\n') 							/*case where the txt file does not end with a linefeed*/
		number_of_line_in_dic++;
	rewind(dic_file);
	if(number_of_line_in_dic==1) {				/*The char set is composed of single ascii characters*/
		i=0;
		c=0;
		while((c = fgetc(dic_file)) != EOF) {
			if((c != '\n') && (c != '\r') && (!strchr(charset_c,c))) {
				charset_c[i++]=c;
				charset_c[i+1]='\0';
			}
		}
	} else { /*The character set is composed of chains of char*/
		i = 0;
		charset_s = malloc(sizeof(char*)*number_of_line_in_dic);
		while(fgets(charset_c,256,dic_file)!=NULL) {
			if((strcmp(charset_c, "\n")!=0) && (strcmp(charset_c, "\r\n")!=0)) {
				*(charset_s+i) = calloc(1, strlen(charset_c)+1);
				if(charset_c[strlen(charset_c)-2]=='\r')				/*if this is a windows type txt file.*/
					strncpy(*(charset_s+i),charset_c,strlen(charset_c)-2);
				else
					if(charset_c[strlen(charset_c)-1]=='\n')
						strncpy(*(charset_s+i),charset_c,strlen(charset_c)-1);
					else
						strncpy(*(charset_s+i),charset_c,strlen(charset_c));
				i++;
			}
		}
	}
	
	/*Process the RAR file - we need to get the salt and an entire encrypted block*/
	parse_rar(to_crack_file, salt, encrypted_block);

	/*If it's a test we save the start time and limit the number of tries*/
	if(benchmark > 0) {
		time(&start_time);
		char timestring[200];
		strftime(timestring,199,"%H:%M:%S",localtime(&start_time));
		printf("\nBenchmark started at %s\n", timestring);
		bench_high_index = high_index;
		if(benchmark < (high_index - low_index))
			high_index = low_index + benchmark - 1;
	}
	
	if(number_of_line_in_dic==1) { /*The char set is composed of single ascii characters*/
		num_combination = get_combi_number(strlen(charset_c),max_pass);
		if(num_combination < low_index) {
			fprintf(stderr, "The index value is higher than the total number of passwords (%llu)\n", num_combination);
			exit(1);
		}
		if(high_index > num_combination || high_index == 0)
			high_index = num_combination;
		uint64_t index = 0;
		AVAES *aescon = malloc(sizeof(AVAES));							/*Init of the AES context*/
		for(index = low_index; index <= high_index; index++) {
			char test_password[256];
			
			/*Save the progress every saving_interval test.*/
			if((index % saving_interval)==0)
				if(benchmark > 0)
					save_progress('b',index,bench_high_index,max_pass,benchmark);
				else
					save_progress('b',index,high_index,max_pass,0);
					
			/*Get the next password and test it*/
			get_char_password(charset_c,strlen(charset_c),test_password,index);
			if((result = rar_test_password(encrypted_block, test_password, salt, aescon)) == 1) {
				strcpy(password,test_password);
				return 1;
			}
		}
	} else { /*The char set is composed of strings*/
		num_combination = get_combi_number(number_of_line_in_dic,max_pass);
		if(num_combination < low_index) {
			fprintf(stderr, "The index value is higher than the total number of passwords (%llu)\n", num_combination);
			exit(1);
		}
		if(high_index > num_combination || high_index == 0)
			high_index = num_combination;
		uint64_t index = 0;
		AVAES *aescon = malloc(sizeof(AVAES));					/*Init of the AES context*/
		for(index = low_index; index <= high_index; index++) {
			char test_password[256];
			
			/*Save the progress every saving_interval test.*/
			if((index % saving_interval)==0)
				if(benchmark > 0)
					save_progress('b',index, bench_high_index,max_pass,benchmark);
				else
					save_progress('b',index,high_index,max_pass,0);
					
			/*Get the next password and test it*/
			get_string_password(charset_s,number_of_line_in_dic,test_password,index);
			if((result = rar_test_password(encrypted_block, test_password, salt, aescon)) == 1) {
				strcpy(password,test_password);
				return 1;
			}
		}
	}
	/*If it's a test, we display the result*/
	if(benchmark > 0) {
		time(&end_time);
		time_t timer = end_time - start_time;
		int number_of_pass = high_index - low_index + 1;
		float pass_per_sec = ((float)number_of_pass/((int)timer));
		float average_days = (((float)num_combination/pass_per_sec)/3600)/24;
		char timestring[200];
		strftime(timestring,199,"%H:%M:%S",localtime(&end_time));
		printf("Benchmark ended at %s\n", timestring);
		printf("%d passwords tested in %d seconds\n",number_of_pass, (int)timer);
		printf("Average performance : %f passwords/sec\n\n", pass_per_sec);
		printf("With this settings there are %llu combinations of passwords\n", num_combination);
		printf("that will all be tried in about %f days\n", average_days);
	}
	return 0;
}

/*
 * This function parse a RAR file : it checks it is a suitably encrypted RAR file and return
 * an encrypted block and corresponding salt value.
 * 
 * Arguments :
 *		FILE * to_crack_file : a stream to the encrypted archive.
 *		char *salt : will contains the salt value.
 *		char *encrypted_block : will contains the first 1023 char of the encrypted block.
 *
 * Return Value : normally 0;
 */
int parse_rar(FILE * to_crack_file, char *salt, char *encrypted_block)
{
	uint16_t * head_crc = malloc(sizeof(uint16_t));
	uint16_t * head_flags = malloc(sizeof(uint16_t));
	uint16_t * head_size = malloc(sizeof(uint16_t));
	uint32_t * add_size = malloc(sizeof(uint32_t));
	char * head_type = malloc(sizeof(char));
	int encrypted_blocks=0;
	int i;

	read_rar_marker_block(to_crack_file);
	read_rar_block_header(to_crack_file, head_crc, head_type, head_flags, head_size, add_size);
	fseek(to_crack_file, 6, SEEK_CUR);	/*Skip 6 reserved bytes*/
	if(*head_flags&0x080) {				/*The blocks are encrypted*/
		encrypted_blocks=1;
		for(i=0;i<8;i++)
			salt[i] = fgetc(to_crack_file);
		salt[8]=0x00;
		for(i=0;i<1023;i++)
			encrypted_block[i] = fgetc(to_crack_file);
		encrypted_block[1023]=0x00;
		return 0;
	} else {							/*Only the file blocks are encrypted*/ 
		fprintf(stderr, "Error : This RAR file's header blocks are not encrypted and is thus not yet supported by this utility.");
		exit(1);
	}
	return(1);
}

/*
 * This function read the marker block of a Rar file and interrupt the execution if 
 * the file appears not to be a RAR file.
 * 
 * Arguments : 
 *		FILE * to_crack_file : a stream to the RAR archive.
 *
 * Return Value : 0 if OK.
 */
int read_rar_marker_block(FILE * to_crack_file)
{
	char rar_marker_block[7]={0x52, 0x61,0x72, 0x21, 0x1a, 0x07, 0x00};
	int i;
	for(i=0; i<7; i++) {
		if(rar_marker_block[i] != fgetc(to_crack_file)) { /*Actually not a RAR*/
					fprintf(stderr,"Not a RAR file !\n");
					exit(2);
		}
	}
	return 0;
} 

/*
 * This function read the headers of a block from a RAR files and put the values of the
 * general fields in variables. The function differs if the processor is big endian. 
 * See the RAR format description at http://www.win-rar.com/index.php?id=24&kb=1&kb_article_id=162
 * 
 * Arguments : 
 *		FILE * to_crack_file : a stream to the RAR archive.
 *
 *	The following arguments are pointers to return values :
 *		uint16_t * head_crc : the CRC of the Header.
 *		char * head_type : an int from 73 to 7a representing the type of header.
 *		uint16_t * head_flags : the header flags.
 *		uint16_t * head_size : the size of the header.
 *		uint32_t *add_size : extra header size (not always present).
 *
 *  Return Value : the size of the header.
 */
int read_rar_block_header(	FILE * to_crack_file, uint16_t * head_crc, char * head_type, 
							uint16_t * head_flags, uint16_t * head_size, uint32_t *add_size)
{
	char c;
#ifdef __LITTLE_ENDIAN__
		c = fgetc(to_crack_file);
		*((char*)(head_crc)) = c;
		c = fgetc(to_crack_file);
		*((char*)(head_crc)+1) = c;
		c = fgetc(to_crack_file);
		*(head_type) = c;
		c = fgetc(to_crack_file);
		*((char*)(head_flags)+0) = c;
		c = fgetc(to_crack_file);
		*((char*)(head_flags)+1) = c;
		c = fgetc(to_crack_file);
		*((char*)(head_size)+0) = c;
		c = fgetc(to_crack_file);
		*((char*)(head_size)+1) = c;
		if(*head_flags&0x8000) {
			c = fgetc(to_crack_file);
			*((char*)(add_size)+0) = c;
			c = fgetc(to_crack_file);
			*((char*)(add_size)+1) = c;
			c = fgetc(to_crack_file);
			*((char*)(add_size)+2) = c;
			c = fgetc(to_crack_file);
			*((char*)(add_size)+3) = c;
		} else {
			*add_size = 0;
		}
#else
		c = fgetc(to_crack_file);
		*((char*)(head_crc)+1) = c;
		c = fgetc(to_crack_file);
		*((char*)(head_crc)+0) = c;
		c = fgetc(to_crack_file);
		*(head_type) = c;
		c = fgetc(to_crack_file);
		*((char*)(head_flags)+1) = c;
		c = fgetc(to_crack_file);
		*((char*)(head_flags)+0) = c;
		c = fgetc(to_crack_file);
		*((char*)(head_size)+1) = c;
		c = fgetc(to_crack_file);
		*((char*)(head_size)+0) = c;
		if(*head_flags&0x8000) {
			c = fgetc(to_crack_file);
			*((char*)(add_size)+3) = c;
			c = fgetc(to_crack_file);
			*((char*)(add_size)+2) = c;
			c = fgetc(to_crack_file);
			*((char*)(add_size)+1) = c;
			c = fgetc(to_crack_file);
			*((char*)(add_size)+0) = c;
		} else {
			*add_size = 0;
		}
#endif
	return(*head_size + *add_size);
}

/*
 * This function read the CRC value of a RAR block.
 * 
 * Arguments : 
 *		char * block : pointer to the block.
 *
 *  Return Value : the CRC value.
 */
uint16_t read_rar_head_crc(char * block)
{
	char c;
	uint16_t head_crc;
	uint16_t * head_ptr = &head_crc;
#ifdef __LITTLE_ENDIAN__
		c = block[0];
		*((char*)(head_ptr)) = c;
		c = c = block[1];
		*((char*)(head_ptr)+1) = c;
#else
		c = c = block[0];
		*((char*)(head_ptr)+1) = c;
		c = c = block[1];
		*((char*)(head_ptr)+0) = c;
#endif
	return(head_crc);
}

/*
 * This function read the flags value of a RAR block.
 * 
 * Arguments : 
 *		char * block : pointer to the block.
 *
 *  Return Value : the flags value.
 */
uint16_t read_rar_head_flags(char * block)
{ 
	char c;
	uint16_t head_flags;
	uint16_t * head_ptr = &head_flags;
#ifdef __LITTLE_ENDIAN__
		c = block[3];
		*((char*)(head_ptr)) = c;
		c = c = block[4];
		*((char*)(head_ptr)+1) = c;
#else
		c = c = block[3];
		*((char*)(head_ptr)+1) = c;
		c = c = block[4];
		*((char*)(head_ptr)+0) = c;
#endif
	return(head_flags);
}

/*
 * This function read the header size of a RAR block.
 * 
 * Arguments : 
 *		char * block : pointer to the block.
 *
 *  Return Value : the header size value.
 */
uint16_t read_rar_head_size(char * block)
{ 
	char c;
	uint16_t head_size;
	uint16_t * head_ptr = &head_size;
#ifdef __LITTLE_ENDIAN__
		c = block[5];
		*((char*)(head_ptr)) = c;
		c = c = block[6];
		*((char*)(head_ptr)+1) = c;
#else
		c = c = block[5];
		*((char*)(head_ptr)+1) = c;
		c = c = block[6];
		*((char*)(head_ptr)+0) = c;
#endif
	return(head_size);
}

/*
 * This function read the file name sizeof a RAR block. The block must be of
 * type 74.
 * 
 * Arguments : 
 *		char * block : pointer to the block.
 *
 *  Return Value : the filename size.
 */
uint16_t read_rar_filename_size(char * block)
{ 
	char c;
	uint16_t head_size;
	uint16_t * head_ptr = &head_size;
#ifdef __LITTLE_ENDIAN__
		c = block[26];
		*((char*)(head_ptr)) = c;
		c = c = block[27];
		*((char*)(head_ptr)+1) = c;
#else
		c = c = block[26];
		*((char*)(head_ptr)+1) = c;
		c = c = block[27];
		*((char*)(head_ptr)+0) = c;
#endif
	return(head_size);
}

/*
 * This function read the file name of a RAR block. The block must be of
 * type 74.
 * 
 * Arguments : 
 *		char * block : pointer to the block.
 *		int filename_size : the length of the filename. See read_rar_filename_size(char * block).
 *		int high_pack : if set to 1, the block has an extended size field that must be skipped.
 *		char * filename : pointer to a variable that will contains the filename.
 *
 *  Return Value : none.
 */
void read_rar_filename(char * filename, const char * block,int filename_size, int high_pack)
{
	int i,start = 32;		/*Stating index for the file namestring*/
	if(high_pack == 1)
		start += 8;			/*Skip the Extened size field*/ 
	for (i = start; i < filename_size + start; i++)
		filename[i - start] = block[i];
}

/*
 * This function generate a specific combination of formed with a specific charset at a specific index.
 * and with a given length. (Permutation of specific length with repetition).
 * 
 * Arguments : 
 *		char charset[] : a string containing the possible characters to form combinations form.
 *		int charset_size : the number of characters in charset.
 *		char password[] : a pointer to the variable that will receive the generated value.
*		uint64_t index : the index of the wanted permutation.
 *		int password_length : the length of the permutation.
 *
 *  Return Value : none.
 */
void ccombination(char charset[], int charset_size, char password[], uint64_t index, int password_length)
{
	uint64_t z,q,a,car;
	uint64_t compt = 0;
	while(password_length - 1 >= 0) {
		a=pow(charset_size,(password_length - 1));
		z = index / a;
		if(index % a != 0)
			car=z+1;
		else {
			car=z;
			z--;
		}
		password[compt]=charset[car-1];
		q = z * a;
		index -= q;
		compt++;
		password_length--;
	}
	password[compt]='\0';
}

/*
 * This function generate a specific combination of formed with a specific charset at a specific index.
 * and with a given length. (Permutation of specific length with repetition). This function will combine strings
 * instead of single characters.
 * 
 * Arguments : 
 *		char **charset : a pointer to an array of pointer containing the string to combine.
 *		int charset_size : the number of characters in charset.
 *		char password[] : a pointer to the variable that will receive the generated value.
 *		uint64_t index : the index of the wanted permutation.
 *		int password_length : the length of the permutation.
 *
 *  Return Value : none.
 */
void scombination(char **charset, int charset_size, char password[], uint64_t index, int password_length)
{
	uint64_t z,q,a,car;
	int u = 0;
	int uu = 0;
	uint64_t compt = 0;
	while(password_length - 1 >= 0) {
		a=pow(charset_size,(password_length - 1));
		z = index / a;
		if(index % a != 0)
			car=z+1;
		else {
			car=z;
			z--;
		}
		uu=strlen(charset[car-1]);
		if((u+uu) > 256)			/*Check we don't go over the array length*/
			break;
		memcpy(password+u,charset[car-1],uu);
		u+=uu;
		q = z * a;
		index -= q;
		compt++;
		password_length--;
	}
	password[u]='\0';
}

/*
 * This function return the password combination of formed with a specific charset of char at a given index.
 * This function is a wrapper for ccombination so that it works password of with any length.
 * 
 * Arguments : 
 *		char charset[] : a string containing the possible characters to form combinations form.
 *		int charset_size : the number of characters in charset.
 *		char password[] : a pointer to the variable that will receive the generated value.
 *		uint64_t index : the index of the wanted permutation.
 *
 *  Return Value : none.
 */
void get_char_password(char charset[], int charset_size, char password[], uint64_t index)
{
	uint64_t length, previous;
	uint64_t indexlist = 0;
	for (length = 1; length < 128; length++) {
		previous = indexlist;
		indexlist += pow(charset_size, length);
		if(indexlist >= index) {
			index -= previous;
			ccombination(charset, charset_size, password, index, length);
			break;
		}
	}	
}

/*
 * This function return the password combination of formed with a specific charset of string at a given index.
 * This function is a wrapper for scombination so that it works password of with any length.
 * 
 * Arguments : 
 *		char **charset : a pointer to an array of pointer containing the string to combine.
 *		int charset_size : the number of characters in charset.
 *		char password[] : a pointer to the variable that will receive the generated value.
 *		uint64_t index : the index of the wanted permutation.
 *
 *  Return Value : none.
 */
void get_string_password(char **charset, int charset_size, char password[], uint64_t index)
{
	uint64_t length, previous;
	uint64_t indexlist = 0;
	for (length = 1; length < 128; length++) {
		previous = indexlist;
		indexlist += pow(charset_size, length);
		if(indexlist >= index) {
			index -= previous;
			scombination(charset, charset_size, password, index, length);
			break;
		}
	}	
}

/*
 * This function calculates how many combination you can form with a given charset and a a maximum
 * password size.
 * 
 * Arguments : 
 *		int charset_size : the number of characters in charset.
 *		int max_password_size : the maximum length of the password.
 *
 *  Return Value : the number of combinations possible.
 */
uint64_t get_combi_number(int charset_size, int max_password_size)
{
	uint64_t a,b;
	b=0;
	for (a=1; a <= max_password_size; a++) {
		b += pow(charset_size, a);
	}
	return b;
}

/*
 * Given a specific password, this function will try to use it to decrypt a block of the RAR
 * and check if the decryption was successfull. 
 * 
 * Arguments : 
 *		char * encrypted_block : a pointer to the encrypted_block.
 *		char * password : a pointer to the password to try.
 *		char * salt : a pointer to the salt value to use.
 *		AVAES *aescon : a pointer to the AES context to use.
 *
 *  Return Value : 0 if the password is bad. 1 if it is good.
 */
int rar_test_password(char * encrypted_block,char * password,char * salt, AVAES *aescon)
{
	char buffer[16];
	char d_buffer[1024];
	unsigned char aeskey[16];
	unsigned char aesinitvector[16];
	int buffer_size = 0;
	int i;
	prepare_key((unsigned char *)password, (unsigned char *)salt, aeskey, aesinitvector);
	av_aes_init(aescon, aeskey, 128, 1);
	while(buffer_size < 1024) {
		for(i = 0; i < 16; i++) {
			buffer[i]=encrypted_block[buffer_size++];
		}
		
		/*Decrypt the buffer*/
		av_aes_crypt(aescon, (unsigned char *)d_buffer+(buffer_size - 16), (unsigned char *)buffer, 1, aesinitvector, 1);
				
		/*If the 3rd byte in the sequence is not 74 or 7A, it's a bad password*/
		if(!((d_buffer[2] == 0x74) || (d_buffer[2]==0x7a)))
			return 0;
		if(d_buffer[2]==0x7a) {
			uint16_t head_size = read_rar_head_size(d_buffer);		/*Lire Head_Size*/
			if(head_size <= buffer_size) {							/*Is there enough to calculate CRC*/
				uint16_t head_crc = read_rar_head_crc(d_buffer);	/*Lire Head CRC*/
				unsigned int blockCRC=CalcCRC32(0xffffffff,d_buffer+2,head_size-2); /*Calculate CRC of whole block*/
				unsigned short HeaderCRC = (~(blockCRC)&0xffff);					/*Do some weird thing to get Rar CRC*/
				if(HeaderCRC == head_crc) {							/*Check if rigth password was found*/
					return 1;				/* :-) */
				} else {
					return 0;				/* :-( */
				}
			}
		}
		if(d_buffer[2]==0x74) {
			uint16_t head_size = read_rar_head_size(d_buffer);		/*Lire Head_Size*/
			
			/*Check if the head_flags makes any senses on the first pass*/
			if(buffer_size == 16) {
				uint16_t head_flags = read_rar_head_flags(d_buffer);
				if(!head_flags&0x04)				/*The file is not encrypted*/
					return 0;
				if(head_flags&0x08)					/*rar 3 does not set this flag*/
					return 0;
				if(!head_flags&0x400)				/*salt is not present*/
					return 0;
				if(head_flags&0x800)				/*old file version*/
					return 0;
				if(!head_flags&0x8000)				/*this flag is always set*/
					return 0;
			/*Here we need to add a check on PACK_SIZE and UNPACK_SIZE to optmize speed a bit more*/
			}
			
			if(head_size <= buffer_size) { /*Is there enough to calculate CRC*/
				uint16_t head_crc = read_rar_head_crc(d_buffer);	/*Lire Head CRC*/
				/*Calculate CRC*/
				unsigned int blockCRC=CalcCRC32(0xffffffff,d_buffer+2,head_size-2);	
				unsigned short HeaderCRC = (~(blockCRC)&0xffff);
				if(HeaderCRC == head_crc) { /*Check if password was found*/
					return 1;				/* :-) */
				} else {
					return 0;				/* :-( */
				}
			}
		}	
	}
	return 0;
}

/*
 * This function transform a utf string to a wide char string. 
 * 
 * Arguments : 
 *		const unsigned char *src : a pointer to the source string.
 *		wchar_t *dst : a pointer to the destination string.
 *		int size : the size of the string.
 *
 *  Return Value : none.
 */
void utf2wide(const unsigned char *src,wchar_t *dst,int size)
{
	size--;
	while (*src!=0) {
		unsigned int c, d;
		c=(unsigned char)*(src++);
		if (c<0x80)
			d=c;
		else
			if ((c>>5)==6) {
				if ((*src&0xc0)!=0x80)
					break;
				d=((c&0x1f)<<6)|(*src&0x3f);
				src++;
			} else
				if ((c>>4)==14) {
					if ((src[0]&0xc0)!=0x80 || (src[1]&0xc0)!=0x80)
						break;
					d=((c&0xf)<<12)|((src[0]&0x3f)<<6)|(src[1]&0x3f);
					src+=2;
				} else
					if ((c>>3)==30) {
						if ((src[0]&0xc0)!=0x80 || (src[1]&0xc0)!=0x80 || (src[2]&0xc0)!=0x80)
							break;
						d=((c&7)<<18)|((src[0]&0x3f)<<12)|((src[1]&0x3f)<<6)|(src[2]&0x3f);
					src+=3;
					} else
						break;
					if (--size<0)
						break;
					if (d>0xffff) {
						if (--size<0 || d>0x10ffff)
							break;
						*(dst++)=((d-0x10000)>>10)+0xd800;
						*(dst++)=(d&0x3ff)+0xdc00;
					} else
						*(dst++)=d;
	}
	*dst=0;
}

/*
 * This function transform a wide char string. 
 * 
 * Arguments : 
 *		const unsigned char *src : a pointer to the source string.
 *		wchar_t *dst : a pointer to the destination string.
 *		int size : the size of the string.
 *
 *  Return Value : a pointer to the destination string.
 */
unsigned char * wide2raw(const wchar_t *src, unsigned char *dst,int size)
{
	int I;
	for (I=0;I<size;I++,src++) {
		dst[I*2]=(unsigned char)*src;
		dst[I*2+1]=(unsigned char)(*src>>8);
		if (*src==0)
		  break;
	}
	return(dst);
}

/*
 * This function calculate the length of a wchar_t string.
 * 
 * Arguments : 
 *		const wchar_t *string : the string to calculate the length of.
 *
 *  Return Value : the length.
 */
int strlenw(const wchar_t *string)
{
	int length=0;
	while (*(string++)!=0)
	length++;
	return(length);
}

/*
 * This function calculate the AES key and initialization vector for the AES decyrption.
 * 
 * Arguments : 
 *		unsigned char* password : a pointer to the password to use.
 *		unsigned char* salt : a pointer to the salt value to use.
 *		unsigned char *aeskey : a pointer to the variable that will receive the key.
 *		unsigned char *aesinit : a pointer to the variable that will receive the init vector.
 *
 *  Return Value : none.
 */
void prepare_key(unsigned char* password, unsigned char* salt, unsigned char *aeskey, unsigned char *aesinit)
{
	int i;
	const int hash_rounds=0x40000;
	wchar_t wide_password[128];
    utf2wide(password,wide_password,128-1);
	wide_password[128-1]=0;
	unsigned char raw_password[2*128+8];
	wide2raw(wide_password,raw_password,0x10000000);
	int raw_length=2*strlenw(wide_password);
	memcpy(raw_password+raw_length,salt,8);
	raw_length+=8;
	SHA1_CTX c;
    SHA1Init(&c);	
	for (i=0;i<hash_rounds;i++) {
		SHA1Update(&c, raw_password, raw_length);
		unsigned char password_number[3];
		password_number[0]=(unsigned char)i;
		password_number[1]=(unsigned char)(i>>8);
		password_number[2]=(unsigned char)(i>>16);
		SHA1Update(&c, password_number, 3);
		if (i%(hash_rounds/16)==0) {
			SHA1_CTX tempc=c;
			unsigned char digest[20];
			SHA1Final(digest, &tempc);	
			aesinit[i/(hash_rounds/16)]=digest[19];
		}
    }
	unsigned char digest[20];
	SHA1Final(digest, &c);
	aeskey[0] = digest[3];	aeskey[1] = digest[2];	aeskey[3] = digest[0];	aeskey[4] = digest[7];
	aeskey[5] = digest[6];	aeskey[6] = digest[5];	aeskey[7] = digest[4];	aeskey[8] = digest[11];
	aeskey[9] = digest[10];	aeskey[10] = digest[9];	aeskey[11] = digest[8];	aeskey[12] = digest[15];
	aeskey[13] = digest[14]; aeskey[14] = digest[13]; aeskey[15] = digest[12]; aeskey[2] = digest[1];	
}

/*
 * This function write progress value to a .crk file when it is called. The .crk file name is the same
 * than the name of the archive that is being attacked.
 * 
 * Arguments : 
 *		char method : 'd' for dictionary, 'b' for bruteforce.
 *		uint64_t low_index : current index.
 *		uint64_t high_index : ending index.
 *		int max_pass : the maximum password length.
 *		int benchmark : the benchmark count.
 *
 *  Return Value : none.
 */
void save_progress(char method, uint64_t low_index, uint64_t high_index, int max_pass, int benchmark)
{
	extern char crk_file_name[256];
	extern char dic_file_name[256];
	extern int saving_interval;
	FILE * crk_file;
	if((crk_file = fopen(crk_file_name,"w"))==NULL) {
		fprintf(stderr, "Can't open %s.", crk_file_name);
		exit(1);
	}
	fprintf(crk_file,"m%c\n", method);
	fprintf(crk_file,"d%s\n", dic_file_name);
	fprintf(crk_file,"i%llu\n", low_index);
	fprintf(crk_file,"j%llu\n", high_index);
	if(benchmark!=0)
		fprintf(crk_file,"b%d\n", benchmark);
	if(max_pass!=0)
		fprintf(crk_file,"p%d\n", max_pass);
	fprintf(crk_file,"t%d\n", saving_interval);
	fclose(crk_file);
}
/*
 * This function write a discovered password to the .crk file corresponding with an archive.
 * 
 * Arguments : 
 *		char * password: the discovered password.
 *
 *  Return Value : none.
 */
void save_result(char * password)
{
	extern char crk_file_name[256];
	FILE * crk_file;
	if((crk_file = fopen(crk_file_name,"w"))==NULL) {
		fprintf(stderr, "Can't open %s.", crk_file_name);
		exit(1);
	}
	fprintf(crk_file,"x%s\n", password);
	fclose(crk_file);
}

/*
 * The function checks if the file is recognized and then launch a dictionary attack.
 *
 * Arguments : 
 *		char * password : will contains the password when it is found.
 *		int max_pass : the maximum size of password to try.
 *		FILE * dic_file : a stream to the file containing the word list.
 *		FILE * to_crack_file : a stream to the archive file we want to decrypt.
 *		low_index : the starting point.
 *		high_index : the end point.
 *		benchmark : if > 0 then only benchmark tests will be effectued.
 *
 * Return Value :
 *		0 : password not found.
 *		1 : password found. Result in char * password.
 */
int dictionary(	char * password, FILE * dic_file, FILE * to_crack_file, uint64_t low_index,
				uint64_t high_index, int benchmark)
{

	/*Read the 2 first byte of the file to crack to identify its type.*/
	char magic[3]="  ";
	char rar_marker_block[7]={0x52, 0x61,0x72, 0x21, 0x1a, 0x07, 0x00};
	char * rar_marker_ptr = rar_marker_block;
	int result;
	magic[0] = fgetc(to_crack_file);
	magic[1] = fgetc(to_crack_file);

	if((magic[0]==(*rar_marker_ptr))&&(magic[1]==(*++rar_marker_ptr))) {	/*Probably a RAR File*/
	
		/*Let's read the rest to check it's really a RAR file Marker Block*/
		while((*++rar_marker_ptr) != 0x00) {
			if(*rar_marker_ptr != fgetc(to_crack_file)) {					/*Actually not a RAR*/
				fprintf(stderr,"Unknown file format.\n");
				return 2;
			}
		}
		
		/*Launch the dictionary function for RAR files*/
		rewind(to_crack_file);
		result = rar_dictionary(password, dic_file, to_crack_file, low_index, high_index, benchmark);
	} else {
		if((magic[0]=='P')&&(magic[1]=='K')) {								/*Probably a Zip file*/
			fprintf(stderr,"Zip file cracking is not yet implemented.\n");
			return 2;	
		} else {
			fprintf(stderr,"Unknown file format.\n");
			return 2;
		}
	}
	return result;
}

/*
 * The function performs a dictionary attack an a RAR file.
 *
 * Arguments : 
 *		char * password : will contains the password when it is found.
 *		int max_pass : the maximum size of password to try.
 *		FILE * dic_file : a stream to the file containing the word list.
 *		FILE * to_crack_file : a stream to the archive file we want to decrypt.
 *		low_index : the starting point.
 *		high_index : the end point.
 *		benchmark : if > 0 then only benchmark tests will be effectued.
 *
 * Return Value :
 *		0 : password not found.
 *		1 : password found. Result in char * password.
 */
int rar_dictionary(char * password, FILE * dic_file, FILE * to_crack_file, 
					uint64_t low_index, uint64_t high_index, int benchmark)
{
	extern int saving_interval;
	int number_of_line_in_dic=0;
	char salt[9];
	char encrypted_block[1025];
	char line[256];
	int result;
	int bench_high_index;

	/*Initialize the CRC Tab for faster lookup*/
	InitCRC();
						
	/*Check how many words in dictionary*/
	int c,i;
	time_t start_time, end_time;

	while ((c = fgetc(dic_file)) != EOF) {
		if(c == '\r')							/*ignore CR on win32*/
			continue;
		if(c=='\n'&&c!=i)
			number_of_line_in_dic++;
		i=c;
	}
	if(i != '\n') {								/*case where a dictionary file does not end with a linefeed*/
		number_of_line_in_dic++;
	}
	rewind(dic_file);

	/*Process the RAR file - we need to get the salt and an entire encrypted block*/
	parse_rar(to_crack_file, salt, encrypted_block);

	/*If it's a test we save the start time and limit the number of tries*/
	if(benchmark > 0) {
		time(&start_time);
		char timestring[200];
		strftime(timestring,199,"%H:%M:%S",localtime(&start_time));
		printf("\nBenchmark started at %s\n", timestring);
		bench_high_index = high_index;
		if(benchmark < (high_index - low_index))
			high_index = low_index + benchmark - 1;
	}
	/*Adjust the indexes*/
	if(number_of_line_in_dic < low_index) {
		fprintf(stderr, "The index value is higher than the total number of passwords (%llu) in dictionary\n", number_of_line_in_dic);
		exit(1);
	}
	if(high_index > number_of_line_in_dic || high_index == 0)
		high_index = number_of_line_in_dic;
			
	/*Place the dic_file cursor at the right position*/
	c = 0;
	while (c < low_index - 1) {
		fgets(line,1024,dic_file);
		if((strcmp(line, "\n")!=0)&&(strcmp(line,"\r\n")!=0))
			c++;
	}
				
	/*Init of the AES context*/
	uint64_t index = 0;
	AVAES *aescon = malloc(sizeof(AVAES));
	
	/*Test each line in dictionry file.*/
	index = low_index;	
	while(index <= high_index) {
		/*Save the progress every saving_interval test.*/
		if((index % saving_interval)==0)
			if(benchmark > 0)
				save_progress('d',index,bench_high_index,0,benchmark);
			else
				save_progress('d',index,high_index,0,0);
				
		/*Fetch the next line without the ending \n*/
		fgets(line,1024,dic_file);
		if((strcmp(line, "\n")!=0)&&(strcmp(line,"\r\n")!=0)) {
			if(line[strlen(line)-2]=='\r')
				line[strlen(line)-2] = '\0';
			else
				if(line[strlen(line)-1] == '\n')
					line[strlen(line)-1] = '\0';
			/*test the password*/
			if((result = rar_test_password(encrypted_block, line, salt, aescon)) == 1) {
				strcpy(password,line);
				return 1;
			}		
		index++;
		}
	}
	/*If it's a test, we display the result*/
	if(benchmark > 0) {
		time(&end_time);
		time_t timer = end_time - start_time;
		int number_of_pass = high_index - low_index + 1;
		float pass_per_sec = ((float)number_of_pass/((int)timer));
		float average_days = (((float)number_of_line_in_dic/pass_per_sec)/3600)/24;
		char timestring[200];
		strftime(timestring,199,"%H:%M:%S",localtime(&end_time));
		printf("Benchmark ended at %s\n", timestring);
		printf("%d passwords tested in %d seconds\n",number_of_pass, (int)timer);
		printf("Average performance : %f passwords/sec\n\n", pass_per_sec);
		printf("With this dictionary there are %llu passwords\n", number_of_line_in_dic);
		printf("that will all be tried in about %f days\n", average_days);
	}	
	return 0;
}

/*
 * The function performs a test to check that the this utility is working properly.
 *
 * Arguments : none.
 *
 * Return Value : none.
 */
void utility_test()
{
	int i;
	char test_password[8]="yuyu";
	char salt[8]={0xE1, 0x3C, 0x57, 0x04, 0x16, 0x86, 0x51, 0x2F};
	unsigned char test_encrypted_block[]={	
		0x4F, 0xD5, 0x97, 0xCA, 0x65, 0x30, 0x81, 0x19,
		0xD4, 0xEB, 0xB0, 0xC8, 0x20, 0x87, 0x4D, 0x58, 0xB7, 0x29, 0x1F, 0x13, 0x4D, 0x8A, 0x4E, 0xB0,
		0x7E, 0x90, 0x4B, 0xF5, 0x77, 0x3C, 0x26, 0xA3, 0x90, 0x3B, 0x6F, 0x97, 0xAA, 0x48, 0x00, 0x92,
		0xD3, 0xCE, 0x30, 0x3D, 0x85, 0x85, 0x5C, 0xA8, 0x2E, 0xB8, 0x19, 0xE5, 0x82, 0xF9, 0x6B, 0xD7,
		0x3F, 0xD4, 0xC8, 0x6C, 0xE0, 0xF5, 0xA7, 0x90, 0x8D, 0x0C, 0x93, 0xAC, 0xBA, 0x70, 0x0F, 0x18,
		0xB0, 0x40, 0x50, 0x4A, 0x09, 0x93, 0x1E, 0xF1, 0x5E, 0xE2, 0x9A, 0xB1, 0x40, 0x47, 0x06, 0xDE,
		0xD9, 0xAF, 0x04, 0x8D, 0x8B, 0x3C, 0x3B, 0x80, 0x08, 0x22, 0xF5, 0x30, 0x8B, 0x9A, 0x4C, 0xC0,
		0xCA, 0xC7, 0x5D, 0xB3, 0xDE, 0x00, 0x08, 0xE9, 0x45, 0x04, 0x78, 0xAE, 0xC2, 0xA6, 0x87, 0xF8,
		0xA7, 0x2F, 0x61, 0xFF, 0xC5, 0xFE, 0x79, 0x3C, 0x40, 0xA4, 0x67, 0xB8, 0x3C, 0x92, 0xAE, 0x75,
		0xC8, 0x0A, 0x9F, 0x26, 0x97, 0x97, 0x1C, 0x4D, 0x58, 0x77, 0xB2, 0x97, 0xF9, 0x80, 0x58, 0x18,
		0xE7, 0x40, 0x61, 0x80, 0xF7, 0x57, 0xFB, 0x31, 0xDE, 0xA1, 0x9C, 0xC5};
	unsigned char sha1_result[20] = { 0xfc, 0x94, 0x3b, 0x3e, 0x46, 0x6d, 0x7d, 0x1b, 0xd1, 0xb4, 0xcc, 0x7b, 0x70, 0xf4, 0x9b, 0x24, 0x17, 0xf1, 0x28, 0x42};
	unsigned char correct_aeskey[16]=		{0x71, 0xed, 0x12, 0xc1, 0xcd, 0xb8, 0xe9, 0x22, 0x28, 0x15, 0xe7, 0xc5, 0xbb, 0x8a, 0x60, 0x8d};
	unsigned char correct_initvector[16]=	{0x1a, 0x90, 0x62, 0x99, 0x63, 0x6c, 0x36, 0x7b, 0x7, 0x7b, 0x94, 0x5c, 0x26, 0xf, 0x99, 0x38};
	char correct_decrypted_block[16] = {0x17, 0x94, 0x74, 0x64, 0x84, 0x32, 0x00, 0xf0, 0x52, 0x06, 0x00, 0x00, 0x84, 0x06, 0x00, 0x02};
	
/*Test the SHA1 function*/
	SHA1_CTX c;
    SHA1Init(&c);
	SHA1Update(&c, test_encrypted_block, 20);
	unsigned char digest[20];
	SHA1Final(digest, &c);
	for(i=0; i < 20; i++) {
		if(digest[i]!=sha1_result[i]) {
			printf("There was an error with the SHA1 Hash calculation\n");
			exit(1);
		}
	}
	
/*Test the prepare key function*/
	unsigned char aeskey[16];
	unsigned char aesinitvector[16];
	prepare_key((unsigned char*)test_password, (unsigned char*)salt, aeskey, aesinitvector);
	for(i=0; i < 16; i++) {
		if(aeskey[i]!=correct_aeskey[i]) {
			printf("There was an error with the AES Key  calculation\n");
			exit(1);
		}
	}
	for(i=0; i < 16; i++) {
		if(aesinitvector[i]!=correct_initvector[i]) {
			printf("There was an error with the Initialization vector calculation\n");
			exit(1);
		}
	}
	
/*Test the AES decryption*/
	AVAES *aescon = malloc(sizeof(AVAES));
	av_aes_init(aescon, aeskey, 128, 1);
	char buffer_d[128];
	char buffer[16];
	int buffer_size = 0;
	while(buffer_size < 128) {
		for(i = 0; i < 16; i++) {
			buffer[i]=test_encrypted_block[buffer_size++];
		}
		
		/*Decrypt the buffer*/
		av_aes_crypt(aescon, (unsigned char *)buffer_d+(buffer_size - 16), (unsigned char *)buffer, 1, aesinitvector, 1);
	}
	for(i=0; i < 16; i++) {
		if(buffer_d[i]!=correct_decrypted_block[i]) {
			printf("There was an error with the AES decryption\n");
			exit(1);
		}
	}	
	free(aescon);
/*Test the read_rar function*/
	uint16_t headCRC;
	headCRC = read_rar_head_crc(correct_decrypted_block);
	if(headCRC != 0x9417) {
		printf("There was an error with the Rar Reading functions.\n");
		exit(1);
	}
/*Test the CRC function*/
	InitCRC();
	unsigned int blockCRC=CalcCRC32(0xffffffff,buffer_d+2,50-2);	
	unsigned short HeaderCRC = (~(blockCRC)&0xffff);
	if(HeaderCRC != headCRC) {
			printf("There was an error with the CRC calculation.\n");
			exit(1);	
	}
printf("Everything seems OK. The utility should work on this computer\n");
exit(0);
}