/* main.c
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
 
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#ifndef __WIN32__
#include <sys/resource.h>
#endif
#include "aapr.h"

/*Global variables*/

/*Will contains the file name to save .crk file name.*/
char crk_file_name[256]; 

/*Will contains the dictionary or character set file.*/
char dic_file_name[256];

 /*save progress in crk file each X tries.*/
int saving_interval=1500;

int main (int argc, const char * argv[])
{
	char method;
	int benchmark =0;
	FILE * dic_file;
	FILE * to_crack_file;
	char to_crack_file_name[256];
	char password[256];					/*will contains the password when it is found*/
	uint64_t high_index = 0;
	uint64_t low_index = 0;
	int max_pass = 1;
	int job_continue = 0;				/*set to 1 if resuming a job*/
	int result=0;						/*contains the result of the cracking functions*/

	/*Set process priority to the minimum*/
#ifndef __WIN32__
		setpriority(PRIO_PROCESS, getpid(), 20);
#endif

	/* Read the command line arguments */
	if(argc > 1) {
		int i=1;
		if(argv[i][0] != '-') {
			display_usage();
			exit(1);
		}
		for(; i < argc; i++) {
			if(*argv[i] != '-')
				continue;
			switch(argv[i][1]) {
				case 'm' :
					switch(argv[i][2]) {
						case 'd':
							method = 'd';
							if(*argv[i+1] != '-')
								strcpy(dic_file_name, argv[i+1]);
							else {
								fprintf(stderr, "Please indicate the dictionary file to use.\n");
								exit(1);						
							}
							break;
					
						case 'b':
							method = 'b';
							if(*argv[i+1] != '-')
								strcpy(dic_file_name, argv[i+1]);
							else {
								fprintf(stderr, "Please indicate the dictionary file to use.\n");
								exit(1);						
							}
							break;
					
						case 'c':
							method = 'c';
							if(*argv[i+1] != '-')
								strcpy(dic_file_name, argv[i+1]);
							else {
								fprintf(stderr, "Please indicate the dictionary file to use.\n");
								exit(1);						
							}
							break;
					
						default:
							fprintf(stderr, "Method %c unknown\n", argv[i][2]);
							exit(1);
							break;
					}
					break;
				
				case 'p':
					if(*argv[i+1] != '-')
						max_pass = atoi(argv[i+1]);
					break;

				case 't':
					if(*argv[i+1] != '-')
						saving_interval = atoi(argv[i+1]);
					break;
				
				case 'c':
					job_continue = 1;
					break;
				
				case 'i':
					if(*argv[i+1] != '-')
						low_index = atoi(argv[i+1]);
					if(*argv[i+2] != '-')
						high_index = atoi(argv[i+2]);
					if(high_index < low_index && high_index != 0) {
							fprintf(stderr, "Wrong starting and ending indexes\n");
							exit(1);
					}
					break;
					
				case 'b':
					if(*argv[i+1] != '-')
						benchmark = atoi(argv[i+1]);
					break;
					
				case '?':
					utility_test();
					break;
			}
		}
		strcpy(to_crack_file_name, argv[i-1]);						/*Read the encrypted archive filename.*/
	} else {														/*No arguments*/
		display_usage();
		exit(1);
	}																/*End of Argument Reading*/

	get_crk_file(crk_file_name, to_crack_file_name);
	FILE *crk_file;
	if(!((crk_file = fopen(crk_file_name,"r"))==NULL)) {
		job_continue = 2;
	}	
	if(job_continue) { /*This is a restart of a former job*/
		char line[256];
		if(job_continue == 1) {										/*argument c was given but the crk file does not exists.*/
			fprintf(stderr, "Can't open %s.", crk_file_name);
			exit(1);
		}
		/*Read the file*/
		while(fgets(line, 256, crk_file) != NULL) {
			switch(line[0]) {
				case 'm':
					if((line[1]=='d')||(line[1]=='b')||(line[1]=='c'))
						method=line[1];
					break;
				case 'd':
					strncpy(dic_file_name,line+1,strlen(line+1)-1);
					dic_file_name[strlen(line+1)-1]='\0';
					break;
				case 'i':
					low_index=atoi(line+1);
					break;
				case 'j':
					high_index=atoi(line+1);
					break;
				case 'p':
					max_pass=atoi(line+1);
					break;
				case 'b':
					benchmark=atoi(line+1);
					break;
				case 't':
					saving_interval=atoi(line+1);
					break;
				case 'x':
					fprintf(stderr, "This archive was already decrypted successfully !\n Check %s\n Delete it if you want to start again.\n", to_crack_file_name);
					exit(0);
					break;
			}
		}
		fclose(crk_file);
	} else { /*This is a new job*/
	/*I can't think about anything to do here yet*/
	}

	/*This is to let people specify 1 or 0 as the first index*/
	if(low_index == 0)
		low_index = 1;

	/*Try to open the dictionary and archive files*/
	if((dic_file = fopen(dic_file_name,"r"))==NULL) {
		fprintf(stderr, "Can't open %s.", dic_file_name);
		exit(1);
	}
	if((to_crack_file = fopen(to_crack_file_name,"rb"))==NULL) {
		fprintf(stderr, "Can't open %s.", to_crack_file);
		exit(1);
	}
	switch(method) {
		case 'b':
			result = bruteforce(password, max_pass, dic_file,
								to_crack_file, low_index, high_index, 
								benchmark);
			break;
		case 'd':
			result = dictionary(password, dic_file,
								to_crack_file, low_index, high_index, 
								benchmark);
			break;
		case 'c':					/*Placeholder for a future extra attack method*/
			break;
	}
			if(result == 1) { /*Password found*/
				save_result(password);
				printf("The archive password is \"%s\".\n", password);
			} else 
				printf("The archive password could not be found with this settings.\n");
		return 0;
}
