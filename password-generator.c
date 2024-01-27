/*
BSD 2-Clause License

Copyright (c) 2024, illegalcoding

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this
   list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice,
   this list of conditions and the following disclaimer in the documentation
   and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/
#include <stdio.h>
#include <sys/time.h>
#include <time.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <pthread.h>

char charset[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ()!#?-_*.,&:+"; // 65 chars
struct timespec prog_start;
struct timespec prog_end;
struct timespec no_io;
#define FILENAME "passwords.txt"
#define CHARSET_SIZE 65
#define RANDINDEX rand_start_index+randcounter
char** passwords;
int* pass_starts;
int* pass_ends;
int pass_starts_counter = 0;
int pass_ends_counter = 0;
int* rand_starts;
int* rand_ends;
int rand_starts_counter = 0;
int rand_ends_counter = 0;
int password_counter = 0;
int num_threads = 0;
int threads_started = 0;
int do_exit = 0;
uint8_t* buf;
struct passgen_args {
	int length;
	int pass_start_index;
	int pass_end_index;
	int rand_start_index;
	int rand_end_index;
};
void usage();
void* generate_passwords(void* args);

void usage() {
	fprintf(stderr,"Usage:\n");	
	fprintf(stderr,"\tpassword-generator [length] [amount] [threads]\n");
	fprintf(stderr,"Note:\n");
	fprintf(stderr,"\tIt is recommended that [threads] match the number of cores your CPU has.\n");
	exit(1);
}
void* generate_passwords(void* argsptr) {
	struct passgen_args args = *(struct passgen_args*)argsptr;
	int length = args.length;
	int pass_start_index = args.pass_start_index;
	int pass_end_index = args.pass_end_index;
	int rand_start_index = args.rand_start_index;
	int rand_end_index = args.rand_end_index;
	int local_do_exit = 0;
	free(argsptr);
	int counter = 0;
	int randcounter = 0;
	while(!do_exit && !local_do_exit) {
		int do_index = pass_start_index+counter;
		if(do_index > pass_end_index) {
			local_do_exit = 1;
			return 0;
		}
		char* password = malloc((length)*sizeof(char));
		password[length] = '\0';
		for(int j = 0; j<length; j++) {
			uint8_t choice = buf[RANDINDEX];
			randcounter++;

			password[j] = charset[choice];
		}
		passwords[do_index] = password;
		counter++;
	}
	return 0;
}
void free_all(int amount) {
	for(int i = 0; i<amount; i++) {
		free(passwords[i]);
	}
}
void pass_split_range(int num_threads, int amount) {
	int split_range = floor((int)(amount/num_threads));
	int start_index = 0;
	int end_index = 0;
	int abs_end_index = amount-1;
	int last_end_index = 0;
	for(int i = 0; i<num_threads; i++) {
		if(i == 0) {
			start_index = 0;
			end_index = start_index+split_range;

			pass_starts[pass_starts_counter] = start_index;
			pass_ends[pass_ends_counter] = end_index;
		
			pass_starts_counter++;
			pass_ends_counter++;
			last_end_index = end_index;
		} else {
			start_index = last_end_index+1;
			end_index = start_index+split_range;
			if(end_index > abs_end_index) {
				end_index = abs_end_index;
			}

			pass_starts[pass_starts_counter] = start_index;
			pass_ends[pass_ends_counter] = end_index;
		
			pass_starts_counter++;
			pass_ends_counter++;
			last_end_index = end_index;
		}
	}
}
void rand_split_range(int num_threads, size_t bufsz) {
	int split_range = floor((int)(bufsz/num_threads));
	int start_index = 0;
	int end_index = 0;
	int abs_end_index = bufsz-1;
	int last_end_index = 0;
	for(int i = 0; i<num_threads; i++) {
		if(i == 0) {
			start_index = 0;
			end_index = start_index+split_range;

			rand_starts[rand_starts_counter] = start_index;
			rand_ends[rand_ends_counter] = end_index;
		
			rand_starts_counter++;
			rand_ends_counter++;
			last_end_index = end_index;
		} else {
			start_index = last_end_index+1;
			end_index = start_index+split_range;
			if(end_index > abs_end_index) {
				end_index = abs_end_index;
			}

			rand_starts[rand_starts_counter] = start_index;
			rand_ends[rand_ends_counter] = end_index;
		
			rand_starts_counter++;
			rand_ends_counter++;
			last_end_index = end_index;
		}
	}
}
void print_passwords(int amount) {
	for(int i = 0; i<amount; i++) {
		fprintf(stderr, "passwords[%d]: %s\n",i,passwords[i]);
	}
}
int main(int argc, char** argv) {
	if(argc != 4) {
		usage();
	}
	clock_gettime(CLOCK_REALTIME,&prog_start);
	int length;
	int amount;
	length = atoi(argv[1]);
	amount = atoi(argv[2]);
	num_threads = atoi(argv[3]);
	size_t buf_size = length*amount*sizeof(uint8_t);
	buf = malloc(buf_size);
	arc4random_buf(buf,buf_size);
	for(int i = 0; i<buf_size;i++) {
		buf[i] = buf[i] % CHARSET_SIZE;
	}

	passwords = malloc(amount*sizeof(char*));
	pass_starts = malloc(num_threads*sizeof(int));
	pass_ends = malloc(num_threads*sizeof(int));
	rand_starts = malloc(num_threads*sizeof(int));
	rand_ends = malloc(num_threads*sizeof(int));
	pass_split_range(num_threads, amount);
	rand_split_range(num_threads, buf_size);
	pthread_t threads[num_threads];
	for(int i = 0; i<num_threads; i++) {
		struct passgen_args* args = malloc(sizeof(struct passgen_args));
		args->pass_start_index = pass_starts[i];
		args->pass_end_index = pass_ends[i];
		args->rand_start_index = rand_starts[i];	
		args->rand_end_index = rand_ends[i];	
		args->length = length;
		pthread_create(&threads[i],NULL,generate_passwords,(void*)args);
		threads_started++;
	}
	for(int i = 0; i<num_threads; i++) {
		pthread_join(threads[i],NULL);
	}
	free(pass_starts);
	free(pass_ends);
	free(rand_starts);
	free(rand_ends);
	free(buf);
	clock_gettime(CLOCK_REALTIME,&no_io);
	FILE* file_out = fopen(FILENAME, "w");
	for(int i = 0; i<amount; i++) {
		char lf = '\n';
		fwrite(passwords[i],length,1,file_out);
		fwrite(&lf,1,1,file_out);
	}
	fclose(file_out);
	free_all(amount);
	free(passwords);
	clock_gettime(CLOCK_REALTIME,&prog_end);
	double all_seconds = (prog_end.tv_sec - prog_start.tv_sec) + (prog_end.tv_nsec - prog_start.tv_nsec) / 1e9;
	double noio_seconds = (no_io.tv_sec - prog_start.tv_sec) + (no_io.tv_nsec - prog_start.tv_nsec) / 1e9;
	fprintf(stderr,"Program finished in %fs, %fs without I/O\n",all_seconds,noio_seconds);
	return 0;
}
