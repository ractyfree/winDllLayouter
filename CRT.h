#pragma once
#include "Imports.h"
#include "MyStructs.h"

#pragma function(malloc)
extern "C" void* __cdecl malloc (
	size_t _Size
	);
#pragma function(free)
extern "C" void* __cdecl free (
	void* _Block
	);

#ifdef Debug
int printf (const char * format, ...);
#endif
char*  strcpy (char *destination, const char *source);

#ifdef Debug
int getchar (void);
#endif
char * strcat (char * destination, const char * source);

int strcmp (const char * str1, const char * str2);

void srand (unsigned int seed);

#pragma function(memset)
extern "C" void * memset (void * ptr, int value, size_t num);

FILE *  fopen (const char * filename, const char * mode);

int fseek (FILE * stream, long int offset, int origin);

long int ftell (FILE * stream);

void rewind (FILE * stream);

char *  fgets (char * str, int num, FILE * stream);

size_t fread (void * ptr, size_t size, size_t count, FILE * stream);


int fclose (FILE * stream);

char* _strlwr (char* String);

wchar_t* _wcslwr (wchar_t* String);

wchar_t*  wcscpy (wchar_t* destination, const wchar_t* source);

size_t wcstombs (char* dest, const wchar_t* src, size_t max);

char * strstr (char * str1, const char * str2);

#pragma function(memcpy)
extern "C" void * memcpy (void * destination, const void * source, size_t num);

#pragma function(realloc)
extern "C" void*  realloc (void* ptr, size_t size);

char*  getenv (const char* name);
#pragma function(strlen)
extern "C" size_t strlen (const char * str);

size_t wcslen (const wchar_t* wcs);

#pragma function(memmove)
extern "C" void *  memmove (void * destination, const void * source, size_t num);

char *   itoa (int value, char * str, int base);

double strtod (const char* str, char** endptr);

int tolower (char c);

char *  strncpy (char * destination, const char * source, size_t num);

long int strtol (const char* str, char** endptr, int base);

int isspace (int c);

char * strtok (char * str, const char * delimiters);

void exit (int status);

const char *  strchr (const char * str, int character);


int system (const char* command);

int rand (void);

int sprintfa (char * str, const char * format, ...);

double atof (const char* str);

int atoi(const char * str);

char * strdup(const char *str1);

