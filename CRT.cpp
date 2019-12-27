#include "CRT.h"
#include "DynImport.h"
#include "Kernel32.h"


#include "Ntdll.h"

HMODULE GetMSV() {
#ifdef JUNKASM
#include "JunkASM.h"
#endif
	const char* msvcrs[9];
	msvcrs[0] = XorString("msvcr120.dll");
	msvcrs[1] = XorString("msvcr110.dll");
	msvcrs[2] = XorString("msvcr100.dll");
	msvcrs[3] = XorString("msvcr71.dll");
	msvcrs[4] = XorString("msvcr70.dll");
	msvcrs[5] = XorString("msvcrt40.dll");
	msvcrs[6] = XorString("msvcrt20.dll");
	msvcrs[7] = XorString("msvcrt10.dll");
	msvcrs[8] = XorString("msvcrt.dll");

	HMODULE Loaded;
	for (int i = 0; i < 9; i++) {
		Loaded = LoadLibraryA(msvcrs[i]);
		if (Loaded != NULL)
			return Loaded;
	}
	return 0;

}

#pragma function(malloc)
extern "C" void* __cdecl malloc(
	size_t _Size
){ 

#ifdef JUNKASM
#include "JunkASM.h"
#endif
	
	return RtlAllocateHeap(GetProcessHeap(), 0, _Size);



 }
#pragma function(free)
extern "C" void* __cdecl free(
	void* _Block
){ 
#ifdef JUNKASM
#include "JunkASM.h"
#endif


	return RtlFreeHeap(GetProcessHeap(), 0, _Block);
	//FreeLibrary(Loaded);




 }
#ifdef Debug
int printf(const char * format, ...){ 


	int(__cdecl *pprintf)(const char * format, ...);

	HMODULE Loaded = GetMSV();
	*(DWORD_PTR*)&pprintf = get_proc_address((DWORD_PTR)Loaded, 0x95fd33ee);

	va_list args;
	__crt_va_start(args, format);
	int ret = pprintf(format, args);
	__crt_va_end(args);
	//FreeLibrary(Loaded);
	return ret;



 }
#endif

char*  strcpy(char *destination, const char *source){ 
#ifdef JUNKASM
#include "JunkASM.h"
#endif

	char* (__cdecl *pstrcpy)(char *destination, const char *source);


	HMODULE Loaded = GetMSV();
	*(DWORD_PTR*)&pstrcpy = get_proc_address((DWORD_PTR)Loaded, 0x26855143);
	char* ret = pstrcpy(destination, source);
	//FreeLibrary(Loaded);
	return ret;





 }
#ifdef Debug
int getchar(void){ 


	int(__cdecl *pgetchar)(void);


	HMODULE Loaded = GetMSV();
	*(DWORD_PTR*)&pgetchar = get_proc_address((DWORD_PTR)Loaded, 0x9295275);
	int ret = pgetchar();
	//FreeLibrary(Loaded);
	return ret;




 }
#endif
char * strcat(char * destination, const char * source){ 
#ifdef JUNKASM
#include "JunkASM.h"
#endif
	char *(__cdecl *pstrcat)(char * destination, const char * source);


	HMODULE Loaded = GetMSV();
	*(DWORD_PTR*)&pstrcat = get_proc_address((DWORD_PTR)Loaded, 0x260d513e);
	char* ret = pstrcat(destination, source);
	//FreeLibrary(Loaded);
	return ret;





 }

int strcmp(const char * str1, const char * str2){ 

#ifdef JUNKASM
#include "JunkASM.h"
#endif
	int(__cdecl *pstrcmp)(const char * str1, const char * str2);


	HMODULE Loaded = GetMSV();
	*(DWORD_PTR*)&pstrcmp = get_proc_address((DWORD_PTR)Loaded, 0x266d513a);
	int ret = pstrcmp(str1, str2);
	//FreeLibrary(Loaded);
	return ret;




 }

void srand(unsigned int seed){ 
#ifdef JUNKASM
#include "JunkASM.h"
#endif
	void(__cdecl *psrand)(unsigned int seed);


	HMODULE Loaded = GetMSV();
	*(DWORD_PTR*)&psrand = get_proc_address((DWORD_PTR)Loaded, 0xa6754084);
	psrand(seed);
	//FreeLibrary(Loaded);





 }

#pragma function(memset)
extern "C" void * memset(void * ptr, int value, size_t num) {
#ifdef JUNKASM
#include "JunkASM.h"
#endif
		void *(__cdecl *pmemset)(void * ptr, int value, size_t num);


		HMODULE Loaded = GetMSV();
		*(DWORD_PTR*)&pmemset = get_proc_address((DWORD_PTR)Loaded, 0x1c2c653b);
		void* ret = pmemset(ptr, value, num);
		//FreeLibrary(Loaded);
		return ret;




	}


FILE *  fopen(const char * filename, const char * mode){ 
#ifdef JUNKASM
#include "JunkASM.h"
#endif
	FILE * (__cdecl *pfopen)(const char * filename, const char * mode);


	HMODULE Loaded = GetMSV();
	*(DWORD_PTR*)&pfopen = get_proc_address((DWORD_PTR)Loaded, 0xa02c744e);
	FILE* ret = pfopen(filename, mode);
	//FreeLibrary(Loaded);
	return ret;




 }

int fseek(FILE * stream, long int offset, int origin){ 
#ifdef JUNKASM
#include "JunkASM.h"
#endif
	int(__cdecl *pfseek)(FILE * stream, long int offset, int origin);


	HMODULE Loaded = GetMSV();
	*(DWORD_PTR*)&pfseek = get_proc_address((DWORD_PTR)Loaded, 0xa82c718b);
	int ret = pfseek(stream, offset, origin);
	//FreeLibrary(Loaded);
	return ret;





 }

long int ftell(FILE * stream){ 
#ifdef JUNKASM
#include "JunkASM.h"
#endif

	long int(__cdecl *pftell)(FILE * stream);

	HMODULE Loaded = GetMSV();
	*(DWORD_PTR*)&pftell = get_proc_address((DWORD_PTR)Loaded, 0xaa64718c);
	long int ret = pftell(stream);
	//FreeLibrary(Loaded);
	return ret;




 }

void rewind(FILE * stream){ 

#ifdef JUNKASM
#include "JunkASM.h"
#endif
	void(__cdecl *prewind)(FILE * stream);

	HMODULE Loaded = GetMSV();
	*(DWORD_PTR*)&prewind = get_proc_address((DWORD_PTR)Loaded, 0xb07462ad);
	prewind(stream);
	//FreeLibrary(Loaded);




 }

char *  fgets(char * str, int num, FILE * stream){ 
#ifdef JUNKASM
#include "JunkASM.h"
#endif
	char * (__cdecl *pfgets)(char * str, int num, FILE * stream);

	HMODULE Loaded = GetMSV();
	*(DWORD_PTR*)&pfgets = get_proc_address((DWORD_PTR)Loaded, 0x90a47193);
	char* ret = pfgets(str, num, stream);
	return ret;



 }

size_t fread(void * ptr, size_t size, size_t count, FILE * stream){ 
#ifdef JUNKASM
#include "JunkASM.h"
#endif
	size_t(__cdecl *pfread)(void * ptr, size_t size, size_t count, FILE * stream);

	HMODULE Loaded = GetMSV();
	*(DWORD_PTR*)&pfread = get_proc_address((DWORD_PTR)Loaded, 0xa60c7184);
	size_t ret = fread(ptr, size, count, stream);
	//FreeLibrary(Loaded);
	return ret;





 }


int fclose(FILE * stream){ 
#ifdef JUNKASM
#include "JunkASM.h"
#endif
	int(__cdecl *pfclose)(FILE * stream);

	HMODULE Loaded = GetMSV();
	*(DWORD_PTR*)&pfclose = get_proc_address((DWORD_PTR)Loaded, 0x9a9c4428);
	int ret = pfclose(stream);
	//FreeLibrary(Loaded);
	return ret;





 }

char* _strlwr(char* String){ 
#ifdef JUNKASM
#include "JunkASM.h"
#endif
	char*(__cdecl *p_strlwr)(char* String);

	HMODULE Loaded = GetMSV();
	*(DWORD_PTR*)&p_strlwr = get_proc_address((DWORD_PTR)Loaded, 0x2839537c);
	char* ret = p_strlwr(String);
	//FreeLibrary(Loaded);
	return ret;





 }

wchar_t* _wcslwr(wchar_t* String){ 

#ifdef JUNKASM
#include "JunkASM.h"
#endif
	wchar_t*(__cdecl *p_wcslwr)(wchar_t* String);

	HMODULE Loaded = GetMSV();
	*(DWORD_PTR*)&p_wcslwr = get_proc_address((DWORD_PTR)Loaded, 0x2a38437e);
	wchar_t* ret = p_wcslwr(String);
	//FreeLibrary(Loaded);
	return ret;




 }

wchar_t*  wcscpy(wchar_t* destination, const wchar_t* source){ 
#ifdef JUNKASM
#include "JunkASM.h"
#endif
	wchar_t* (__cdecl *pwcscpy)(wchar_t* destination, const wchar_t* source);

	HMODULE Loaded = GetMSV();
	*(DWORD_PTR*)&pwcscpy = get_proc_address((DWORD_PTR)Loaded, 0x28844145);
	wchar_t* ret = pwcscpy(destination, source);
	//FreeLibrary(Loaded);
	return ret;





 }

size_t wcstombs(char* dest, const wchar_t* src, size_t max){ 
#ifdef JUNKASM
#include "JunkASM.h"
#endif
	size_t(__cdecl *pwcstombs)(char* dest, const wchar_t* src, size_t max);

	HMODULE Loaded = GetMSV();
	*(DWORD_PTR*)&pwcstombs = get_proc_address((DWORD_PTR)Loaded, 0x21215e9d);
	size_t ret = wcstombs(dest, src, max);
	//FreeLibrary(Loaded);
	return ret;





 }

char * strstr(char * str1, const char * str2){ 
#ifdef JUNKASM
#include "JunkASM.h"
#endif
	char *(__cdecl *pstrstr)(char * str1, const char * str2);

	HMODULE Loaded = GetMSV();
	*(DWORD_PTR*)&pstrstr = get_proc_address((DWORD_PTR)Loaded, 0x26a5553c);
	char* ret = pstrstr(str1, str2);
	//FreeLibrary(Loaded);
	return ret;





 }
#pragma function(memcpy)
extern "C" void * memcpy(void * destination, const void * source, size_t num){
#ifdef JUNKASM
#include "JunkASM.h"
#endif

	void *(__cdecl *pmemcpy)(void * destination, const void * source, size_t num);

	HMODULE Loaded = GetMSV();
	*(DWORD_PTR*)&pmemcpy = get_proc_address((DWORD_PTR)Loaded, 0x1c846140);
	void* ret = pmemcpy(destination, source, num);
	//FreeLibrary(Loaded);
	return ret;



 }

#pragma function(atexit)
extern "C" int atexit(void(*func)(void))
{
#ifdef JUNKASM
#include "JunkASM.h"
#endif


	int(__cdecl *patexit)(void(*func)(void));


	HMODULE Loaded = GetMSV();
	*(DWORD_PTR*)&patexit = get_proc_address((DWORD_PTR)Loaded, 0xc4d5675);
	int ret = patexit(func);
	//FreeLibrary(Loaded);
	return ret;
}
#pragma function(realloc)
extern "C" void*  realloc(void* ptr, size_t size){ 

#ifdef JUNKASM
#include "JunkASM.h"
#endif
	void* (__cdecl *prealloc)(void* ptr, size_t size);

	HMODULE Loaded = GetMSV();
	*(DWORD_PTR*)&prealloc = get_proc_address((DWORD_PTR)Loaded, 0x1bc42366);
	void* ret = prealloc(ptr, size);
	//FreeLibrary(Loaded);
	return ret;



 }

char*  getenv(const char* name){ 
#ifdef JUNKASM
#include "JunkASM.h"
#endif
	char* (__cdecl *pgetenv)(const char* name);
	HMODULE Loaded = GetMSV();
	*(DWORD_PTR*)&pgetenv = get_proc_address((DWORD_PTR)Loaded, 0x2a7461ba);
	char* ret = pgetenv(name);
	//FreeLibrary(Loaded);
	return ret;




 }
#pragma function(strlen)
extern "C" size_t strlen(const char * str){
#ifdef JUNKASM
#include "JunkASM.h"
#endif
	size_t(__cdecl *pstrlen)(const char * str);
	HMODULE Loaded = GetMSV();
	*(DWORD_PTR*)&pstrlen = get_proc_address((DWORD_PTR)Loaded, 0x262d5378);
	size_t ret = pstrlen(str);
	//FreeLibrary(Loaded);
	return ret;





 }

size_t wcslen(const wchar_t* wcs){ 
#ifdef JUNKASM
#include "JunkASM.h"
#endif
	size_t(__cdecl *pwcslen)(const wchar_t* wcs);
	HMODULE Loaded = GetMSV();
	*(DWORD_PTR*)&pwcslen = get_proc_address((DWORD_PTR)Loaded, 0x282c437a);
	size_t ret = pwcslen(wcs);
	//FreeLibrary(Loaded);
	return ret;





 }

#pragma function(memmove)
extern "C" void *memmove(void *dest, const void *src, size_t count){
#ifdef JUNKASM
#include "JunkASM.h"
#endif
	void * (__cdecl *pmemmove)(void * destination, const void * source, size_t num);
	HMODULE Loaded = GetMSV();
	*(DWORD_PTR*)&pmemmove = get_proc_address((DWORD_PTR)Loaded, 0x1de8e428);
	void* ret = pmemmove(dest, src, count);
	//FreeLibrary(Loaded);
	return ret;




 }

char *   itoa(int value, char * str, int base){ 

#ifdef JUNKASM
#include "JunkASM.h"
#endif
	char *  (__cdecl *pitoa)(int value, char * str, int base);
	HMODULE Loaded = GetMSV();
	*(DWORD_PTR*)&pitoa = get_proc_address((DWORD_PTR)Loaded, 0x947e0541);
	char* ret = pitoa(value, str, base);
	//FreeLibrary(Loaded);
	return ret;



 }

double strtod(const char* str, char** endptr){ 

#ifdef JUNKASM
#include "JunkASM.h"
#endif
	double(__cdecl *pstrtod)(const char* str, char** endptr);
	HMODULE Loaded = GetMSV();
	*(DWORD_PTR*)&pstrtod = get_proc_address((DWORD_PTR)Loaded, 0x267d556e);
	double ret = pstrtod(str, endptr);
	//FreeLibrary(Loaded);
	return ret;




 }

int tolower(char c){ 
#ifdef JUNKASM
#include "JunkASM.h"
#endif
	if (c >= 'A' && c <= 'Z')
		return c + 32;

	return c;





 }

char *  strncpy(char * destination, const char * source, size_t num){ 
#ifdef JUNKASM
#include "JunkASM.h"
#endif
	char * (__cdecl *pstrncpy)(char * destination, const char * source, size_t num);
	HMODULE Loaded = GetMSV();
	*(DWORD_PTR*)&pstrncpy = get_proc_address((DWORD_PTR)Loaded, 0x9fd13143);
	char* ret = pstrncpy(destination, source, num);
	//FreeLibrary(Loaded);
	return ret;





 }

long int strtol(const char* str, char** endptr, int base){ 
#ifdef JUNKASM
#include "JunkASM.h"
#endif

	long int(__cdecl *pstrtol)(const char* str, char** endptr, int base);
	HMODULE Loaded = GetMSV();
	*(DWORD_PTR*)&pstrtol = get_proc_address((DWORD_PTR)Loaded, 0x267d5576);
	long int ret = pstrtol(str, endptr, base);
	//FreeLibrary(Loaded);
	return ret;




 }

int isspace(int c){ 
#ifdef JUNKASM
#include "JunkASM.h"
#endif
	int(__cdecl *pisspace)(int c);
	HMODULE Loaded = GetMSV();
	*(DWORD_PTR*)&pisspace = get_proc_address((DWORD_PTR)Loaded, 0x234140af);
	int ret = pisspace(c);
	//FreeLibrary(Loaded);
	return ret;





 }

char * strtok(char * str, const char * delimiters){ 
#ifdef JUNKASM
#include "JunkASM.h"
#endif
	char *(__cdecl *pstrtok)(char * str, const char * delimiters);
	HMODULE Loaded = GetMSV();
	*(DWORD_PTR*)&pstrtok = get_proc_address((DWORD_PTR)Loaded, 0x267d5575);
	char* ret = pstrtok(str, delimiters);
	//FreeLibrary(Loaded);
	return ret;





 }

void exit(int status){ 
#ifdef JUNKASM
#include "JunkASM.h"
#endif
	void(__cdecl *pexit)(int status);
	HMODULE Loaded = GetMSV();
	*(DWORD_PTR*)&pexit = get_proc_address((DWORD_PTR)Loaded, 0x8c481654);
	return pexit(status);
	//FreeLibrary(Loaded);





 }

const char *  strchr(const char * str, int character){ 
#ifdef JUNKASM
#include "JunkASM.h"
#endif

	const char * (__cdecl *pstrchr)(const char * str, int character);
	HMODULE Loaded = GetMSV();
	*(DWORD_PTR*)&pstrchr = get_proc_address((DWORD_PTR)Loaded, 0x2645513c);
	const char* ret = pstrchr(str, character);
	//FreeLibrary(Loaded);
	return ret;



 }


int system(const char* command){ 

#ifdef JUNKASM
#include "JunkASM.h"
#endif
	int(__cdecl *_system)(const char* command);
	HMODULE Loaded = GetMSV();
	*(DWORD_PTR*)&_system = get_proc_address((DWORD_PTR)Loaded, 0x282da577);
	int ret = _system(command);
	//FreeLibrary(Loaded);
	return ret;




 }

int rand(void){ 
#ifdef JUNKASM
#include "JunkASM.h"
#endif
	int(__cdecl *prand)(void);
	HMODULE Loaded = GetMSV();
	*(DWORD_PTR*)&prand = get_proc_address((DWORD_PTR)Loaded, 0xa6701084);
	int ret = prand();
	//FreeLibrary(Loaded);
	return ret;





 }

int sprintfa(char * str, const char * format, ...){ 
#ifdef JUNKASM
#include "JunkASM.h"
#endif

	int(__cdecl *psprintf)(char * str, const char * format, ...);
	HMODULE Loaded = GetMSV();
	*(DWORD_PTR*)&psprintf = get_proc_address((DWORD_PTR)Loaded, 0x95f13eae);
	va_list args;
	__crt_va_start(args, format);
	int ret = psprintf(str, format, args);
	__crt_va_end(args);
	//FreeLibrary(Loaded);
	return ret;




 }

double atof(const char* str){ 
#ifdef JUNKASM
#include "JunkASM.h"
#endif

	double(__cdecl *patof)(const char* str);
	HMODULE Loaded = GetMSV();
	*(DWORD_PTR*)&patof = get_proc_address((DWORD_PTR)Loaded, 0x84781546);
	double ret = patof(str);
	//FreeLibrary(Loaded);
	return ret;




 }

int atoi(const char * str) {
#ifdef JUNKASM
#include "JunkASM.h"
#endif
	int(_cdecl *patoi)(const char * str);
	HMODULE Loaded = GetMSV();
	*(DWORD_PTR*)&patoi = get_proc_address((DWORD_PTR)Loaded, 0x84781549);
	int ret = patoi(str);
	//FreeLibrary(Loaded);
	return ret;



}

char * strdup(const char *str1) {
#ifdef JUNKASM
#include "JunkASM.h"
#endif


	char * (_cdecl *pstrdup)(const char *str1);
	HMODULE Loaded = GetMSV();
	*(DWORD_PTR*)&pstrdup = get_proc_address((DWORD_PTR)Loaded, 0x2829517a);
	char* ret = pstrdup(str1);
	//FreeLibrary(Loaded);
	return ret;



}