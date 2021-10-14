#include <Windows.h>
#include "Injection.h"
#include <iostream>
#include <filesystem>
#include <atlconv.h>

int main(int argc, char* argv[])
{
	USES_CONVERSION;
	if (argc < 2)
	{
		printf_s("./InjectProc.exe proc_rpl path/to/target/exe path/to/exe\n\
		");
	}

	ProcessReplacement(A2T(argv[2]), A2T(argv[3]));
	return EXIT_SUCCESS;
}