#include "..\external signature scanner\scanner\scanner.h"

int main()
{

	std::string signature = "\xba\x00\x00\x00\x00\xcd\x00\xb8"s; // signature (add s after the " of the string)
	std::string mask = "x????x?x"; // mask
	int procressid = 8244;

	scanner scannerscanner(procressid);

	auto address = scannerscanner.findsignature(signature, mask); // return the first addres that the scanner found

	if (address == 0) // if the function return 0, then no addreses were found
	{
		std::cout << "no addres were found\n";
	}
	else
	{
		// print the first address that the scanner found
		std::cout << "first address found at \n";
		std::cout << std::dec << "decimal address: " << address << "\n";
		std::cout << std::hex << "heximal address address: " << address << std::dec << "\n";
		std::cout << "\n";

		// retrieve all addreses that the scanner found
		// all addres found by the scanner get stored in a uintptr_t vector
		// this code will iterate thought the whole vector
		for (auto& looploop : scannerscanner.returnaddreses())
		{
			std::cout << std::dec << "decimal address: " << looploop << "\n";
			std::cout << std::hex << "heximal address address: " << looploop << std::dec << "\n";
			std::cout << "\n";
		}
	}

	

	std::cin.get();

}
