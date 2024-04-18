#include <iostream>
#include <Windows.h>
#include <TlHelp32.h>
#include <memory>
#include <string_view>
#include <cstdint>
#include <vector>
#include <chrono>
#include <string>
#include <thread>
#include <ctime>

#include "menu.h"
#include "helper.hpp"
#include "nt.hpp"
#include "cpudef.hpp"
#include "evo.h"
#define good(msg, ...) printf("[+] " msg "\n", ##__VA_ARGS__)
#define info(msg, ...) printf("[*] " msg "\n", ##__VA_ARGS__)
#define warn(msg, ...) printf("[-] " msg "\n", ##__VA_ARGS__)

inline uint16_t page_offset;

std::string s{ "" };


void getTime(std::string program) {
	auto currentTime = std::chrono::system_clock::now();

	// Convert the current time to a time_t object
	std::time_t currentTime_t = std::chrono::system_clock::to_time_t(currentTime);

	// Declare a tm struct to store the local time
	std::tm localTime;

	// Use localtime_s to convert the time_t object to local time
	if (localtime_s(&localTime, &currentTime_t) == 0) {
		// Print the current date
		std::cout << program << " @ "
			<< (localTime.tm_year + 1900) << " " << (localTime.tm_mon + 1) << " " << localTime.tm_mday
			<< "\n\n";
	}
	else {
		// Handle error
		std::cerr << "Failed to get local time." << std::endl;
	}
}
int main()
{
	getTime("EVO_UTIL");
	std::string module;
	std::thread(menu).detach();
	
	

	while (1) {}
}