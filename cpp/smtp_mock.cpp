#include <iostream>
#include <fstream>
#include <string>

/*
	Mock SMTP binary used for auth tests.
	Reads a virtual email from --input and writes it to --output.
*/

int main(int argc, char* argv[]) {
	std::string inputPath;
	std::string outputPath;

	for (int i = 1; i < argc; ++i) {
		std::string arg = argv[i];
		if (arg == "--input" && i + 1 < argc) {
			inputPath = argv[++i];
		} else if (arg == "--output" && i + 1 < argc) {
			outputPath = argv[++i];
		}
	}

	if (inputPath.empty() || outputPath.empty()) {
		std::cerr << "Usage: smtp_mock --input <file> --output <file>\n";
		return 1;
	}

	std::ifstream inFile(inputPath);
	if (!inFile.is_open()) {
		std::cerr << "Failed to open input file: " << inputPath << "\n";
		return 1;
	}

	std::string content;
	std::string line;
	bool hasContent = false;

	while (std::getline(inFile, line)) {
		content += line + "\n";
		hasContent = true;
	}
	inFile.close();

	/* Return non-zero exit code if input is empty (required by TestSMTPMockNonZeroExit) */
	if (!hasContent || content.empty()) {
		std::cerr << "Input file is empty.\n";
		return 1;
	}

	std::ofstream outFile(outputPath);
	if (!outFile.is_open()) {
		std::cerr << "Failed to open output file: " << outputPath << "\n";
		return 1;
	}

	outFile << content;
	outFile.close();

	return 0;
}
