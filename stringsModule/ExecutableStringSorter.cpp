#include <string>
#include <stdio.h>
#include <stdexcept>
#include <vector>
#include <iostream>
#include <fstream>

std::vector<std::string> stringsForExe(std::string fileName)
{
    char buffer[128];
    std::vector<std::string> result;
    std::string command = "strings " + fileName + " -nobanner";
    FILE* pipe = _popen(command.data(), "r");
    if (!pipe) throw std::runtime_error("popen() failed!");
    try
    {
        while (!feof(pipe))
        {
            if (fgets(buffer, 128, pipe) != NULL)
                result.push_back(buffer);
        }
    }
    catch (...)
    {
        _pclose(pipe);
        throw;
    }
    _pclose(pipe);
    for (std::string& str : result) {
        str.erase(std::find(str.begin(), str.end(), '\n'));
    }
    return result;
}


int main(int argc, char* argv[])
{
	// load the probality matrix from probabilty_matrix_data.txt
	int probalityMatrix[95][95]; //every data point is the ASCII value -32 

	std::string line;
	int threshold;
	std::fstream myFile("probabilty_matrix_data.txt");

	if (myFile.is_open()) {
		std::istream& x = getline(myFile, line);  //first line is the threshold
		threshold = std::stoi(line);
		for (int i = 0; i < 95; i++)
		{
			for (int j = 0; j < 95; j++) {
				std::istream& n = getline(myFile, line);
				probalityMatrix[i][j] = std::stoi(line);
			}
		}
		myFile.close();
	}
	else { std::cout << "can't open probabilty_matrix_data.txt" << std::endl; }

	//evaluate the given strings from inputed executable
	std::string fileName;
	if (argc > 1) {
		fileName = argv[1];
	}
	else {
		std::cout << "Enter executable name: " << std::endl;
		std::cin >> fileName;
	}
	std::vector<std::string> fileStrings = stringsForExe(fileName);

	std::vector<std::string> valuedFileStrings; //the non garbage strings from the file

	for (std::string& str : fileStrings) {
		int sum = 0;
		for (int i = 0; i < str.length() - 1; i++)
		{
			sum += probalityMatrix[int(str[i]) - 32][int(str[i + 1]) - 32];
		}
		if (sum >= threshold) {
			valuedFileStrings.push_back(str);
		}
	}

	std::ofstream filteredStrings("filtered_strings.txt", std::ios::out | std::ios::trunc);
	std::ofstream selectedStrings("selected_strings.txt", std::ios::out | std::ios::trunc);

	std::vector<std::string> dictionaryStrings;
	std::fstream wordsFile("words.txt");

	if (wordsFile.is_open()) {
		while (getline(wordsFile, line)) {
			dictionaryStrings.push_back(line);
		}
		myFile.close();
	}
	else { std::cout << "can't open words.txt" << std::endl; }

	for (std::string& currentStr : valuedFileStrings) {
		for (std::string currentWord : dictionaryStrings) {
			if (currentStr.find(currentWord) != std::string::npos) {
				selectedStrings << currentStr << std::endl;
				//std::cout << currentStr << " ,found string: " << currentWord << std::endl;
				break;
			}
		}
		filteredStrings << currentStr << std::endl;
	}
	filteredStrings.close();
	selectedStrings.close();

	return 0;
}