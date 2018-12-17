
#include <iostream>
#include <fstream>
#include <string>

using namespace std;

int main(int argc, char* argv[]) {
    if(argc != 2) {
        cout << "Invalid arguments!\nUsage: extractor <input file path>" << endl;
        return 1;
    }

    string content = "";

    ifstream ifs(argv[1]);
    if(ifs.is_open()) {

        ifs.seekg(0, ios::end);
        int size = ifs.tellg();
        ifs.seekg(0, ios::beg);

        cout << "#define TP_BIN_SIZE " << size << endl;
        cout << "char TP_BIN_DATA[] = {";

        char* buf = new char[size];

        ifs.read(buf, size);

        for(int i = 0; i < size; i++) {
            content += to_string((int)(buf[i]));
            if(i < size - 1) content += ",";
        }

        delete[] buf;

        ifs.close();

    } else {
        cout << "Error! Could not open file " << argv[1] << endl;
        return 1;
    }

    cout << content << "};" << endl;

    return 0;
}