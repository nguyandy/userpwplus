
#include <stdio.h>
#include <iostream>
#include <fstream>
#include <string>
#include <vector>

#include <termios.h>
#include <unistd.h>

#include <sys/types.h>
#include <pwd.h>

#include <shadow.h>
#include <crypt.h>

#include <string.h>

#define CONF_PATH "/etc/userpwplus/userpwplus.conf"
#define DIC_PATH "/etc/userpwplus/dictionary.list"
#define TRACK_PATH "/etc/userpwplus/pwtrack.list"

using namespace std;

// enable or disable console output
void echo(bool on = true) {
	struct termios settings;
	tcgetattr( STDIN_FILENO, &settings );
	settings.c_lflag = on
					? (settings.c_lflag |   ECHO )
					: (settings.c_lflag & ~(ECHO));
	tcsetattr( STDIN_FILENO, TCSANOW, &settings );
}

int _minLen = 12;
bool _checkDic = true;
bool _allowRepeat = false;

vector<string> _dictionary;
vector<string> _pwtrack;

// read configuration file and parse 
int readConfig() {
	ifstream ifs(CONF_PATH);
	if(ifs.is_open()) {
		string line1("");
		string line2("");
		string line3("");
		getline(ifs, line1);
		getline(ifs, line2);
		getline(ifs, line3);
		string tmp;
		if(line1.find("MinimumLength=")==0) {
			tmp = line1.substr(14);
			int itmp = stoi(tmp);
			if(itmp >= 3 && itmp <= 32) {
				_minLen = itmp;
			} else {
				_minLen = itmp < 3 ? 3 : 32;
			}
		}
		if(line2.find("DictionaryCheck=")==0) {
			tmp = line2.substr(16);
			_checkDic = tmp.compare("YES") == 0;
		}
		if(line3.find("RepeatPassword=")==0) {
			tmp = line2.substr(15);
			_allowRepeat = tmp.compare("YES") == 0;
		}
		ifs.close();
		return 0;
	} else {
		return 1;
	}
}

// read a words list file and returns vector
vector<string> readWordList(const char* filename) {
	vector<string> res;
	ifstream ifs(filename);
	if(ifs.is_open()) {
		string line;
		while(getline(ifs, line)) {
			res.push_back(line);
		}
		ifs.close();
	}
	return res;
}

// check if current password is correct
int checkCurrentPassword(const char* username, const char* password) {
    struct spwd *shadow_entry;
    char *p, *correct, *supplied, *salt;
	shadow_entry = getspnam(username);
    if (shadow_entry == NULL) return 1;
    correct = shadow_entry->sp_pwdp;
    /* Extract the salt. */
    salt = strdup(correct);

    if (salt == NULL) return 2;
    p = strchr(salt + 1, '$');
    if (p == NULL) return 2;
    p = strchr(p + 1, '$');
    if (p == NULL) return 2;
    p[1] = 0;
    // encrypt the supplied password with the salt and compare the results
    supplied = crypt(password, salt);
    if (supplied == NULL) return 2;

	int result = strcmp(supplied, correct);

	delete(salt);

    return result;
}

// get current username
string getCurrentUser() {
	struct passwd* pws;
	pws = getpwuid(getuid());
	return string(pws->pw_name);
}

// set user password by usernamd and password
int setUserPassword(const char* username, const char* password) {

	// read shadow database /etc/shadow
	ifstream ifs("/etc/shadow");
	vector<string> lines;
	if(ifs.is_open()) {
		string line;
		while(getline(ifs, line)) {
			lines.push_back(line);
		}
		ifs.close();
	} else {
		return 1;
	}

	bool done = false;
	for(int i = 0; i < lines.size(); i++) {
		char* p = (char*)lines[i].c_str();
		char* p1 = strchr(p, ':');
		if(p1 == NULL) continue;
		string name = lines[i].substr(0, (int)((long)p1-(long)p));
		if(name.compare(username) != 0) continue;

		// if the username is matched
		char* p2 = strchr(p1 + 1, ':');
		if(p2 == NULL) continue;

		// extract encrypted password
		long ip = (long)p;
		long ip1 = (long)p1;
		long ip2 = (long)p2;
		string pwent = lines[i].substr((int)(ip1-ip+1), (int)(ip2-ip1-1));
		string pre = lines[i].substr(0, (int)ip1-(int)ip+1);
		string suf = lines[i].substr((int)ip2-(int)ip, strlen(p)-(int)ip2+(int)ip+1);

		// extract salt value
		char* salt = strdup(pwent.c_str());
		if (salt == NULL) return 2;
		p = strchr(salt + 1, '$');
		if (p == NULL) return 2;
		p = strchr(p + 1, '$');
		if (p == NULL) return 2;
		p[1] = 0;
		
		// encrypt the supplied password with the salt 
		char* new_epwd = crypt(password, salt);

		delete salt;

		lines[i] = pre + string(new_epwd) + suf;

		done = true;
		break;
	}

	if(!done) {
		return 3;
	}

	// recreate shadow database with changed encrypted password
	ofstream ofs("/etc/shadow", ios_base::trunc);
	if(ofs.is_open()) {
		for(int j = 0; j < lines.size(); j++) {
			ofs << lines[j] << endl;
		}
		ofs.close();
	} else {
		return 1;
	}

	return 0;
}

// check password validation
int checkValidity(string pwd) {

	// check minimum length
	if(pwd.length() < _minLen) {
		return 1;
	} 

	int i;
	// check dictionary if enabled
	if(_checkDic) {
		for(i = 0; i < _dictionary.size(); i++) {
			if(pwd.compare(_dictionary[i])==0) return 2; 
		}
	}
	
	// check passwords track if enabled
	if(!_allowRepeat) {
		for(i = 0; i < _pwtrack.size(); i++) {
			if(pwd.compare(_pwtrack[i])==0) return 3; 
		}
	}

	return 0;
}

// append a word at the end of a word list file
int addWordToFile(string word, const char* filename) {
	ofstream ofs(filename, ios_base::app);
	if(ofs.is_open()) {
		ofs << word << endl;
		ofs.close();
	} else {
		return 1;
	}
	return 0;
}

int main(int argc, char* argv[]) {

	// read configuration
	readConfig();
	// extract dictionary data from file
	_dictionary = readWordList(DIC_PATH);
	// extract password track from file
	_pwtrack = readWordList(TRACK_PATH);

	// get current username
	string username = getCurrentUser();

	ifstream if_pwd("/etc/passwd");
	if(if_pwd.is_open()) {
		if_pwd.close();
	} else {
		cout << "Permission denied!" << endl;
		return -1;
	}

	// input current password
	cout << "Current password: ";
	string current_pwd = "";
	char ch;

	echo(false);
	getline(cin, current_pwd);
	echo(true);

	// check current password is correct
	if(checkCurrentPassword(username.c_str(), current_pwd.c_str()) != 0) {
		cout << endl << "Invalid password!" << endl;
		return -1;
	}

	string new_pwd;
	string confirm_pwd;

	int tries = 0;
	bool isValid = false;
	// try input new password for 3 times at maximum
	do{
		tries++;
		cout << endl << "New password: ";
		echo(false);
		getline(cin, new_pwd);
		echo(true);

		// check password validation
		int check = checkValidity(new_pwd);
		if(check == 0) {
			// if the new password is good
			isValid = true;
			break;
		} else {
			// if there is something wrong in new password
			if(check == 1) {
				cout << "\nThe password must be at least " << _minLen << " characters.\n";
			} else if(check == 2) {
				cout << "\nThe password is not allowed.\n";
			} else if(check == 3) {
				cout << "\nThe password has ever been used before.\n";
			} 

			if(tries == 3) break;
		} 
		
	} while(tries < 4);

	if(!isValid) {
		cout << "\nPassword not changed.\n";
		return 4;
	}

	// confirm password
	cout << endl << "Confirm new password: ";
	echo(false);
	getline(cin, confirm_pwd);
	echo(true);

	if(new_pwd.compare(confirm_pwd) != 0) {
		cout << endl << "Password mismatch! Try again." << endl;
		return -1;
	}

	// update shadow database with new password
	int res = setUserPassword(username.c_str(), new_pwd.c_str());

	if(res == 1) {
		cout << "\nPermission denied!" << endl;
		return 1;
	}

	// register new password into password track
	addWordToFile(new_pwd, TRACK_PATH);

	cout << "\nPassword updated successfully" << endl;
	return 0;
}
