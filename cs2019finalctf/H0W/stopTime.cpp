#include <iostream>
#include <ctime>

using namespace std;
int main(){
	unsigned int cnt = 4000000;
	for(int i=0;;i++){
		if(i % cnt == 0){
			system("date 2019-9-11");
			system("time 13:25:14");
			cout << "set\n";
		}
		
	}
	
}