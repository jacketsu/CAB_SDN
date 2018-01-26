#include "CABcython.h"
#include <time.h>
#include <iostream>
#include <stdlib.h>

using namespace std;

int main(){
    CABcython ca("../metadata/ruleset/acl_8000", 40);
    srand(time(NULL));

    for (int i = 0; i < 5; ++i){
        vector<unsigned long> query;

        for (int j = 0; j < 4; ++j){
            query.push_back(rand());
        }

        auto res = ca.queryBTree(query);

        int cnt = 0;
        for (auto k : res){
            if (cnt == 0)
                cout << "(";

            ++cnt;

            if (cnt == 8){
                cout << k << "); ";
                cnt = 0;
            }
            else
                cout << k << ", ";
        }
        cout << endl;
    }
}
