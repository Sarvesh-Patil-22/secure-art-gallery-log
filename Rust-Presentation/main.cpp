#include <iostream>
#include <vector>



int main(){


    std::vector<int> vec = {1,2,3};
    int x = vec[10]; // Undefined Behavior, Out of bounds
    std::cout << "x= " << x << std::endl;


    int y = 5;
    y += 1; // Mutable by default
    const int y2 = 5;
    // y2 += 1; // error: immutable by const


    // use-after-free, undefined behavior
    std::vector<int>* v = new std::vector<int>{1, 2, 3};
    // delete v;
    std::cout << "v= " << (*v)[0] << std::endl; // caught during runtime


    // uninitialized variables
    int k;                                // Undefined Behavior
    std::cout << "k= " << k << std::endl; // prints random value

}