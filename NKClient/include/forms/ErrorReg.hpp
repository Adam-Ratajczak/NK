#pragma once
#include <string>

class ErrorReg{
public:
    static void GetError(std::string& errorMsg, int errNo);
};
