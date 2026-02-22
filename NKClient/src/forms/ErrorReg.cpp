#include "forms/ErrorReg.hpp"
#include "nk_protocol.h"
#include <cstdio>

void ErrorReg::GetError(std::string& errorMsg, int errNo){
    switch (errNo)
    {
    case NK_ERROR_AUTH_FAILED:
        errorMsg = "Authentication failed!";
        break;
    case NK_ERROR_INVALID_FRAME:
        errorMsg = "Invalid frame!";
        break;
    case NK_ERROR_USER_EXISTS:
        errorMsg = "User exists!";
        break;
    case NK_ERROR_INVALID_USER_OR_PASSWORD:
        errorMsg = "Invalid user or password!";
        break;
    case NK_ERROR_PERMISSION_DENIED:
        errorMsg = "Permission denied!";
        break;
    case NK_ERROR_USER_NOT_FOUND:
        errorMsg = "User doesn't exist!";
        break;
    case NK_ERROR_RECIPENT_CANNOT_BE_SENDER:
        errorMsg = "Recipent cannot be sender!";
        break;
    case NK_ERROR_INVALID_DEVICE:
        errorMsg = "Invalid device!";
        break;
    case NK_ERROR_DEVICE_NOT_READY:
        errorMsg = "Device not ready!";
        break;
    case NK_ERROR_NOTHING_TO_SEND:
        errorMsg = "Nothing to send!";
        break;
    case NK_ERROR_NOT_IMPLEMENTED:
        errorMsg = "Not implemented!";
        break;
    case NK_ERROR_INTERNAL:
        errorMsg = "Internal server error!";
        break;
    default:
        errorMsg = "";
        break;
    }
}
