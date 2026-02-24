#pragma once
#include <functional>
#include <unordered_map>

typedef std::function<void(const unsigned char*, int)> RequestDelegate;
typedef std::function<void()> OkRequestDelegate;
typedef std::function<void(int)> ErrorRequestDelegate;
class RequestManager {
public:
    static void Register();
    static void Unregister();

    static void SubscribeRequest(unsigned char opcode, RequestDelegate delegate);
    static void UnsubscribeRequest(unsigned char opcode);

    static void SubscribeOkRequest(unsigned char opcode, OkRequestDelegate delegate);
    static void UnsubscribeOkRequest(unsigned char opcode);

    static void SubscribeErrorRequest(unsigned char opcode, ErrorRequestDelegate delegate);
    static void UnsubscribeErrorRequest(unsigned char opcode);

    static void ProcessRequest(const unsigned char* data, int len);

private:
    static void ProcessHelloRequest(const unsigned char* data, int len);
    static void ProcessOkRequest(const unsigned char* data, int len);
    static void ProcessErrorRequest(const unsigned char* data, int len);
    static void ProcessRequestSaltResultRequest(const unsigned char* data, int len);
    static void ProcessLoginResultRequest(const unsigned char* data, int len);
    static void ProcessRequestDevicesResult(const unsigned char* data, int len);
    static void ProcessSyncUserDataRequest(const unsigned char* data, int len);
    static void ProcessSyncFriendRequestsRequest(const unsigned char* data, int len);
    static void ProcessSyncRelationsRequest(const unsigned char* data, int len);
    static void ProcessChannelRequestDMResultRequest(const unsigned char* data, int len);
    static void ProcessChannelRequestRecipentsResultRequest(const unsigned char* data, int len);
    static void ProcessChannelSubmitKeyResultRequest(const unsigned char* data, int len);
    static void ProcessSyncChannelKeysRequest(const unsigned char* data, int len);
    static void ProcessChannelMessageDeliverRequest(const unsigned char* data, int len);
    static void ProcessSyncChannelHistoryRequest(const unsigned char* data, int len);
    static void ProcessChannelTypingBroadcastRequest(const unsigned char* data, int len);

    static void ApplyOk(unsigned char opcode);
    static void ApplyError(unsigned char opcode, int errNo);

    static std::unordered_map<unsigned char, RequestDelegate> _requestSubscribers;
    static std::unordered_map<unsigned char, OkRequestDelegate> _okRequestSubscribers;
    static std::unordered_map<unsigned char, ErrorRequestDelegate> _errorRequestSubscribers;
};
