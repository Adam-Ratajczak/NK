#pragma once
#include <string>
#include <unordered_map>
#include <functional>

typedef std::function<void()> FormActionDelegate;
class FormManager{
public:
    static void SubscribeOpen(const std::string& formName, FormActionDelegate delegate);
    static void SubscribeRender(const std::string& formName, FormActionDelegate delegate);
    
    static void UnsubscribeOpen(const std::string& formName);
    static void UnsubscribeRender(const std::string& formName);

    static void Create();
    static void Destroy();
    static void Open(const std::string& toRender);
    static void Render();

    static std::string CurrentForm();
private:
    static std::string _toRender; 
    static std::unordered_map<std::string, FormActionDelegate> _openSubscribers;
    static std::unordered_map<std::string, FormActionDelegate> _renderSubscribers;
};
