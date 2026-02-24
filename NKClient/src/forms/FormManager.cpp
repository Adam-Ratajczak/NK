#include "forms/FormManager.hpp"
#include "forms/RegistrationForm.hpp"
#include "forms/LoginForm.hpp"
#include "forms/BlockedUsersForm.hpp"
#include "forms/FriendsForm.hpp"
#include "forms/MainBar.hpp"
#include "forms/RequestsForm.hpp"
#include "forms/MainForm.hpp"
#include "forms/UserForm.hpp"
#include "forms/ChannelForm.hpp"

std::string FormManager::_toRender;
std::unordered_map<std::string, FormActionDelegate> FormManager::_openSubscribers;
std::unordered_map<std::string, FormActionDelegate> FormManager::_renderSubscribers;
void FormManager::SubscribeOpen(const std::string& formName, FormActionDelegate delegate){
    _openSubscribers[formName] = delegate;
}

void FormManager::SubscribeRender(const std::string& formName, FormActionDelegate delegate){
    _renderSubscribers[formName] = delegate;
}

void FormManager::UnsubscribeOpen(const std::string& formName){
    if(_openSubscribers.find(formName) != _openSubscribers.end()){
        _openSubscribers.erase(formName);
    }
}

void FormManager::UnsubscribeRender(const std::string& formName){
    if(_renderSubscribers.find(formName) != _renderSubscribers.end()){
        _renderSubscribers.erase(formName);
    }
}

void FormManager::Create(){
    RegistrationForm::Create();
    LoginForm::Create();
    BlockedUsersForm::Create();
    FriendsForm::Create();
    MainBar::Create();
    RequestsForm::Create();
    MainForm::Create();
    UserForm::Create();
    ChannelForm::Create();
}

void FormManager::Destroy(){
    RegistrationForm::Destroy();
    LoginForm::Destroy();
    BlockedUsersForm::Destroy();
    FriendsForm::Destroy();
    MainBar::Destroy();
    RequestsForm::Destroy();
    MainForm::Destroy();
    UserForm::Destroy();
    ChannelForm::Destroy();
}

void FormManager::Open(const std::string& toRender){
    _toRender = toRender;
    if(_openSubscribers[_toRender]){
        _openSubscribers[_toRender]();
    }
}

void FormManager::Render(){
    if(_renderSubscribers[_toRender]){
        _renderSubscribers[_toRender]();
    }
}

std::string FormManager::CurrentForm(){
    return _toRender;
}
