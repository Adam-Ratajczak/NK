#include "forms/UserForm.hpp"
#include "forms/MainBar.hpp"
#include "forms/FormManager.hpp"
#include <networking/UserManager.hpp>
#include <networking/NetworkManager.hpp>
#include <networking/SessionManager.hpp>
#include <networking/RequestManager.hpp>
#include <imgui.h>
#include "nk_protocol.h"
#include <forms/ErrorReg.hpp>

std::string UserForm::_errorMsg;
char UserForm::_username[64] = {};
char UserForm::_password[64] = {};
char UserForm::_repeatPassword[64] = {};
bool UserForm::_shouldLogOut = false;
void UserForm::Create(){
    FormManager::SubscribeOpen("UserForm", &UserForm::Open);
    FormManager::SubscribeRender("UserForm", &UserForm::Render);
    RequestManager::SubscribeOkRequest(NK_OPCODE_UPDATE_USER_DATA, &UserForm::OnUserDataChangeSuccess);
    RequestManager::SubscribeOkRequest(NK_OPCODE_LOGOUT, &UserForm::OnLogoutSuccess);
    RequestManager::SubscribeOkRequest(NK_OPCODE_UNREGISTER, &UserForm::OnLogoutSuccess);
    RequestManager::SubscribeErrorRequest(NK_OPCODE_UNREGISTER, &UserForm::OnError);
}

void UserForm::Destroy(){
    FormManager::UnsubscribeOpen("UserForm");
    FormManager::UnsubscribeRender("UserForm");
    RequestManager::UnsubscribeOkRequest(NK_OPCODE_UPDATE_USER_DATA);
    RequestManager::UnsubscribeOkRequest(NK_OPCODE_LOGOUT);
    RequestManager::UnsubscribeOkRequest(NK_OPCODE_UNREGISTER);
    RequestManager::UnsubscribeErrorRequest(NK_OPCODE_UNREGISTER);
}

void UserForm::Open(){
    MainBar::Open();
}

void UserForm::Render()
{
    const ImGuiIO& io = ImGui::GetIO();

    ImGui::SetNextWindowPos(ImVec2(0.0f, 0.0f));
    ImGui::SetNextWindowSize(io.DisplaySize);

    ImGuiWindowFlags flags =
        ImGuiWindowFlags_NoDecoration |
        ImGuiWindowFlags_NoMove |
        ImGuiWindowFlags_NoResize |
        ImGuiWindowFlags_NoSavedSettings;

    ImGui::Begin("NK", nullptr, flags);

    MainBar::Render();

    const float panel_width  = 800.0f;
    const float panel_height = 600.0f;

    ImVec2 center = ImVec2(
        (io.DisplaySize.x - panel_width) * 0.5f,
        (io.DisplaySize.y - panel_height) * 0.5f
    );

    ImGui::SetCursorPos(center);

    if (ImGui::BeginChild("MainPanel", ImVec2(panel_width, panel_height), true))
    {
        ImGui::Text("User settings");
        ImGui::Separator();
        ImGui::Spacing();

        ImGui::Text("Username");
        ImGui::InputText("##username", _username, sizeof(_username));
        ImGui::SameLine();
        if (ImGui::Button("Change username"))
        {
            bool hasError = false;
            if(!hasError && strlen(_username) == 0){
                _errorMsg = "username cannot be empty.";
                hasError = true;
            }

            if(!hasError){
                _shouldLogOut = true;
                NetworkManager::ChangeUsername(_username);
            }
        }

        ImGui::Spacing();
        ImGui::Separator();
        ImGui::Spacing();

        ImGui::Text("Change password");

        ImGui::InputText("Password", _password, sizeof(_password), ImGuiInputTextFlags_Password);

        ImGui::InputText("Repeat password", _repeatPassword, sizeof(_repeatPassword), ImGuiInputTextFlags_Password);

        if (ImGui::Button("Change password"))
        {
            bool hasError = false;
            if(!hasError && strcmp(_password, _repeatPassword) != 0){
                _errorMsg = "Passwords don't match!";
                hasError = true;
            }

            if(!hasError && strlen(_password) < 8){
                _errorMsg = "Password must have at least 8 characters.";
                hasError = true;
            }

            if(!hasError && !PasswordValid(_password)){
                _errorMsg = "Password must have an uppercase letter, number and symbol.";
                hasError = true;
            }

            if(!hasError){
                _shouldLogOut = true;
                NetworkManager::ChangePassword(_password);
            }
        }

        ImGui::Spacing();
        ImGui::Separator();
        ImGui::Spacing();

        if (ImGui::Button("Randomize tag"))
        {
            NetworkManager::RandomizeUserTag();
        }

        ImGui::Spacing();
        ImGui::Separator();
        ImGui::Spacing();

        if (ImGui::Button("Logout"))
        {
            NetworkManager::Logout();
        }

        ImGui::SameLine();

        if (ImGui::Button("Unregister"))
        {
            NetworkManager::Unregister();
        }

        ImGui::Text(_errorMsg.c_str());
    }

    ImGui::EndChild();
    ImGui::End();
}

bool UserForm::PasswordValid(const std::string& password){
    bool has_capital = false;
    bool has_lowercase = false;
    bool has_number = false;
    bool has_symbol = false;

    for (unsigned char c : password)
    {
        if (std::isupper(c))
            has_capital = true;
        else if (std::islower(c))
            has_lowercase = true;
        else if (std::isdigit(c))
            has_number = true;
        else
            has_symbol = true;
    }

    return has_capital && has_lowercase && has_number && has_symbol;
}

void UserForm::Reset(){
    memset(_username, 0, sizeof(_username));
    memset(_password, 0, sizeof(_password));
    memset(_repeatPassword, 0, sizeof(_repeatPassword));
    _errorMsg = "";
    _shouldLogOut = false;
}

void UserForm::OnUserDataChangeSuccess(){
    if(_shouldLogOut){
        NetworkManager::Logout();
    }
    Reset();
}

void UserForm::OnLogoutSuccess(){
    FormManager::Open("LoginForm");
}

void UserForm::OnError(int errNo){
    ErrorReg::GetError(_errorMsg, errNo);
}
