#include "forms/RegistrationForm.hpp"
#include "forms/FormManager.hpp"
#include "forms/ErrorReg.hpp"
#include "networking/NetworkManager.hpp"
#include "networking/RequestManager.hpp"
#include <imgui.h>
#include <cstring>
#include "nk_protocol.h"

std::string RegistrationForm::_errorMsg;
char RegistrationForm::_username[64] = {};
char RegistrationForm::_password[64] = {};
char RegistrationForm::_repeatPassword[64] = {};
void RegistrationForm::Create(){
    FormManager::SubscribeOpen("RegistrationForm", &RegistrationForm::Open);
    FormManager::SubscribeRender("RegistrationForm", &RegistrationForm::Render);
    RequestManager::SubscribeOkRequest(NK_OPCODE_REGISTER, &RegistrationForm::HandleSuccess);
    RequestManager::SubscribeErrorRequest(NK_OPCODE_REGISTER, &RegistrationForm::HandleError);
}

void RegistrationForm::Destroy(){
    FormManager::UnsubscribeOpen("RegistrationForm");
    FormManager::UnsubscribeRender("RegistrationForm");
    RequestManager::UnsubscribeOkRequest(NK_OPCODE_REGISTER);
    RequestManager::UnsubscribeErrorRequest(NK_OPCODE_REGISTER);
}

void RegistrationForm::Open(){

}

void RegistrationForm::Render()
{
    const ImGuiIO& io = ImGui::GetIO();

    ImGui::SetNextWindowPos(ImVec2(0.0f, 0.0f));
    ImGui::SetNextWindowSize(io.DisplaySize);

    ImGuiWindowFlags flags =
        ImGuiWindowFlags_NoDecoration |
        ImGuiWindowFlags_NoMove |
        ImGuiWindowFlags_NoResize |
        ImGuiWindowFlags_NoSavedSettings;

    ImGui::Begin("Register", nullptr, flags);

    const float panel_width  = 450.0f;
    const float panel_height = 160.0f;

    ImVec2 center = ImVec2(
        (io.DisplaySize.x - panel_width) * 0.5f,
        (io.DisplaySize.y - panel_height) * 0.5f
    );

    ImGui::SetCursorPos(center);
    ImGui::BeginChild("RegisterPanel", ImVec2(panel_width, panel_height), true);

    ImGui::Text("Register");
    ImGui::Spacing();
    ImGui::Separator();
    ImGui::Spacing();

    ImGui::InputText("Username", _username, sizeof(_username));
    ImGui::InputText("Password", _password, sizeof(_password), ImGuiInputTextFlags_Password);
    ImGui::InputText("Repeat password", _repeatPassword, sizeof(_repeatPassword), ImGuiInputTextFlags_Password);

    ImGui::Spacing();
    ImGui::Text("%s", _errorMsg.c_str());
    ImGui::Spacing();

    float button_width = (panel_width - 30.0f) * 0.5f;

    if (ImGui::Button("Login instead", ImVec2(button_width, 0.0f)))
    {
        FormManager::Open("LoginForm");
        Reset();
    }

    ImGui::SameLine();

    if (ImGui::Button("Register", ImVec2(button_width, 0.0f)))
    {
        bool hasError = false;
        if(!hasError && strlen(_username) == 0){
            _errorMsg = "username cannot be empty.";
            hasError = true;
        }

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
            NetworkManager::Register(_username, _password);
        }
    }

    ImGui::EndChild();
    ImGui::End();
}

void RegistrationForm::HandleSuccess(){
    FormManager::Open("LoginForm");
    Reset();
}

void RegistrationForm::HandleError(int errNo){
    ErrorReg::GetError(_errorMsg, errNo);
}

bool RegistrationForm::PasswordValid(const std::string& password){
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

void RegistrationForm::Reset(){
    memset(_username, 0, sizeof(_username));
    memset(_password, 0, sizeof(_password));
    memset(_repeatPassword, 0, sizeof(_repeatPassword));
    _errorMsg = "";
}
