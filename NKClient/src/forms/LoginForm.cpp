#include "forms/LoginForm.hpp"
#include "forms/FormManager.hpp"
#include "forms/ErrorReg.hpp"
#include "networking/NetworkManager.hpp"
#include "networking/SessionManager.hpp"
#include "networking/RequestManager.hpp"
#include "networking/UserManager.hpp"
#include <imgui.h>
#include <cstring>
#include "nk_protocol.h"

std::string LoginForm::_errorMsg;
char LoginForm::_username[64] = {};
char LoginForm::_password[64] = {};
void LoginForm::Create(){
    FormManager::SubscribeOpen("LoginForm", &LoginForm::Open);
    FormManager::SubscribeRender("LoginForm", &LoginForm::Render);
    RequestManager::SubscribeErrorRequest(NK_OPCODE_LOGIN, &LoginForm::HandleError);
}

void LoginForm::Destroy(){
    FormManager::UnsubscribeOpen("LoginForm");
    FormManager::UnsubscribeRender("LoginForm");
    RequestManager::UnsubscribeErrorRequest(NK_OPCODE_LOGIN);
}

void LoginForm::Open(){

}

void LoginForm::Render()
{
    const ImGuiIO& io = ImGui::GetIO();

    ImGui::SetNextWindowPos(ImVec2(0.0f, 0.0f));
    ImGui::SetNextWindowSize(io.DisplaySize);

    ImGuiWindowFlags flags =
        ImGuiWindowFlags_NoDecoration |
        ImGuiWindowFlags_NoMove |
        ImGuiWindowFlags_NoResize |
        ImGuiWindowFlags_NoSavedSettings;

    ImGui::Begin("Login", nullptr, flags);

    const float panel_width  = 350.0f;
    const float panel_height = 160.0f;

    ImVec2 center = ImVec2(
        (io.DisplaySize.x - panel_width) * 0.5f,
        (io.DisplaySize.y - panel_height) * 0.5f
    );

    ImGui::SetCursorPos(center);
    ImGui::BeginChild("LoginPanel", ImVec2(panel_width, panel_height), true);

    ImGui::Text("Login");
    ImGui::Spacing();
    ImGui::Separator();
    ImGui::Spacing();

    ImGui::InputText("Username", _username, sizeof(_username));
    ImGui::InputText("Password", _password, sizeof(_password), ImGuiInputTextFlags_Password);

    ImGui::Spacing();
    ImGui::Text("%s", _errorMsg.c_str());
    ImGui::Spacing();

    float button_width = (panel_width - 30.0f) * 0.5f;

    if (ImGui::Button("Create account", ImVec2(button_width, 0.0f)))
    {
        Reset();
        FormManager::Open("RegistrationForm");
    }

    ImGui::SameLine();

    if (ImGui::Button("Login", ImVec2(button_width, 0.0f)))
    {
        UserManager::Login(_username, _password);
    }

    ImGui::EndChild();
    ImGui::End();
}

void LoginForm::HandleSuccess(){
    Reset();
    FormManager::Open("MainForm");
}

void LoginForm::HandleError(int errNo){
    ErrorReg::GetError(_errorMsg, errNo);
}

void LoginForm::Reset(){
    memset(_username, 0, sizeof(_username));
    memset(_password, 0, sizeof(_password));
    _errorMsg = "";
}
