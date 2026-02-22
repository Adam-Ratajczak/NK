#include "forms/MainBar.hpp"
#include "forms/FormManager.hpp"
#include <networking/UserManager.hpp>
#include <networking/SessionManager.hpp>
#include <imgui.h>

UserInfo MainBar::_selfUser;
void MainBar::Create(){
    UserManager::Subscribe(&MainBar::AddUser);
}

void MainBar::Destroy(){
    UserManager::Unsubscribe(&MainBar::AddUser);
}

void MainBar::Open(){
}

void MainBar::Render()
{
    const ImGuiIO& io = ImGui::GetIO();

    const float topHeight = 40.0f;

    if (ImGui::BeginChild("TopBar", ImVec2(0, topHeight), true))
    {
        std::string unameStr = _selfUser.UserName.empty()
        ? "Loading..."
        : _selfUser.UserName + "#" + std::to_string(_selfUser.UserTag);

        float btnWidth = 160.0f;

        if(ImGui::Button("Friend requests")){
            if(FormManager::CurrentForm() == "RequestsForm"){
                FormManager::Open("MainForm");
            }else{
                FormManager::Open("RequestsForm");
            }
        }
        ImGui::SameLine();
        
        if(ImGui::Button("Friends")){
            if(FormManager::CurrentForm() == "FriendsForm"){
                FormManager::Open("MainForm");
            }else{
                FormManager::Open("FriendsForm");
            }
        }
        ImGui::SameLine();
        
        if(ImGui::Button("Blocked users")){
            if(FormManager::CurrentForm() == "BlockedUsersForm"){
                FormManager::Open("MainForm");
            }else{
                FormManager::Open("BlockedUsersForm");
            }
        }
        ImGui::SameLine(
            ImGui::GetWindowContentRegionMax().x - btnWidth
        );

        if(ImGui::Button(unameStr.c_str(), ImVec2(btnWidth, 0))){
            if(FormManager::CurrentForm() == "UserForm"){
                FormManager::Open("MainForm");
            }else{
                FormManager::Open("UserForm");
            }
        }
    }
    ImGui::EndChild();

    ImGui::Spacing();
}

void MainBar::AddUser(const UserInfo& user){
    if(user.UserId == UserManager::UserId){
        _selfUser = user;
    }
}
