#include "forms/BlockedUsersForm.hpp"
#include "forms/MainBar.hpp"
#include "forms/FormManager.hpp"
#include <networking/UserManager.hpp>
#include <networking/SessionManager.hpp>
#include <networking/NetworkManager.hpp>
#include <networking/UserRelationsManager.hpp>
#include <imgui.h>

std::unordered_set<int> BlockedUsersForm::_blockedUserIds;
std::unordered_map<int, UserInfo> BlockedUsersForm::_blockedUsers;
void BlockedUsersForm::Create(){
    FormManager::SubscribeOpen("BlockedUsersForm", &BlockedUsersForm::Open);
    FormManager::SubscribeRender("BlockedUsersForm", &BlockedUsersForm::Render);
    UserManager::Subscribe(&BlockedUsersForm::AddUserInfo);
    UserRelationsManager::Subscribe(&BlockedUsersForm::AddBlockedUser);
}

void BlockedUsersForm::Destroy(){
    FormManager::UnsubscribeOpen("BlockedUsersForm");
    FormManager::UnsubscribeRender("BlockedUsersForm");
}

void BlockedUsersForm::Open(){
    MainBar::Open();
}

void BlockedUsersForm::Render()
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
        ImGui::Text("Blocked users");
        ImGui::Separator();
        ImGui::Spacing();

        if (_blockedUsers.empty())
        {
            ImGui::Text("No blocked users");
        }
        else
        {
            for (auto& [id, user] : _blockedUsers)
            {
                ImGui::PushID(id);

                std::string label =
                    user.UserName + "#" + std::to_string(user.UserTag);

                ImGui::Text("%s", label.c_str());
                ImGui::BeginGroup();
                ImGui::SameLine(300);

                if (ImGui::Button("Unblock"))
                {
                    NetworkManager::ResetRelation(user.UserId);
                }
                ImGui::EndGroup();

                ImGui::PopID();
            }
        }
    }

    ImGui::EndChild();
    ImGui::End();
}

void BlockedUsersForm::AddBlockedUser(const UserRelationInfo& userRelation){
    if(userRelation.StatusCode == UserRelationStatus::BLOCKED){
        UserInfo user;
        if(UserManager::GetUserInfo(userRelation.RecipentId, user)){
            _blockedUsers[userRelation.RecipentId] = user;
        }else{
            _blockedUserIds.insert(userRelation.RecipentId);
        }
    }else{
        auto itBl = _blockedUserIds.find(userRelation.RecipentId);
        if(itBl != _blockedUserIds.end()){
            _blockedUserIds.erase(itBl);
        }
        auto itUser = _blockedUsers.find(userRelation.RecipentId);
        if(itUser != _blockedUsers.end()){
            _blockedUsers.erase(itUser);
        }
    }
}

void BlockedUsersForm::AddUserInfo(const UserInfo& user){
    auto it = _blockedUserIds.find(user.UserId);
    if(it != _blockedUserIds.end()){
        _blockedUsers[user.UserId] = user;
        _blockedUserIds.erase(it);
    }
}
