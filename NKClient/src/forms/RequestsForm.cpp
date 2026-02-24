#include "forms/RequestsForm.hpp"
#include "forms/MainBar.hpp"
#include "forms/FormManager.hpp"
#include <networking/UserManager.hpp>
#include <networking/FriendRequestsManager.hpp>
#include <networking/SessionManager.hpp>
#include <networking/NetworkManager.hpp>
#include <JsLogger.hpp>
#include <imgui.h>

std::unordered_set<int> RequestsForm::_userIds;
std::unordered_map<int, FriendRequestInfo> RequestsForm::_friendRequests;
std::unordered_map<int, UserInfo> RequestsForm::_users;
void RequestsForm::Create(){
    FormManager::SubscribeOpen("RequestsForm", &RequestsForm::Open);
    FormManager::SubscribeRender("RequestsForm", &RequestsForm::Render);
    FriendRequestsManager::Subscribe(&RequestsForm::AddFriendRequest);
    UserManager::Subscribe(&RequestsForm::AddUserInfo);
}

void RequestsForm::Destroy(){
    FormManager::UnsubscribeOpen("RequestsForm");
    FormManager::UnsubscribeRender("RequestsForm");
}

void RequestsForm::Open(){
    MainBar::Open();
}

void RequestsForm::Render()
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
        ImGui::Text("Friend requests");
        ImGui::Separator();
        ImGui::Spacing();

        if (_friendRequests.empty())
        {
            ImGui::Text("No requests");
        }
        else
        {
            for (auto& [requestId, request] : _friendRequests)
            {
                auto userIt = _users.find(request.SenderId);
                if (userIt == _users.end())
                    continue;

                const UserInfo& user = userIt->second;

                ImGui::PushID(requestId);

                std::string name = user.UserName + "#" + std::to_string(user.UserTag);
                ImGui::Text("%s", name.c_str());
                ImGui::SameLine();

                const char* statusText = "";
                switch (request.StatusCode)
                {
                    case FriendRequestStatus::PENDING:
                        statusText = "Pending";
                        break;
                    case FriendRequestStatus::ACCEPTED:
                        statusText = "Accepted";
                        break;
                    case FriendRequestStatus::DENIED:
                        statusText = "Denied";
                        break;
                }

                ImGui::TextDisabled("[%s]", statusText);

                if (request.StatusCode == FriendRequestStatus::PENDING)
                {

                    ImGui::BeginGroup();
                    ImGui::SameLine(300);
                    if (ImGui::Button("Accept"))
                    {
                        NetworkManager::AcceptFriendRequest(request.RequestId);
                    }

                    ImGui::SameLine();

                    if (ImGui::Button("Deny"))
                    {
                        NetworkManager::DenyFriendRequest(request.RequestId);
                    }

                    ImGui::SameLine();

                    if (ImGui::Button("Block"))
                    {
                        NetworkManager::BlockUser(user.UserId);
                    }
                    
                    ImGui::EndGroup();
                }
                else if (request.StatusCode == FriendRequestStatus::DENIED)
                {
                    if (ImGui::Button("Block"))
                    {
                        NetworkManager::BlockUser(user.UserId);
                    }
                }

                ImGui::PopID();
            }
        }
    }

    ImGui::EndChild();
    ImGui::End();
}

void RequestsForm::AddFriendRequest(const FriendRequestInfo& request){
    _friendRequests[request.RequestId] = request;
    
    UserInfo user;
    if(UserManager::GetUserInfo(request.SenderId, user)){
        _users[request.SenderId] = user;
    }else{
        _userIds.insert(request.SenderId);
    }
}

void RequestsForm::AddUserInfo(const UserInfo& user){
    auto it = _userIds.find(user.UserId);
    if(it != _userIds.end()){
        _users[user.UserId] = user;
        _userIds.erase(it);
    }
}
