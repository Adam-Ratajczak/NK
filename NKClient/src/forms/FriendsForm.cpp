#include "forms/FriendsForm.hpp"
#include "forms/MainBar.hpp"
#include "forms/FormManager.hpp"
#include "forms/ChannelForm.hpp"
#include "forms/ErrorReg.hpp"
#include <networking/UserManager.hpp>
#include <networking/SessionManager.hpp>
#include <networking/UserRelationsManager.hpp>
#include <networking/NetworkManager.hpp>
#include <networking/RequestManager.hpp>
#include "networking/ChannelsManager.hpp"
#include <imgui.h>
#include "nk_protocol.h"

std::set<int> FriendsForm::_friendUserIds;
std::map<int, UserInfo> FriendsForm::_friendUsers;
std::string FriendsForm::_errorMsg;
void FriendsForm::Create(){
    FormManager::SubscribeOpen("FriendsForm", &FriendsForm::Open);
    FormManager::SubscribeRender("FriendsForm", &FriendsForm::Render);
    UserManager::Subscribe(&FriendsForm::AddUserInfo);
    UserRelationsManager::Subscribe(&FriendsForm::AddFriendUsers);
    ChannelsManager::SubscribeDM(&FriendsForm::OnDMChannelInfo);
    RequestManager::SubscribeOkRequest(NK_OPCODE_FRIEND_REQUEST, &FriendsForm::OnOkRequest);
    RequestManager::SubscribeErrorRequest(NK_OPCODE_FRIEND_REQUEST, &FriendsForm::OnErrorRequest);
}

void FriendsForm::Destroy(){
    FormManager::UnsubscribeOpen("FriendsForm");
    FormManager::UnsubscribeRender("FriendsForm");
}

void FriendsForm::Open(){
    MainBar::Open();
}

void FriendsForm::Render()
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
        static char friendInput[128] = {};

        ImGui::Text("Add friend");
        ImGui::InputText("##friend_input", friendInput, sizeof(friendInput));
        ImGui::SameLine();

        if (ImGui::Button("Send request"))
        {
            std::string input(friendInput);

            auto pos = input.find('#');
            if (pos != std::string::npos)
            {
                std::string uname = input.substr(0, pos);
                unsigned int tag = (unsigned int)std::stoi(input.substr(pos + 1));

                if (!uname.empty())
                {
                    NetworkManager::SendFriendRequest(uname, tag);
                    memset(friendInput, 0, sizeof(friendInput));
                }
            }
            ImGui::Text(_errorMsg.c_str());
        }
        ImGui::Spacing();
        ImGui::Separator();
        ImGui::Spacing();

        ImGui::Text("Friends");

        if (_friendUsers.empty())
        {
            ImGui::Text("No friends");
        }
        else
        {
            for (auto& [id, user] : _friendUsers)
            {
                ImGui::PushID(id);

                std::string label = user.UserName + "#" + std::to_string(user.UserTag);
                ImGui::Text("%s", label.c_str());

                ImGui::BeginGroup();
                ImGui::SameLine(300);

                if (ImGui::Button("Remove"))
                {
                    NetworkManager::ResetRelation(user.UserId);
                }

                ImGui::SameLine();

                if (ImGui::Button("Block"))
                {
                    NetworkManager::BlockUser(user.UserId);
                }

                ImGui::SameLine();

                if (ImGui::Button("Message"))
                {
                    DMChannelInfo DMChannel;
                    if(ChannelsManager::GetDMInfo(user.UserId, DMChannel)){
                        OnDMChannelInfo(DMChannel);
                    }
                }
                
                ImGui::EndGroup();

                ImGui::PopID();
            }
        }
    }

    ImGui::EndChild();
    ImGui::End();
}

void FriendsForm::AddFriendUsers(const UserRelationInfo& userRelation){
    if(userRelation.StatusCode == UserRelationStatus::FRIEND){
        UserInfo user;
        if(UserManager::GetUserInfo(userRelation.RecipentId, user)){
            _friendUsers[userRelation.RecipentId] = user;
        }else{
            _friendUserIds.insert(userRelation.RecipentId);
        }
    }else{
        auto itFr = _friendUserIds.find(userRelation.RecipentId);
        if(itFr != _friendUserIds.end()){
            _friendUserIds.erase(itFr);
        }
        auto itUser = _friendUsers.find(userRelation.RecipentId);
        if(itUser != _friendUsers.end()){
            _friendUsers.erase(itUser);
        }
    }
}

void FriendsForm::AddUserInfo(const UserInfo& user){
    auto it = _friendUserIds.find(user.UserId);
    if(it != _friendUserIds.end()){
        _friendUsers[user.UserId] = user;
        _friendUserIds.erase(it);
    }
}

void FriendsForm::OnDMChannelInfo(const DMChannelInfo& DMChannel){
    ChannelForm::ChannelInfo = DMChannel;
    FormManager::Open("ChannelForm");
}

void FriendsForm::OnOkRequest(){
    _errorMsg = "Friend request sent";
}

void FriendsForm::OnErrorRequest(int errNo){
    ErrorReg::GetError(_errorMsg, errNo);
}
