#include "forms/ChannelForm.hpp"
#include "forms/FormManager.hpp"
#include "forms/MainBar.hpp"
#include "networking/UserManager.hpp"
#include "networking/ChannelKeysManager.hpp"
#include "networking/ChannelMessagesManager.hpp"
#include "networking/ChannelsManager.hpp"
#include "networking/NetworkManager.hpp"
#include <imgui.h>
#include "nk_protocol.h"

DMChannelInfo ChannelForm::ChannelInfo;
UserInfo ChannelForm::_recipent;
ChannelKeyInfo ChannelForm::_channelKey;
std::map<unsigned int, ChannelMessageInfo> ChannelForm::_messages;
char ChannelForm::_inputBuf[512] = {};
float ChannelForm::_lastTypingTime = 0.0f;
bool ChannelForm::_isTyping = false;
void ChannelForm::Create(){
    FormManager::SubscribeOpen("ChannelForm", &ChannelForm::Open);
    FormManager::SubscribeRender("ChannelForm", &ChannelForm::Render);
    UserManager::Subscribe(&ChannelForm::AddRecipent);
    ChannelKeysManager::Subscribe(&ChannelForm::AddChannelKey);
    ChannelMessagesManager::Subscribe(&ChannelForm::AddMessage);
}

void ChannelForm::Destroy(){
    FormManager::UnsubscribeOpen("ChannelForm");
    FormManager::UnsubscribeRender("ChannelForm");
}

void ChannelForm::Open(){
    MainBar::Open();
    UserManager::GetUserInfo(ChannelInfo.UserId, _recipent);
    ChannelKeyInfo key;
    if(ChannelKeysManager::GetActiveChannelKey(ChannelInfo.ChannelId, _channelKey)){
        AddChannelKey(key);
    }else{
        ChannelsManager::SyncWithChannel(ChannelInfo.ChannelId);
    }
}

void ChannelForm::Render()
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
        ImGui::Text("%s#%u", _recipent.UserName.c_str(), _recipent.UserTag);
        ImGui::Separator();

        ImGui::BeginChild("Messages", ImVec2(0, -80), false);

        // if (ImGui::GetScrollY() <= 0.0f) {
        //     if (!_messages.empty()) {
        //         auto oldest = _messages.begin()->second.MessageId;
        //         NetworkManager::RequestChannelHistory(
        //             ChannelInfo.ChannelId,
        //             oldest,
        //             25
        //         );
        //     }
        // }

        for (auto& [id, msg] : _messages) {
            std::string text;

            if(msg.ChannelId == ChannelInfo.ChannelId){
                if (msg.IsDecrypted) {
                    text = std::string(msg.Plaintext.begin(), msg.Plaintext.end());
                } else {
                    text = "[encrypted]";
                }

                ImGui::Text("[%u] %s", msg.SenderId, text.c_str());
            }
        }

        if (ImGui::GetScrollY() >= ImGui::GetScrollMaxY())
            ImGui::SetScrollHereY(1.0f);

        ImGui::EndChild();

        ImGui::Separator();

        ImGui::Text("typing...");

        ImGui::PushItemWidth(-80);

        bool edited = ImGui::InputText("##msg", _inputBuf, sizeof(_inputBuf));

        ImGui::PopItemWidth();
        ImGui::SameLine();

        if (ImGui::Button("Send", ImVec2(70, 0))) {
            size_t len = strlen(_inputBuf);
            if (len > 0) {
                if(_channelKey.ChannelId == ChannelInfo.ChannelId){
                    printf("Sending payload\n");
                    fflush(stdout);
                    NetworkManager::SendMessage(ChannelInfo.ChannelId, _inputBuf, _channelKey);
                }

                _inputBuf[0] = '\0';

                NetworkManager::StopTyping(ChannelInfo.ChannelId);
                _isTyping = false;
            }
        }

        float now = io.DeltaTime > 0 ? ImGui::GetTime() : 0;

        if (edited) {
            _lastTypingTime = now;

            if (!_isTyping) {
                NetworkManager::StartTyping(ChannelInfo.ChannelId);
                _isTyping = true;
            }
        }

        if (_isTyping && (now - _lastTypingTime) > 1.0f) {
            NetworkManager::StopTyping(ChannelInfo.ChannelId);
            _isTyping = false;
        }
    }

    ImGui::EndChild();
    ImGui::End();
}

void ChannelForm::AddRecipent(const UserInfo& user){
    if(user.UserId == ChannelInfo.UserId){
        _recipent = user;
    }
}

void ChannelForm::AddChannelKey(const ChannelKeyInfo& channelKey){
    if(channelKey.ChannelId == ChannelInfo.ChannelId){
        printf("Key version: %d\n", channelKey.KeyVersion);
        fflush(stdout);
        _channelKey = channelKey;
        NetworkManager::RequestChannelHistory(ChannelInfo.ChannelId, NK_INVALID_MESSAGE, 25);
    }
}

void ChannelForm::AddMessage(const ChannelMessageInfo& message){
    if(message.ChannelId == ChannelInfo.ChannelId){
        _messages[message.MessageId] = message;
    }
}
