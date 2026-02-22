#include "forms/MainForm.hpp"
#include "forms/MainBar.hpp"
#include "forms/FormManager.hpp"
#include <networking/UserManager.hpp>
#include <networking/SessionManager.hpp>
#include <imgui.h>

void MainForm::Create(){
    FormManager::SubscribeOpen("MainForm", &MainForm::Open);
    FormManager::SubscribeRender("MainForm", &MainForm::Render);
}

void MainForm::Destroy(){
    FormManager::UnsubscribeOpen("MainForm");
    FormManager::UnsubscribeRender("MainForm");
}

void MainForm::Open(){
    MainBar::Open();
}

void MainForm::Render()
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
    }
    ImGui::EndChild();

    ImGui::End();
}
