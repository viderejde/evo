
#pragma warning(disable : 4996)
#include <chrono>
#include <thread>
#include <cstring>
#include "gui.h"
#include "imgui.h"
#include "imgui_impl_dx9.h"
#include "imgui_impl_win32.h"
#include <iostream>
#include <ShObjIdl.h>
#include <string>
#include <sstream>
#include <locale>
#include <codecvt>
#include "evo.h"

#include "menu.h"

char result[100];

const std::string compilation_date = __DATE__;

const char* build = "EVO_UTIL | updated ";

const char* games[] = { "Apex Legends", "CS2", "Honkai Star Rail" };
int selectedGameIndex = 0;

bool zwMapViewOfSectionChecked = false;
bool mmMapIoSpaceChecked = false;

std::string title = std::string(build) + std::string(compilation_date);

const char* finalTitle = title.c_str();

float availableSize = 10.0;
bool mainChild = false;
bool closed = false;
PWSTR pszFilePath = NULL;
std::string path{ "" };

void gui::Render() noexcept
{

    ImGui::SetNextWindowPos({ 0, 0 });
    ImGui::SetNextWindowSize({ WIDTH, HEIGHT });
    ImGui::Begin(
        finalTitle,

        &exit,
        ImGuiWindowFlags_NoResize |
        ImGuiWindowFlags_NoSavedSettings |
        ImGuiWindowFlags_NoCollapse |
        ImGuiWindowFlags_NoMove
    );

    static char buf[128] = "";
    ImGuiStyle* style = &ImGui::GetStyle();

    style->Colors[ImGuiCol_TitleBg] = ImColor(0, 0, 0, 255);
    style->Colors[ImGuiCol_TitleBgActive] = ImColor(0, 0, 0, 255);

    style->Colors[ImGuiCol_Separator] = ImColor(38, 38, 38, 255);
    style->Colors[ImGuiCol_WindowBg] = ImColor(255, 255, 255, 255);

    style->Colors[ImGuiCol_ChildBg] = ImColor(180, 180, 180, 255);

    style->Colors[ImGuiCol_FrameBg] = ImColor(180, 180, 180, 255);


    style->Colors[ImGuiCol_FrameBgHovered] = ImColor(90, 90, 90, 255);
    style->Colors[ImGuiCol_FrameBgActive] = ImColor(90, 90, 90, 255);
    style->Colors[ImGuiCol_ButtonActive] = ImColor(90, 90, 90, 255);
    style->Colors[ImGuiCol_HeaderActive] = ImColor(74, 120, 86, 255);
    style->Colors[ImGuiCol_TabActive] = ImColor(90, 90, 90, 255);
    style->Colors[ImGuiCol_FrameBgHovered] = ImColor(74, 120, 86, 255);
    style->Colors[ImGuiCol_ButtonHovered] = ImColor(90, 90, 90, 255);
    style->Colors[ImGuiCol_HeaderHovered] = ImColor(74, 120, 86, 255);
    style->Colors[ImGuiCol_Header] = ImColor(25, 25, 25, 255);
    style->Colors[ImGuiCol_TableRowBg] = ImColor(90, 90, 90, 255);
    style->Colors[ImGuiCol_TableRowBgAlt] = ImColor(20, 20, 20, 255);
    style->Colors[ImGuiCol_CheckMark] = ImColor(0, 0, 0, 255);   // Check mark color
    style->Colors[ImGuiCol_FrameBgHovered] = ImColor(90, 90, 90, 255); // Hovered background color
    style->Colors[ImGuiCol_FrameBgActive] = ImColor(0, 0, 0, 255);



    // B6D094
    char activationKeyBuffer[128] = "";

   


    ImGui::PushStyleColor(ImGuiCol_Border, ImColor(38, 38, 38, 255).Value);

    ImGui::PopStyleColor();


    ImGui::PushStyleColor(ImGuiCol_Border, ImColor(38, 38, 38, 255).Value);
    ImGui::PushStyleVar(ImGuiStyleVar_FrameBorderSize, 1.0f);
    availableSize = ImGui::GetContentRegionAvail().y;
    float halfWindowWidth = ImGui::GetContentRegionAvail().x * 0.5;

    ImGui::PushStyleColor(ImGuiCol_Button, ImColor(180, 180, 180, 255).Value);
    ImGui::PushStyleColor(ImGuiCol_Button, ImColor(180, 180, 180, 255).Value);
    ImGui::PushStyleColor(ImGuiCol_Text, ImColor(0, 0, 0, 255).Value); // Red

   
    if (ImGui::Button("SCAN")) {
        evo(path);
    }
    ImGui::SameLine();
    if (ImGui::Button("SELECT FOLDER")) {
        HRESULT hr = CoInitializeEx(NULL, COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE);

        IFileDialog* pFileDialog;
        hr = CoCreateInstance(CLSID_FileOpenDialog, NULL, CLSCTX_INPROC_SERVER, IID_PPV_ARGS(&pFileDialog));
        if (SUCCEEDED(hr)) {
            // Set options for the file dialog
            DWORD dwOptions;
            pFileDialog->GetOptions(&dwOptions);
            pFileDialog->SetOptions(dwOptions | FOS_PICKFOLDERS | FOS_FORCEFILESYSTEM);

            // Show the file dialog
            if (SUCCEEDED(pFileDialog->Show(NULL))) {
                IShellItem* pShellItem;
                hr = pFileDialog->GetResult(&pShellItem);
                if (SUCCEEDED(hr)) {
                    pszFilePath = NULL;
                    hr = pShellItem->GetDisplayName(SIGDN_FILESYSPATH, &pszFilePath);
                    if (SUCCEEDED(hr)) {
                       // std::wcout << L"Selected folder path: " << pszFilePath << std::endl;
                        std::wstring_convert<std::codecvt_utf8<wchar_t>, wchar_t> converter;
                        path = converter.to_bytes(pszFilePath);
                        //std::cout << path;
                        // Free the allocated memory for the path
                        CoTaskMemFree(pszFilePath);
                    }
                    pShellItem->Release();
                }
            }
            pFileDialog->Release();
        }

        CoUninitialize();

    }
    ImGui::SameLine();

    ImGui::PushItemWidth(halfWindowWidth);
    ImGui::Text("path: %s", path.c_str());
    ImGui::PopItemWidth();
    
    ImGui::Separator();
    ImGui::Text("EXPORTS");
   

    ImGui::Checkbox("ZwMapViewOfSection", &zwMapViewOfSectionChecked);

    // Place the next widget on the same line
   // ImGui::SameLine();

    ImGui::Checkbox("MmMapIoSpace", &mmMapIoSpaceChecked);

 
    
   
    // Same line keeps the next element on the same line as the previous element
    

   
    

    
 

   
    // Set the default focus
    ImGui::SetItemDefaultFocus();

    // The button next to it
   
    ImGui::PopStyleColor(1);
    if (mainChild == true) {
        ImGui::BeginChild("##Under", ImVec2(ImGui::GetContentRegionAvail().x, ImGui::GetContentRegionAvail().y), true);
        {

            auto windowWidth = ImGui::GetContentRegionAvail().x;
            auto windowHeight = ImGui::GetContentRegionAvail().y;
            auto textHeight = ImGui::CalcTextSize("welcome, duckyshine123").y;
            auto textWidth = ImGui::CalcTextSize("welcome, duckyshine123").x;

            ImGui::SetCursorPosX((windowWidth - textWidth));
            ImGui::SetCursorPosY(((windowHeight - textHeight) + 8));


            ImGui::Text("welcome,");
            ImGui::SameLine();
            ImGui::PushStyleColor(ImGuiCol_Text(), ImColor(74, 120, 86, 255).Value);
            ImGui::Text("duckyshine123");
            ImGui::PopStyleColor();

        }
    }


    ImGui::EndChild();
    ImGui::PopStyleVar();
    ImGui::PopStyleColor();



    ImGui::End();
}

void menu() {
    gui::CreateHWindow("EVO++");
    gui::CreateDevice();
    gui::CreateImGui();


    ImGuiIO& io = ImGui::GetIO();
    ImFont* segoe = io.Fonts->AddFontFromFileTTF("C:\\Users\\diluc\\source\\repos\\sequoiaUM\\sequoiaUM\\SF-pro.ttf", 20.0f);
    // default1 = io.Fonts->AddFontDefault();
    io.Fonts->Build();

    while (gui::exit)
    {
        if (closed == true)
        {
            break;
        }
        gui::BeginRender();
        gui::Render();
        gui::EndRender();

        std::this_thread::sleep_for(std::chrono::milliseconds(5));
    }

    gui::DestroyImGui();
    gui::DestroyDevice();
    gui::DestroyHWindow();
}

