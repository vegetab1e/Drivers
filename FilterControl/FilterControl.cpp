#include <windows.h>
#include <fltUser.h>

#include <cstring>

int main(int argc, char* argv[])
{
    static char buffer[1024];
    std::memset(buffer, 0, sizeof(buffer));

    HANDLE handle = NULL;
    HRESULT result = FilterConnectCommunicationPort(L"\\FileBlockerFilterPort",
                                                    0,
                                                    nullptr,
                                                    0,
                                                    nullptr,
                                                    &handle);
    if (FAILED(result))
        return 1;

    DWORD num_bytes = 0;
    PCCH message = "Hello ворлд!";
    result = FilterSendMessage(handle,
                               (PCH)message,
                               static_cast<DWORD>(std::strlen(message)),
                               buffer,
                               sizeof(buffer),
                               &num_bytes);
    if (FAILED(result))
    {
        CloseHandle(handle);
        return 1;
    }

    CloseHandle(handle);
    return 0;
}
