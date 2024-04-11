#include <acf_manager.hpp>
#include <filesystem>
#include <phosphor-logging/elog-errors.hpp>
#include <phosphor-logging/elog.hpp>
#include <phosphor-logging/log.hpp>
#include <tacf.hpp>
#include <vector>
#include <xyz/openbmc_project/Certs/error.hpp>

namespace acf
{
namespace cert
{
using namespace phosphor::logging;

using InvalidCertificate =
    sdbusplus::xyz::openbmc_project::Certs::Error::InvalidCertificate;

using Reason = xyz::openbmc_project::Certs::InvalidCertificate::REASON;

constexpr auto ACF_FILE_PATH = "/etc/acf/service.acf";

/** @brief Implementation for readBinaryFile
 *  Read file contents into buffer
 *
 *  @param[in] fileNameParm - Path of file.
 *  @param[out] bufferParm - Buffer to store contents of file.
 *
 *  @return Status of if read was successful.
 */
static bool readBinaryFile(const std::string fileNameParm,
                           std::vector<uint8_t>& bufferParm)
{
    std::ifstream sInputFile;
    if (fileNameParm.empty())
    {
        return false;
    }

    // Open the file.
    sInputFile.open(fileNameParm.c_str(), std::ios::binary);
    sInputFile.unsetf(std::ios::skipws);
    if (!sInputFile)
    {
        return false;
    }

    // Get the size of the file.
    std::error_code ec;
    std::filesystem::path path = fileNameParm;
    std::uintmax_t size = file_size(path, ec);
    if (ec)
    {
        return false;
    }

    // Read the file.
    bufferParm.reserve(size);
    bufferParm.assign(size, 0);
    sInputFile.read((char*)bufferParm.data(), size);
    sInputFile.close();

    return true;
}

bool acfInstalled()
{
    std::error_code ec;
    std::filesystem::path path = ACF_FILE_PATH;
    bool exists = std::filesystem::exists(path, ec);
    if (ec)
    {
        return false;
    }
    return exists;
}

acf_info ACFCertMgr::installACF(std::vector<uint8_t> accessControlFile)
{
    std::string sDate;

    // delete acf file if accessControlFile is empty
    if (accessControlFile.empty() && acfInstalled())
    {
        std::remove(ACF_FILE_PATH);
        return std::make_tuple(accessControlFile, acfInstalled(), sDate);
    }
    // Verify and install ACF and get expiration date.
    Tacf tacf{[](std::string msg) {
        log<phosphor::logging::level::INFO>(msg.c_str());
    }};
    int rc =
        tacf.install(accessControlFile.data(), accessControlFile.size(), sDate);
    if (rc)
    {
        log<level::INFO>("ACF install failed");
        log<level::ERR>("Error: ", entry("rc=%0x", rc));
        elog<InvalidCertificate>(Reason("ACF validation failed"));
    }

    return std::make_tuple(accessControlFile, acfInstalled(), sDate);
}

std::tuple<std::vector<uint8_t>, bool, std::string> ACFCertMgr::getACFInfo(void)
{
    std::string sDate;
    std::vector<uint8_t> accessControlFile;

    if (!readBinaryFile(ACF_FILE_PATH, accessControlFile))
    {
        log<level::ERR>("ACF not installed or not readable");
    }
    else
    {
        // Verify ACF and get expiration date.
        Tacf tacf{[](std::string msg) {
            log<phosphor::logging::level::INFO>(msg.c_str());
        }};
        int rc = tacf.verify(accessControlFile.data(), accessControlFile.size(),
                             sDate);
        if (rc)
        {
            log<level::INFO>("ACF is not valid");
            log<level::ERR>("Error: ", entry("rc=%0x", rc));
        }
    }

    return std::make_tuple(accessControlFile, acfInstalled(), sDate);
}

} // namespace cert
} // namespace acf
