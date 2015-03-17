/*
 * Copyright (C) 2004-2015 ZNC, see the NOTICE file for details.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "nofile.h"
#include "noutils.h"
#include "nodebug.h"
#include <fcntl.h>
#include <pwd.h>
#include <sys/stat.h>
#include <sys/types.h>

#ifndef HAVE_LSTAT
#define lstat(a, b) stat(a, b)
#endif

#ifndef O_BINARY
#define O_BINARY 0
#endif

static inline void SetFdCloseOnExec(int fd)
{
    int flags = fcntl(fd, F_GETFD, 0);
    if (flags < 0) return; // Ignore errors
    // When we execve() a new process this fd is now automatically closed.
    fcntl(fd, F_SETFD, flags | FD_CLOEXEC);
}

NoString NoFile::m_sHomePath;

NoFile::NoFile() : NoFile("") {}

NoFile::NoFile(const NoString& sLongName) : m_sBuffer(""), m_iFD(-1), m_bHadError(false), m_sLongName(""), m_sShortName("")
{
    SetFileName(sLongName);
}

NoFile::~NoFile() { Close(); }

void NoFile::SetFileName(const NoString& sLongName)
{
    if (sLongName.Left(2) == "~/") {
        m_sLongName = NoFile::GetHomePath() + sLongName.substr(1);
    } else
        m_sLongName = sLongName;

    m_sShortName = sLongName;
    m_sShortName.TrimRight("/");

    NoString::size_type uPos = m_sShortName.rfind('/');
    if (uPos != NoString::npos) {
        m_sShortName = m_sShortName.substr(uPos + 1);
    }
}

bool NoFile::IsDir(const NoString& sLongName, bool bUseLstat)
{
    if (sLongName.Equals("/")) return NoFile::FType(sLongName, FT_DIRECTORY, bUseLstat);

    // Some OS don't like trailing slashes for directories
    return NoFile::FType(sLongName.TrimRight_n("/"), FT_DIRECTORY, bUseLstat);
}

bool NoFile::IsReg(const NoString& sLongName, bool bUseLstat) { return NoFile::FType(sLongName, FT_REGULAR, bUseLstat); }
bool NoFile::IsChr(const NoString& sLongName, bool bUseLstat) { return NoFile::FType(sLongName, FT_CHARACTER, bUseLstat); }
bool NoFile::IsBlk(const NoString& sLongName, bool bUseLstat) { return NoFile::FType(sLongName, FT_BLOCK, bUseLstat); }
bool NoFile::IsFifo(const NoString& sLongName, bool bUseLstat) { return NoFile::FType(sLongName, FT_FIFO, bUseLstat); }
bool NoFile::IsLnk(const NoString& sLongName, bool bUseLstat) { return NoFile::FType(sLongName, FT_LINK, bUseLstat); }
bool NoFile::IsSock(const NoString& sLongName, bool bUseLstat) { return NoFile::FType(sLongName, FT_SOCK, bUseLstat); }

bool NoFile::IsReg(bool bUseLstat) const { return NoFile::IsReg(m_sLongName, bUseLstat); }
bool NoFile::IsDir(bool bUseLstat) const { return NoFile::IsDir(m_sLongName, bUseLstat); }
bool NoFile::IsChr(bool bUseLstat) const { return NoFile::IsChr(m_sLongName, bUseLstat); }
bool NoFile::IsBlk(bool bUseLstat) const { return NoFile::IsBlk(m_sLongName, bUseLstat); }
bool NoFile::IsFifo(bool bUseLstat) const { return NoFile::IsFifo(m_sLongName, bUseLstat); }
bool NoFile::IsLnk(bool bUseLstat) const { return NoFile::IsLnk(m_sLongName, bUseLstat); }
bool NoFile::IsSock(bool bUseLstat) const { return NoFile::IsSock(m_sLongName, bUseLstat); }

// for gettin file types, using fstat instead
bool NoFile::FType(const NoString& sFileName, EFileTypes eType, bool bUseLstat)
{
    struct stat st;

    if (!bUseLstat) {
        if (stat(sFileName.c_str(), &st) != 0) {
            return false;
        }
    } else {
        if (lstat(sFileName.c_str(), &st) != 0) {
            return false;
        }
    }

    switch (eType) {
    case FT_REGULAR:
        return S_ISREG(st.st_mode);
    case FT_DIRECTORY:
        return S_ISDIR(st.st_mode);
    case FT_CHARACTER:
        return S_ISCHR(st.st_mode);
    case FT_BLOCK:
        return S_ISBLK(st.st_mode);
    case FT_FIFO:
        return S_ISFIFO(st.st_mode);
    case FT_LINK:
        return S_ISLNK(st.st_mode);
    case FT_SOCK:
        return S_ISSOCK(st.st_mode);
    default:
        break;
    }
    return false;
}

//
// Functions to retrieve file information
//
bool NoFile::Exists() const { return NoFile::Exists(m_sLongName); }
off_t NoFile::GetSize() const { return NoFile::GetSize(m_sLongName); }
time_t NoFile::GetATime() const { return NoFile::GetATime(m_sLongName); }
time_t NoFile::GetMTime() const { return NoFile::GetMTime(m_sLongName); }
time_t NoFile::GetCTime() const { return NoFile::GetCTime(m_sLongName); }
uid_t NoFile::GetUID() const { return NoFile::GetUID(m_sLongName); }
gid_t NoFile::GetGID() const { return NoFile::GetGID(m_sLongName); }
bool NoFile::Exists(const NoString& sFile)
{
    struct stat st;
    return (stat(sFile.c_str(), &st) == 0);
}

off_t NoFile::GetSize(const NoString& sFile)
{
    struct stat st;
    if (stat(sFile.c_str(), &st) != 0) {
        return 0;
    }

    return (S_ISREG(st.st_mode)) ? st.st_size : 0;
}

time_t NoFile::GetATime(const NoString& sFile)
{
    struct stat st;
    return (stat(sFile.c_str(), &st) != 0) ? 0 : st.st_atime;
}

time_t NoFile::GetMTime(const NoString& sFile)
{
    struct stat st;
    return (stat(sFile.c_str(), &st) != 0) ? 0 : st.st_mtime;
}

time_t NoFile::GetCTime(const NoString& sFile)
{
    struct stat st;
    return (stat(sFile.c_str(), &st) != 0) ? 0 : st.st_ctime;
}

uid_t NoFile::GetUID(const NoString& sFile)
{
    struct stat st;
    return (stat(sFile.c_str(), &st) != 0) ? -1 : (int)st.st_uid;
}

gid_t NoFile::GetGID(const NoString& sFile)
{
    struct stat st;
    return (stat(sFile.c_str(), &st) != 0) ? -1 : (int)st.st_gid;
}
int NoFile::GetInfo(const NoString& sFile, struct stat& st) { return stat(sFile.c_str(), &st); }

//
// Functions to manipulate the file on the filesystem
//
bool NoFile::Delete()
{
    if (NoFile::Delete(m_sLongName)) return true;
    m_bHadError = true;
    return false;
}

bool NoFile::Move(const NoString& sNewFileName, bool bOverwrite)
{
    if (NoFile::Move(m_sLongName, sNewFileName, bOverwrite)) return true;
    m_bHadError = true;
    return false;
}

bool NoFile::Copy(const NoString& sNewFileName, bool bOverwrite)
{
    if (NoFile::Copy(m_sLongName, sNewFileName, bOverwrite)) return true;
    m_bHadError = true;
    return false;
}

bool NoFile::Delete(const NoString& sFileName) { return (unlink(sFileName.c_str()) == 0) ? true : false; }

bool NoFile::Move(const NoString& sOldFileName, const NoString& sNewFileName, bool bOverwrite)
{
    if (NoFile::Exists(sNewFileName)) {
        if (!bOverwrite) {
            errno = EEXIST;
            return false;
        }
#ifdef _WIN32
        // rename() never overwrites files on Windows.
        DWORD dFlags = MOVEFILE_WRITE_THROUGH | MOVEFILE_COPY_ALLOWED | MOVEFILE_REPLACE_EXISTING;
        return (::MoveFileExA(sOldFileName.c_str(), sNewFileName.c_str(), dFlags) != 0);
#endif
    }

    return (rename(sOldFileName.c_str(), sNewFileName.c_str()) == 0);
}

bool NoFile::Copy(const NoString& sOldFileName, const NoString& sNewFileName, bool bOverwrite)
{
    if ((!bOverwrite) && (NoFile::Exists(sNewFileName))) {
        errno = EEXIST;
        return false;
    }

    NoFile OldFile(sOldFileName);
    NoFile NewFile(sNewFileName);

    if (!OldFile.Open()) {
        return false;
    }

    if (!NewFile.Open(O_WRONLY | O_CREAT | O_TRUNC)) {
        return false;
    }

    char szBuf[8192];
    ssize_t len = 0;

    while ((len = OldFile.Read(szBuf, 8192))) {
        if (len < 0) {
            DEBUG("NoFile::Copy() failed: " << strerror(errno));
            OldFile.Close();

            // That file is only a partial copy, get rid of it
            NewFile.Close();
            NewFile.Delete();

            return false;
        }
        NewFile.Write(szBuf, len);
    }

    OldFile.Close();
    NewFile.Close();

    struct stat st;
    GetInfo(sOldFileName, st);
    Chmod(sNewFileName, st.st_mode);

    return true;
}

bool NoFile::Chmod(mode_t mode)
{
    if (m_iFD == -1) {
        errno = EBADF;
        return false;
    }
    if (fchmod(m_iFD, mode) != 0) {
        m_bHadError = true;
        return false;
    }
    return true;
}

bool NoFile::Chmod(const NoString& sFile, mode_t mode) { return (chmod(sFile.c_str(), mode) == 0); }

bool NoFile::Seek(off_t uPos)
{
    /* This sets errno in case m_iFD == -1 */
    errno = EBADF;

    if (m_iFD != -1 && lseek(m_iFD, uPos, SEEK_SET) == uPos) {
        ClearBuffer();
        return true;
    }
    m_bHadError = true;

    return false;
}

bool NoFile::Truncate()
{
    /* This sets errno in case m_iFD == -1 */
    errno = EBADF;

    if (m_iFD != -1 && ftruncate(m_iFD, 0) == 0) {
        ClearBuffer();
        return true;
    }

    m_bHadError = true;

    return false;
}

bool NoFile::Sync()
{
    /* This sets errno in case m_iFD == -1 */
    errno = EBADF;

    if (m_iFD != -1 && fsync(m_iFD) == 0) return true;
    m_bHadError = true;
    return false;
}

bool NoFile::Open(const NoString& sFileName, int iFlags, mode_t iMode)
{
    SetFileName(sFileName);
    return Open(iFlags, iMode);
}

bool NoFile::Open(int iFlags, mode_t iMode)
{
    if (m_iFD != -1) {
        errno = EEXIST;
        m_bHadError = true;
        return false;
    }

    // We never want to get a controlling TTY through this -> O_NOCTTY
    iMode |= O_NOCTTY;

    // Some weird OS from MS needs O_BINARY or else it generates fake EOFs
    // when reading ^Z from a file.
    iMode |= O_BINARY;

    m_iFD = open(m_sLongName.c_str(), iFlags, iMode);
    if (m_iFD < 0) {
        m_bHadError = true;
        return false;
    }

    /* Make sure this FD isn't given to childs */
    SetFdCloseOnExec(m_iFD);

    return true;
}

ssize_t NoFile::Read(char* pszBuffer, int iBytes)
{
    if (m_iFD == -1) {
        errno = EBADF;
        return -1;
    }

    ssize_t res = read(m_iFD, pszBuffer, iBytes);
    if (res != iBytes) m_bHadError = true;
    return res;
}

bool NoFile::ReadLine(NoString& sData, const NoString& sDelimiter)
{
    char buff[4096];
    ssize_t iBytes;

    if (m_iFD == -1) {
        errno = EBADF;
        return false;
    }

    do {
        NoString::size_type iFind = m_sBuffer.find(sDelimiter);
        if (iFind != NoString::npos) {
            // We found a line, return it
            sData = m_sBuffer.substr(0, iFind + sDelimiter.length());
            m_sBuffer.erase(0, iFind + sDelimiter.length());
            return true;
        }

        iBytes = read(m_iFD, buff, sizeof(buff));

        if (iBytes > 0) {
            m_sBuffer.append(buff, iBytes);
        }
    } while (iBytes > 0);

    // We are at the end of the file or an error happened

    if (!m_sBuffer.empty()) {
        // ..but there is still some partial line in the buffer
        sData = m_sBuffer;
        m_sBuffer.clear();
        return true;
    }

    // Nothing left for reading :(
    return false;
}

bool NoFile::ReadFile(NoString& sData, size_t iMaxSize)
{
    char buff[4096];
    size_t iBytesRead = 0;

    sData.clear();

    while (iBytesRead < iMaxSize) {
        ssize_t iBytes = Read(buff, sizeof(buff));

        if (iBytes < 0)
            // Error
            return false;

        if (iBytes == 0)
            // EOF
            return true;

        sData.append(buff, iBytes);
        iBytesRead += iBytes;
    }

    // Buffer limit reached
    return false;
}

ssize_t NoFile::Write(const char* pszBuffer, size_t iBytes)
{
    if (m_iFD == -1) {
        errno = EBADF;
        return -1;
    }

    ssize_t res = write(m_iFD, pszBuffer, iBytes);
    if (-1 == res) m_bHadError = true;
    return res;
}

ssize_t NoFile::Write(const NoString& sData) { return Write(sData.data(), sData.size()); }
void NoFile::Close()
{
    if (m_iFD >= 0) {
        if (close(m_iFD) < 0) {
            m_bHadError = true;
            DEBUG("NoFile::Close(): close() failed with [" << strerror(errno) << "]");
        }
    }
    m_iFD = -1;
    ClearBuffer();
}
void NoFile::ClearBuffer() { m_sBuffer.clear(); }

bool NoFile::TryExLock(const NoString& sLockFile, int iFlags)
{
    Open(sLockFile, iFlags);
    return TryExLock();
}

bool NoFile::TryExLock() { return Lock(F_WRLCK, false); }

bool NoFile::ExLock() { return Lock(F_WRLCK, true); }

bool NoFile::UnLock() { return Lock(F_UNLCK, true); }

bool NoFile::Lock(short iType, bool bBlocking)
{
    struct flock fl;

    if (m_iFD == -1) {
        return false;
    }

    fl.l_type = iType;
    fl.l_whence = SEEK_SET;
    fl.l_start = 0;
    fl.l_len = 0;
    return (fcntl(m_iFD, (bBlocking ? F_SETLKW : F_SETLK), &fl) != -1);
}

bool NoFile::IsOpen() const { return (m_iFD != -1); }
NoString NoFile::GetLongName() const { return m_sLongName; }
NoString NoFile::GetShortName() const { return m_sShortName; }
NoString NoFile::GetDir() const
{
    NoString sDir(m_sLongName);

    while (!sDir.empty() && sDir.Right(1) != "/" && sDir.Right(1) != "\\") {
        sDir.RightChomp();
    }

    return sDir;
}

void NoFile::InitHomePath(const NoString& sFallback)
{
    const char* home = getenv("HOME");

    m_sHomePath.clear();
    if (home) {
        m_sHomePath = home;
    }

    if (m_sHomePath.empty()) {
        const struct passwd* pUserInfo = getpwuid(getuid());

        if (pUserInfo) {
            m_sHomePath = pUserInfo->pw_dir;
        }
    }

    if (m_sHomePath.empty()) {
        m_sHomePath = sFallback;
    }
}
