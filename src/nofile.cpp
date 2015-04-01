/*
 * Copyright (C) 2015 NoBNC
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
#include "nodir.h"
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
    if (flags < 0)
        return; // Ignore errors
    // When we execve() a new process this fd is now automatically closed.
    fcntl(fd, F_SETFD, flags | FD_CLOEXEC);
}

NoFile::NoFile(const NoString& filePath) : m_buffer(""), m_fd(-1), m_hadError(false), m_longName(""), m_shortName("")
{
    SetFileName(filePath);
}

NoFile::~NoFile()
{
    Close();
}

void NoFile::SetFileName(const NoString& filePath)
{
    if (filePath.left(2) == "~/") {
        m_longName = NoDir::home().path() + filePath.substr(1);
    } else
        m_longName = filePath;

    m_shortName = filePath;
    m_shortName.trimRight("/");

    NoString::size_type uPos = m_shortName.rfind('/');
    if (uPos != NoString::npos) {
        m_shortName = m_shortName.substr(uPos + 1);
    }
}

bool NoFile::IsDir(bool bUseLstat) const
{
    if (m_longName.equals("/"))
        return NoFile::FType(m_longName, Directory, bUseLstat);

    // Some OS don't like trailing slashes for directories
    return NoFile::FType(m_longName.trimRight_n("/"), Directory, bUseLstat);
}

bool NoFile::IsReg(bool bUseLstat) const
{
    return NoFile::FType(m_longName, Regular, bUseLstat);
}
bool NoFile::IsChr(bool bUseLstat) const
{
    return NoFile::FType(m_longName, Character, bUseLstat);
}
bool NoFile::IsBlk(bool bUseLstat) const
{
    return NoFile::FType(m_longName, Block, bUseLstat);
}
bool NoFile::IsFifo(bool bUseLstat) const
{
    return NoFile::FType(m_longName, Fifo, bUseLstat);
}
bool NoFile::IsLnk(bool bUseLstat) const
{
    return NoFile::FType(m_longName, Link, bUseLstat);
}
bool NoFile::IsSock(bool bUseLstat) const
{
    return NoFile::FType(m_longName, Socket, bUseLstat);
}

// for gettin file types, using fstat instead
bool NoFile::FType(const NoString& fileName, FileType type, bool bUseLstat)
{
    struct stat st;

    if (!bUseLstat) {
        if (stat(fileName.c_str(), &st) != 0) {
            return false;
        }
    } else {
        if (lstat(fileName.c_str(), &st) != 0) {
            return false;
        }
    }

    switch (type) {
    case Regular:
        return S_ISREG(st.st_mode);
    case Directory:
        return S_ISDIR(st.st_mode);
    case Character:
        return S_ISCHR(st.st_mode);
    case Block:
        return S_ISBLK(st.st_mode);
    case Fifo:
        return S_ISFIFO(st.st_mode);
    case Link:
        return S_ISLNK(st.st_mode);
    case Socket:
        return S_ISSOCK(st.st_mode);
    default:
        break;
    }
    return false;
}

//
// Functions to retrieve file information
//
bool NoFile::Exists() const
{
    return NoFile::Exists(m_longName);
}
off_t NoFile::GetSize() const
{
    return NoFile::GetSize(m_longName);
}
time_t NoFile::GetATime() const
{
    return NoFile::GetATime(m_longName);
}
time_t NoFile::GetMTime() const
{
    return NoFile::GetMTime(m_longName);
}
time_t NoFile::GetCTime() const
{
    return NoFile::GetCTime(m_longName);
}
uid_t NoFile::GetUID() const
{
    return NoFile::GetUID(m_longName);
}
gid_t NoFile::GetGID() const
{
    return NoFile::GetGID(m_longName);
}
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
int NoFile::GetInfo(const NoString& sFile, struct stat& st)
{
    return stat(sFile.c_str(), &st);
}

//
// Functions to manipulate the file on the filesystem
//
bool NoFile::Delete()
{
    if (NoFile::Delete(m_longName))
        return true;
    m_hadError = true;
    return false;
}

bool NoFile::Move(const NoString& sNewFileName, bool bOverwrite)
{
    if (NoFile::Move(m_longName, sNewFileName, bOverwrite))
        return true;
    m_hadError = true;
    return false;
}

bool NoFile::Copy(const NoString& sNewFileName, bool bOverwrite)
{
    if (NoFile::Copy(m_longName, sNewFileName, bOverwrite))
        return true;
    m_hadError = true;
    return false;
}

bool NoFile::Delete(const NoString& fileName)
{
    return (unlink(fileName.c_str()) == 0) ? true : false;
}

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
            NO_DEBUG("NoFile::Copy() failed: " << strerror(errno));
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
    if (m_fd == -1) {
        errno = EBADF;
        return false;
    }
    if (fchmod(m_fd, mode) != 0) {
        m_hadError = true;
        return false;
    }
    return true;
}

bool NoFile::Chmod(const NoString& sFile, mode_t mode)
{
    return (chmod(sFile.c_str(), mode) == 0);
}

bool NoFile::Seek(off_t uPos)
{
    /* This sets errno in case m_iFD == -1 */
    errno = EBADF;

    if (m_fd != -1 && lseek(m_fd, uPos, SEEK_SET) == uPos) {
        ClearBuffer();
        return true;
    }
    m_hadError = true;

    return false;
}

bool NoFile::Truncate()
{
    /* This sets errno in case m_iFD == -1 */
    errno = EBADF;

    if (m_fd != -1 && ftruncate(m_fd, 0) == 0) {
        ClearBuffer();
        return true;
    }

    m_hadError = true;

    return false;
}

bool NoFile::Sync()
{
    /* This sets errno in case m_iFD == -1 */
    errno = EBADF;

    if (m_fd != -1 && fsync(m_fd) == 0)
        return true;
    m_hadError = true;
    return false;
}

bool NoFile::Open(const NoString& fileName, int iFlags, mode_t iMode)
{
    SetFileName(fileName);
    return Open(iFlags, iMode);
}

bool NoFile::Open(int iFlags, mode_t iMode)
{
    if (m_fd != -1) {
        errno = EEXIST;
        m_hadError = true;
        return false;
    }

    // We never want to get a controlling TTY through this -> O_NOCTTY
    iMode |= O_NOCTTY;

    // Some weird OS from MS needs O_BINARY or else it generates fake EOFs
    // when reading ^Z from a file.
    iMode |= O_BINARY;

    m_fd = open(m_longName.c_str(), iFlags, iMode);
    if (m_fd < 0) {
        m_hadError = true;
        return false;
    }

    /* Make sure this FD isn't given to childs */
    SetFdCloseOnExec(m_fd);

    return true;
}

ssize_t NoFile::Read(char* pszBuffer, int iBytes)
{
    if (m_fd == -1) {
        errno = EBADF;
        return -1;
    }

    ssize_t res = read(m_fd, pszBuffer, iBytes);
    if (res != iBytes)
        m_hadError = true;
    return res;
}

bool NoFile::ReadLine(NoString& data, const NoString& sDelimiter)
{
    char buff[4096];
    ssize_t iBytes;

    if (m_fd == -1) {
        errno = EBADF;
        return false;
    }

    do {
        NoString::size_type iFind = m_buffer.find(sDelimiter);
        if (iFind != NoString::npos) {
            // We found a line, return it
            data = m_buffer.substr(0, iFind + sDelimiter.length());
            m_buffer.erase(0, iFind + sDelimiter.length());
            return true;
        }

        iBytes = read(m_fd, buff, sizeof(buff));

        if (iBytes > 0) {
            m_buffer.append(buff, iBytes);
        }
    } while (iBytes > 0);

    // We are at the end of the file or an error happened

    if (!m_buffer.empty()) {
        // ..but there is still some partial line in the buffer
        data = m_buffer;
        m_buffer.clear();
        return true;
    }

    // Nothing left for reading :(
    return false;
}

bool NoFile::ReadFile(NoString& data, size_t iMaxSize)
{
    char buff[4096];
    size_t iBytesRead = 0;

    data.clear();

    while (iBytesRead < iMaxSize) {
        ssize_t iBytes = Read(buff, sizeof(buff));

        if (iBytes < 0)
            // Error
            return false;

        if (iBytes == 0)
            // EOF
            return true;

        data.append(buff, iBytes);
        iBytesRead += iBytes;
    }

    // Buffer limit reached
    return false;
}

ssize_t NoFile::Write(const char* pszBuffer, size_t iBytes)
{
    if (m_fd == -1) {
        errno = EBADF;
        return -1;
    }

    ssize_t res = write(m_fd, pszBuffer, iBytes);
    if (-1 == res)
        m_hadError = true;
    return res;
}

ssize_t NoFile::Write(const NoString& data)
{
    return Write(data.data(), data.size());
}
void NoFile::Close()
{
    if (m_fd >= 0) {
        if (close(m_fd) < 0) {
            m_hadError = true;
            NO_DEBUG("NoFile::Close(): close() failed with [" << strerror(errno) << "]");
        }
    }
    m_fd = -1;
    ClearBuffer();
}
void NoFile::ClearBuffer()
{
    m_buffer.clear();
}

bool NoFile::TryExLock(const NoString& sLockFile, int iFlags)
{
    Open(sLockFile, iFlags);
    return TryExLock();
}

bool NoFile::TryExLock()
{
    return Lock(F_WRLCK, false);
}

bool NoFile::ExLock()
{
    return Lock(F_WRLCK, true);
}

bool NoFile::UnLock()
{
    return Lock(F_UNLCK, true);
}

bool NoFile::Lock(short iType, bool bBlocking)
{
    struct flock fl;

    if (m_fd == -1) {
        return false;
    }

    fl.l_type = iType;
    fl.l_whence = SEEK_SET;
    fl.l_start = 0;
    fl.l_len = 0;
    return (fcntl(m_fd, (bBlocking ? F_SETLKW : F_SETLK), &fl) != -1);
}

bool NoFile::IsOpen() const
{
    return (m_fd != -1);
}
NoString NoFile::GetLongName() const
{
    return m_longName;
}
NoString NoFile::GetShortName() const
{
    return m_shortName;
}
NoString NoFile::GetDir() const
{
    NoString sDir(m_longName);

    while (!sDir.empty() && sDir.right(1) != "/" && sDir.right(1) != "\\") {
        sDir.rightChomp(1);
    }

    return sDir;
}

bool NoFile::HadError() const
{
    return m_hadError;
}

void NoFile::ResetError()
{
    m_hadError = false;
}
