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

#ifndef NOFILE_H
#define NOFILE_H

#include <nobnc/noglobal.h>
#include <nobnc/nostring.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>

class NO_EXPORT NoFile
{
public:
    NoFile(const NoString& filePath = "");
    ~NoFile();

    enum FileType { Regular, Directory, Character, Block, Fifo, Link, Socket };

    void SetFileName(const NoString& filePath);

    bool IsReg(bool bUseLstat = false) const;
    bool IsDir(bool bUseLstat = false) const;
    bool IsChr(bool bUseLstat = false) const;
    bool IsBlk(bool bUseLstat = false) const;
    bool IsFifo(bool bUseLstat = false) const;
    bool IsLnk(bool bUseLstat = true) const;
    bool IsSock(bool bUseLstat = false) const;

    // for gettin file types, using fstat instead
    static bool FType(const NoString& fileName, FileType type, bool bUseLstat = false);

    enum Attribute { Name, Size, AccessTime, ModificationTime, CreationTime, Uid };

    bool Exists() const;
    off_t GetSize() const;
    time_t GetATime() const;
    time_t GetMTime() const;
    time_t GetCTime() const;
    uid_t GetUID() const;
    gid_t GetGID() const;
    static bool Exists(const NoString& sFile);

    static off_t GetSize(const NoString& sFile);
    static time_t GetATime(const NoString& sFile);
    static time_t GetMTime(const NoString& sFile);
    static time_t GetCTime(const NoString& sFile);
    static uid_t GetUID(const NoString& sFile);
    static gid_t GetGID(const NoString& sFile);
    static int GetInfo(const NoString& sFile, struct stat& st);

    bool Delete();
    bool Move(const NoString& sNewFileName, bool bOverwrite = false);
    bool Copy(const NoString& sNewFileName, bool bOverwrite = false);

    static bool Delete(const NoString& fileName);
    static bool Move(const NoString& sOldFileName, const NoString& sNewFileName, bool bOverwrite = false);
    static bool Copy(const NoString& sOldFileName, const NoString& sNewFileName, bool bOverwrite = false);
    bool Chmod(mode_t mode);
    static bool Chmod(const NoString& sFile, mode_t mode);
    bool Seek(off_t pos);
    bool Truncate();
    bool Sync();
    bool Open(const NoString& fileName, int iFlags = O_RDONLY, mode_t mode = 0644);
    bool Open(int iFlags = O_RDONLY, mode_t mode = 0644);
    ssize_t Read(char* pszBuffer, int iBytes);
    bool ReadLine(NoString& data, const NoString& sDelimiter = "\n");
    bool ReadFile(NoString& data, size_t iMaxSize = 512 * 1024);
    ssize_t Write(const char* pszBuffer, size_t iBytes);
    ssize_t Write(const NoString& data);
    void Close();
    void ClearBuffer();

    bool TryExLock(const NoString& sLockFile, int iFlags = O_RDWR | O_CREAT);
    bool TryExLock();
    bool ExLock();
    bool UnLock();

    bool IsOpen() const;
    NoString GetLongName() const;
    NoString GetShortName() const;
    NoString GetDir() const;

    bool HadError() const;
    void ResetError();

private:
    // fcntl() locking wrapper
    bool Lock(short iType, bool bBlocking);

    NoString m_buffer;
    int m_fd;
    bool m_hadError;

    NoString m_longName; //!< Absolute filename (m_path + "/" + m_shortName)
    NoString m_shortName; //!< Filename alone, without path
};

#endif // NOFILE_H
