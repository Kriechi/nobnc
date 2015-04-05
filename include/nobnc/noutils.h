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

#ifndef NOUTILS_H
#define NOUTILS_H

#include <nobnc/noglobal.h>
#include <nobnc/nostring.h>

namespace No
{
NO_EXPORT NoString formatIp(ulong addr);
NO_EXPORT ulong formatLongIp(const NoString& address);

NO_EXPORT void printError(const NoString& message);
NO_EXPORT void printMessage(const NoString& message, bool strong = false);
NO_EXPORT void printPrompt(const NoString& message);
NO_EXPORT void printAction(const NoString& message);
NO_EXPORT void printStatus(bool success, const NoString& message = "");

#ifdef HAVE_LIBSSL
NO_EXPORT NoString encrypt(const NoString& data, const NoString& password);
NO_EXPORT NoString decrypt(const NoString& data, const NoString& password);
#endif

NO_EXPORT NoString salt();
NO_EXPORT NoString md5(const NoString& str);
NO_EXPORT NoString sha256(const NoString& str);

NO_EXPORT NoString getPass(const NoString& prompt);
NO_EXPORT NoString getSaltedHashPass(NoString& salt);
NO_EXPORT bool getInput(const NoString& prompt, NoString& ret, const NoString& defaultValue = "", const NoString& hint = "");
NO_EXPORT bool getBoolInput(const NoString& prompt, bool defaultValue);
NO_EXPORT bool getBoolInput(const NoString& prompt, bool* defaultValue = nullptr);
NO_EXPORT bool getNumInput(const NoString& prompt, uint& ret, uint min = 0, uint max = ~0, uint defaultValue = ~0);

NO_EXPORT ulonglong millTime();

NO_EXPORT NoString ctime(time_t t, const NoString& timezone);
NO_EXPORT NoString formatTime(time_t t, const NoString& format, const NoString& timezone);
NO_EXPORT NoString formatServerTime(const timeval& tv);
NO_EXPORT NoStringSet timezones();
NO_EXPORT NoStringSet encodings();

NO_EXPORT NoStringMap messageTags(const NoString& line);
NO_EXPORT void setMessageTags(NoString& line, const NoStringMap& tags);

NO_EXPORT bool writeToDisk(const NoStringMap& values, const NoString& path, mode_t mode = 0644);
NO_EXPORT bool readFromDisk(NoStringMap& values, const NoString& path);

NO_EXPORT NoString toByteStr(ulonglong d);
NO_EXPORT NoString toTimeStr(ulong s);
NO_EXPORT NoString toPercent(double d);

NO_EXPORT NoString stripControls(const NoString& str);

NO_EXPORT NoString randomString(uint uLength);

NO_EXPORT NoString namedFormat(const NoString& format, const NoStringMap& values);

NO_EXPORT NoString ellipsize(const NoString& str, uint len);

NO_EXPORT NoStringMap optionSplit(const NoString& str);
NO_EXPORT NoStringVector quoteSplit(const NoString& str);

NO_EXPORT bool wildCmp(const NoString& str, const NoString& wild, No::CaseSensitivity cs = No::CaseSensitive);

NO_EXPORT NoString token(const NoString& str, size_t pos, const NoString& sep = " ");
NO_EXPORT NoString tokens(const NoString& str, size_t pos, const NoString& sep = " ");
NO_EXPORT NoString firstLine(const NoString& str);
}

#endif // NOUTILS_H
